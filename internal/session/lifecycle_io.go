package session

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// Clock timers are monotonic, never inline and stopped without blocking. Tests
// inject constructors only; production sockets and their trust stay on real time.
type Timer interface{ Stop() bool }
type Clock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) Timer
}
type realClock struct{}

func (realClock) Now() time.Time                            { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
func NewClock() Clock                                       { return realClock{} }

const NativeOpenTimeout = 5 * time.Second
const NativeWriteTimeout = 5 * time.Second

// RenewableStreams is a business-facing lifetime capability, not a wire version.
// It does not authenticate a request or guarantee target connection readiness.
type RenewableStreams interface{ RenewableStreams() bool }

// PhaseContext bounds an opening phase without retaining an absolute-age context
// in the resulting stream. The caller must stop phase I/O callbacks before cancel.
type phaseContext struct {
	context.Context
	clock    Clock
	deadline time.Time
	cancel   context.CancelCauseFunc
}

func (p *phaseContext) Err() error {
	if !p.clock.Now().Before(p.deadline) {
		p.cancel(context.DeadlineExceeded)
	}
	return p.Context.Err()
}
func PhaseContext(parent context.Context, clock Clock, budget time.Duration) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	phase := &phaseContext{Context: ctx, clock: clock, deadline: clock.Now().Add(budget), cancel: cancel}
	timer := clock.AfterFunc(budget, func() { cancel(context.DeadlineExceeded) })
	return phase, func() { timer.Stop(); cancel(context.Canceled) }
}

var ErrNativeWriteTimeout error = progressTimeout{}

type progressTimeout struct{}

func (progressTimeout) Error() string   { return "native write progress deadline exceeded" }
func (progressTimeout) Timeout() bool   { return true }
func (progressTimeout) Temporary() bool { return false }

// nativeOperation has one bounded timer. A stopped/fired callback cannot close
// a later operation: completion and timeout linearize under this operation guard.
func nativeOperation(clock Clock, budget time.Duration, abort func(), operation func() error) error {
	var mu sync.Mutex
	complete, expired := false, false
	joined := make(chan struct{})
	deadline := clock.Now().Add(budget)
	timer := clock.AfterFunc(budget, func() {
		defer close(joined)
		mu.Lock()
		run := !complete
		if run {
			expired = true
		}
		mu.Unlock()
		if run {
			abort()
		}
	})
	err := operation()
	mu.Lock()
	if !clock.Now().Before(deadline) {
		expired = true
	}
	complete = true
	timedOut := expired
	mu.Unlock()
	if !timer.Stop() {
		<-joined
	}
	if timedOut {
		abort()
		return errors.Join(ErrNativeWriteTimeout, err)
	}
	return err
}

type nativeWriter struct {
	endpoint io.ReadWriteCloser
	clock    Clock
	abort    func()
}

func (w nativeWriter) Write(p []byte) (int, error) {
	var n int
	err := nativeOperation(w.clock, NativeWriteTimeout, w.abort, func() error { var e error; n, e = w.endpoint.Write(p); return e })
	return n, err
}

// ProxyNative preserves directional EOF only after successful bounded CloseWrite.
// Every write, half-close or hard read error is fatal to both directions. Quiet
// reads have no idle/age timer; current authority and cancellation own lifetime.
func ProxyNative(ctx context.Context, left, right io.ReadWriteCloser, clock Clock) error {
	if left == nil || right == nil || clock == nil {
		return errors.New("invalid native proxy endpoint")
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = left.Close(); _ = right.Close() }) }
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); <-ctx.Done(); closeBoth() }()
	outcomes := make(chan error, 2)
	copyOne := func(dst, src io.ReadWriteCloser) {
		_, err := io.Copy(nativeWriter{dst, clock, closeBoth}, src)
		if err == nil || errors.Is(err, io.EOF) {
			if cw, ok := dst.(closeWriter); ok {
				err = nativeOperation(clock, NativeWriteTimeout, closeBoth, cw.CloseWrite)
			} else {
				err = errors.New("native proxy endpoint does not support directional EOF")
			}
		}
		if err != nil {
			closeBoth()
		}
		outcomes <- err
	}
	go copyOne(right, left)
	go copyOne(left, right)
	first, second := <-outcomes, <-outcomes
	closeBoth()
	cancel()
	<-monitorDone
	if errors.Is(first, ErrNativeWriteTimeout) || errors.Is(second, ErrNativeWriteTimeout) {
		return errors.Join(ErrNativeWriteTimeout, first, second, parent.Err())
	}
	return errors.Join(first, second, parent.Err())
}
