package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type ioTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*ioTestTimer
}
type ioTestTimer struct {
	clock  *ioTestClock
	at     time.Time
	fn     func()
	active bool
}

func (c *ioTestClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *ioTestClock) AfterFunc(d time.Duration, fn func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &ioTestTimer{c, c.now.Add(d), fn, true}
	c.timers = append(c.timers, t)
	return t
}
func (t *ioTestTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	old := t.active
	t.active = false
	return old
}
func (c *ioTestClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var fs []func()
	for _, t := range c.timers {
		if t.active && !c.now.Before(t.at) {
			t.active = false
			fs = append(fs, t.fn)
		}
	}
	c.mu.Unlock()
	for _, f := range fs {
		f()
	}
}
func (c *ioTestClock) active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.active {
			n++
		}
	}
	return n
}
func awaitIO(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatal("native I/O state not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestNativeProxyQuietAndContinuousFlowsHaveNoAgeTimer(t *testing.T) {
	clock := &ioTestClock{now: time.Unix(1000, 0)}
	left, client := net.Pipe()
	right, target := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ProxyNative(ctx, left, right, clock) }()
	defer client.Close()
	defer target.Close()
	defer cancel()
	for i := 0; i < 125; i++ {
		payload := []byte{byte(i)}
		w := make(chan error, 1)
		go func() { _, e := client.Write(payload); w <- e }()
		var observed [1]byte
		if _, e := io.ReadFull(target, observed[:]); e != nil || observed[0] != payload[0] {
			t.Fatal("target receipt mismatch", e)
		}
		if e := <-w; e != nil {
			t.Fatal(e)
		}
		go func() { _, e := target.Write(observed[:]); w <- e }()
		if _, e := io.ReadFull(client, observed[:]); e != nil {
			t.Fatal(e)
		}
		if e := <-w; e != nil {
			t.Fatal(e)
		}
		awaitIO(t, func() bool { return clock.active() == 0 })
		clock.advance(30 * time.Second)
	}
	clock.advance(2 * time.Hour)
	select {
	case <-done:
		t.Fatal("quiet healthy flow acquired an age timeout")
	default:
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("native proxy did not join cancellation")
	}
	if clock.active() != 0 {
		t.Fatal("native proxy retained progress timers")
	}
}
func TestNativeProxyBlockedWriteTimeoutIsFatalToBothCopies(t *testing.T) {
	clock := &ioTestClock{now: time.Unix(1000, 0)}
	left, client := net.Pipe()
	right, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	done := make(chan error, 1)
	go func() { done <- ProxyNative(context.Background(), left, right, clock) }()
	sent := make(chan error, 1)
	go func() { _, e := client.Write([]byte("blocked")); sent <- e }()
	awaitIO(t, func() bool { return clock.active() > 0 })
	clock.advance(NativeWriteTimeout)
	select {
	case e := <-done:
		var timeout net.Error
		if !errors.As(e, &timeout) || !timeout.Timeout() {
			t.Fatal("blocked write timeout was normalized", e)
		}
	case <-time.After(time.Second):
		t.Fatal("write timeout did not abort both directions")
	}
	<-sent
	if clock.active() != 0 {
		t.Fatal("write timeout retained timer")
	}
}

type nativeEOFEndpoint struct{}

func (nativeEOFEndpoint) Read([]byte) (int, error)    { return 0, io.EOF }
func (nativeEOFEndpoint) Write(p []byte) (int, error) { return len(p), nil }
func (nativeEOFEndpoint) Close() error                { return nil }
func (nativeEOFEndpoint) CloseWrite() error           { return nil }

type blockedNativeEOF struct {
	entered, closed chan struct{}
	once            sync.Once
}

func (e *blockedNativeEOF) Read([]byte) (int, error)    { <-e.closed; return 0, net.ErrClosed }
func (e *blockedNativeEOF) Write(p []byte) (int, error) { return len(p), nil }
func (e *blockedNativeEOF) Close() error                { e.once.Do(func() { close(e.closed) }); return nil }
func (e *blockedNativeEOF) CloseWrite() error           { close(e.entered); <-e.closed; return net.ErrClosed }
func TestNativeProxyBlockedCloseWriteIsFatalAndJoins(t *testing.T) {
	clock := &ioTestClock{now: time.Unix(1000, 0)}
	destination := &blockedNativeEOF{entered: make(chan struct{}), closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- ProxyNative(context.Background(), nativeEOFEndpoint{}, destination, clock) }()
	<-destination.entered
	clock.advance(NativeWriteTimeout)
	select {
	case e := <-done:
		var timeout net.Error
		if !errors.As(e, &timeout) || !timeout.Timeout() {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked directional EOF did not join")
	}
	if clock.active() != 0 {
		t.Fatal("directional EOF retained timer")
	}
}
func TestNativeProxyTCPHalfClosePreservesResponse(t *testing.T) {
	client, left := proxyTCPPair(t)
	target, right := proxyTCPPair(t)
	defer client.Close()
	defer target.Close()
	done := make(chan error, 1)
	go func() { done <- ProxyNative(context.Background(), left, right, NewClock()) }()
	go func() {
		data, e := io.ReadAll(target)
		if e == nil {
			_, _ = target.Write(append([]byte("response:"), data...))
			_ = target.CloseWrite()
		}
	}()
	_, _ = client.Write([]byte("request"))
	_ = client.CloseWrite()
	data, e := io.ReadAll(client)
	if e != nil || string(data) != "response:request" {
		t.Fatal("native half-close lost response", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestOpeningPhaseRechecksMonotonicDeadlineBeforeLateTimerCallback(t *testing.T) {
	clock := &ioTestClock{now: time.Unix(1000, 0)}
	ctx, stop := PhaseContext(context.Background(), clock, NativeOpenTimeout)
	defer stop()
	clock.mu.Lock()
	clock.now = clock.now.Add(NativeOpenTimeout)
	clock.mu.Unlock()
	if ctx.Err() == nil || !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		t.Fatal("opening phase accepted equality while its timer callback lagged")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("late deadline observation did not cancel phase")
	}
}
