package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type directionalTimeout struct{}

func (directionalTimeout) Error() string   { return "deterministic directional timeout" }
func (directionalTimeout) Timeout() bool   { return true }
func (directionalTimeout) Temporary() bool { return true }

type timeoutReadEndpoint struct{ *hardProxyEndpoint }

func (e timeoutReadEndpoint) Read(p []byte) (int, error) {
	n, err := e.hardProxyEndpoint.Read(p)
	if errors.Is(err, errHardProxy) {
		err = directionalTimeout{}
	}
	return n, err
}

type diagnosticHalfCloseEndpoint struct {
	*hardProxyEndpoint
	entered chan struct{}
	once    sync.Once
	calls   atomic.Int32
	block   bool
	fail    bool
}

func (e *diagnosticHalfCloseEndpoint) CloseWrite() error {
	e.calls.Add(1)
	e.once.Do(func() { close(e.entered) })
	if e.block {
		<-e.closed
	}
	if e.fail {
		return errors.New("directional EOF failed")
	}
	return nil
}
func TestProxyHardErrorSkipsBlockingHalfClose(t *testing.T) {
	trigger, failed := make(chan struct{}), make(chan struct{})
	l, r := newHardProxyEndpoint(trigger, failed), newHardProxyEndpoint(trigger, failed)
	l.readErr = true
	destination := &diagnosticHalfCloseEndpoint{hardProxyEndpoint: r, entered: make(chan struct{}), block: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ProxyBidirectional(ctx, l, destination) }()
	waitProxyWorker(t, l.entered)
	waitProxyWorker(t, r.entered)
	close(trigger)
	waitProxyWorker(t, failed)
	select {
	case err := <-done:
		if !errors.Is(err, errHardProxy) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("hard error blocked in half-close")
	}
	if destination.calls.Load() != 0 || l.active.Load() != 0 || r.active.Load() != 0 || l.closes.Load() != 1 || r.closes.Load() != 1 {
		t.Fatal("hard path did not skip half-close and join once")
	}
}
func TestProxyDirectionalTimeoutBoundary(t *testing.T) {
	for _, halfCloseOK := range []bool{true, false} {
		name := "half_close_ok"
		if !halfCloseOK {
			name = "half_close_failed"
		}
		t.Run(name, func(t *testing.T) {
			trigger, failed := make(chan struct{}), make(chan struct{})
			l, r := newHardProxyEndpoint(trigger, failed), newHardProxyEndpoint(trigger, failed)
			l.readErr = true
			destination := &diagnosticHalfCloseEndpoint{hardProxyEndpoint: r, entered: make(chan struct{}), fail: !halfCloseOK}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- ProxyBidirectional(ctx, timeoutReadEndpoint{l}, destination) }()
			waitProxyWorker(t, l.entered)
			waitProxyWorker(t, r.entered)
			close(trigger)
			waitProxyWorker(t, failed)
			waitProxyWorker(t, destination.entered)
			var err error
			if halfCloseOK {
				select {
				case err = <-done:
					t.Fatalf("directional timeout truncated reverse: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
				if l.closes.Load() != 0 || r.closes.Load() != 0 || r.active.Load() != 1 {
					t.Fatal("reverse was not retained after directional EOF")
				}
				cancel()
			}
			select {
			case err = <-done:
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("proxy did not join")
			}
			var original directionalTimeout
			if !errors.As(err, &original) {
				t.Fatalf("lost directional timeout: %v", err)
			}
			if l.active.Load() != 0 || r.active.Load() != 0 || l.closes.Load() != 1 || r.closes.Load() != 1 {
				t.Fatal("active copies or duplicate Close")
			}
		})
	}
}
