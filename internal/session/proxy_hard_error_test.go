package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errHardProxy = errors.New("deterministic irrecoverable copy error")

// Each peer's blocked Read can return only after Close. There is no timeout,
// EOF or spontaneous peer completion that could hide the lifecycle defect.
type hardProxyEndpoint struct {
	entered, closed, trigger, failed chan struct{}
	readErr, writeErr, source        bool
	once, enteredOnce, failedOnce    sync.Once
	reads                            atomic.Int32
	active, closes                   atomic.Int32
}

func newHardProxyEndpoint(trigger, failed chan struct{}) *hardProxyEndpoint {
	return &hardProxyEndpoint{entered: make(chan struct{}), closed: make(chan struct{}), trigger: trigger, failed: failed}
}
func (e *hardProxyEndpoint) Read(p []byte) (int, error) {
	e.active.Add(1)
	defer e.active.Add(-1)
	e.enteredOnce.Do(func() { close(e.entered) })
	if e.readErr {
		<-e.trigger
		e.failedOnce.Do(func() { close(e.failed) })
		return 0, errHardProxy
	}
	if e.source && e.reads.Add(1) == 1 {
		<-e.trigger
		p[0] = 'x'
		return 1, nil
	}
	<-e.closed
	return 0, io.ErrClosedPipe
}
func (e *hardProxyEndpoint) Write(p []byte) (int, error) {
	e.active.Add(1)
	defer e.active.Add(-1)
	if e.writeErr {
		e.failedOnce.Do(func() { close(e.failed) })
		return 0, errHardProxy
	}
	return len(p), nil
}
func (e *hardProxyEndpoint) Close() error {
	e.closes.Add(1)
	e.once.Do(func() { close(e.closed) })
	return nil
}
func TestProxyHardErrorJoinsOtherCopy(t *testing.T) {
	for _, direction := range []string{"left", "right"} {
		for _, kind := range []string{"read", "write"} {
			t.Run(direction+"_"+kind, func(t *testing.T) {
				trigger, failed := make(chan struct{}), make(chan struct{})
				l, r := newHardProxyEndpoint(trigger, failed), newHardProxyEndpoint(trigger, failed)
				bad, other := l, r
				if direction == "right" {
					bad, other = r, l
				}
				if kind == "read" {
					bad.readErr = true
				} else {
					bad.writeErr = true
					other.source = true
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- ProxyBidirectional(ctx, l, r) }()
				waitProxyWorker(t, l.entered)
				waitProxyWorker(t, r.entered)
				close(trigger)
				waitProxyWorker(t, failed)
				var err error
				select {
				case err = <-done:
				case <-time.After(200 * time.Millisecond):
					t.Errorf("hard error returned from one copy but proxy still waits; active left/right=%d/%d closes=%d/%d", l.active.Load(), r.active.Load(), l.closes.Load(), r.closes.Load())
					cancel()
					select {
					case err = <-done:
					case <-time.After(time.Second):
						t.Fatal("cleanup failed to join proxy")
					}
				}
				if !errors.Is(err, errHardProxy) {
					t.Fatalf("lost original hard error: %v", err)
				}
				if l.active.Load() != 0 || r.active.Load() != 0 || l.closes.Load() != 1 || r.closes.Load() != 1 {
					t.Fatal("active copies or duplicate/missing Close after return")
				}
			})
		}
	}
}
func proxyTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	peer, e := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	server, e := l.AcceptTCP()
	if e != nil {
		peer.Close()
		t.Fatal(e)
	}
	for _, c := range []*net.TCPConn{peer, server} {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		t.Cleanup(func() { c.Close() })
	}
	return server, peer
}
func TestProxyTCPHalfClosePreservesResponse(t *testing.T) {
	l, client := proxyTCPPair(t)
	r, target := proxyTCPPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ProxyBidirectional(ctx, l, r) }()
	response := bytes.Repeat([]byte("abcdefgh"), 32768)
	targetDone := make(chan error, 1)
	go func() {
		request, e := io.ReadAll(target)
		if e == nil && string(request) != "request" {
			e = errors.New("request mismatch")
		}
		if e == nil {
			var n int
			n, e = target.Write(response)
			if e == nil && n != len(response) {
				e = io.ErrShortWrite
			}
		}
		if e == nil {
			e = target.CloseWrite()
		}
		targetDone <- e
	}()
	if _, e := client.Write([]byte("request")); e != nil {
		t.Fatal(e)
	}
	if e := client.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(client)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("normal half-close lost response bytes: %d/%d", len(got), len(response))
	}
	if e = <-targetDone; e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("normal proxy did not finish")
	}
}
