package session

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedProxyConn struct {
	net.Conn
	readEntered, writeEntered chan struct{}
	readOnce, writeOnce       sync.Once
	active                    atomic.Int32
	closes                    atomic.Int32
}

func (c *observedProxyConn) Read(p []byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	c.readOnce.Do(func() { close(c.readEntered) })
	return c.Conn.Read(p)
}
func (c *observedProxyConn) Write(p []byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	c.writeOnce.Do(func() { close(c.writeEntered) })
	return c.Conn.Write(p)
}
func (c *observedProxyConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestProxyCancellationJoinsBlockedCopies(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		name := "reads"
		if blockedWrite {
			name = "write"
		}
		t.Run(name, func(t *testing.T) {
			left, client := net.Pipe()
			right, target := net.Pipe()
			observed := func(c net.Conn) *observedProxyConn {
				return &observedProxyConn{Conn: c, readEntered: make(chan struct{}), writeEntered: make(chan struct{})}
			}
			l, r := observed(left), observed(right)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			var result error
			go func() { defer close(done); result = ProxyBidirectional(ctx, l, r) }()
			t.Cleanup(func() { cancel(); _ = client.Close(); _ = target.Close(); waitProxyWorker(t, done) })
			waitProxyWorker(t, l.readEntered)
			waitProxyWorker(t, r.readEntered)
			if blockedWrite {
				_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := client.Write([]byte("blocked outbound")); err != nil {
					t.Fatal(err)
				}
				waitProxyWorker(t, r.writeEntered)
			}
			cancel()
			waitProxyWorker(t, done)
			if result != nil {
				t.Fatal("proxy cancellation changed normalized closure behavior")
			}
			if l.active.Load() != 0 || r.active.Load() != 0 || l.closes.Load() != 1 || r.closes.Load() != 1 {
				t.Fatal("proxy returned with active copies or duplicate/missing endpoint closure")
			}
		})
	}
}

func waitProxyWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy worker did not finish")
	}
}
