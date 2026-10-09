package legacy_npc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type boundedTestListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *boundedTestListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *boundedTestListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *boundedTestListener) Addr() net.Addr { return &net.TCPAddr{} }

type boundedTestConn struct {
	net.Conn
	entered             *atomic.Int32
	closed              *atomic.Int32
	readOnce, closeOnce sync.Once
}

func (c *boundedTestConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { c.entered.Add(1) })
	return c.Conn.Read(p)
}
func (c *boundedTestConn) Close() error {
	c.closeOnce.Do(func() { c.closed.Add(1) })
	return c.Conn.Close()
}
func TestStandaloneLegacyServeBoundsAndJoinsUnauthenticatedConnections(t *testing.T) {
	// A gateway needs no store access until a handshake is received.
	g := &Gateway{handshakeTimeout: time.Minute, maxHandshakeBytes: 4096}
	l := &boundedTestListener{conns: make(chan net.Conn, 300), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var entered, closed atomic.Int32
	var peers []net.Conn
	for i := 0; i < 300; i++ {
		a, b := net.Pipe()
		peers = append(peers, b)
		l.conns <- &boundedTestConn{Conn: a, entered: &entered, closed: &closed}
	}
	defer func() {
		for _, p := range peers {
			p.Close()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, l) }()
	until := time.Now().Add(2 * time.Second)
	for (entered.Load() != 256 || closed.Load() != 44) && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if entered.Load() != 256 || closed.Load() != 44 {
		cancel()
		t.Fatalf("accepted=%d overload closed=%d", entered.Load(), closed.Load())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve failed to join stalled handshakes")
	}
	if closed.Load() != 300 {
		t.Fatal("accepted connections retained")
	}
}
