package carrier

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
)

type heldSession struct {
	stream  *heldStream
	receive int
}

func (s *heldSession) ReceiveBufferLimit() int                          { return s.receive }
func (s *heldSession) OpenStream(context.Context) (mux.Stream, error)   { return s.stream, nil }
func (s *heldSession) AcceptStream(context.Context) (mux.Stream, error) { return nil, io.EOF }
func (s *heldSession) Close() error                                     { return s.stream.Close() }

type heldStream struct {
	entered chan int
	unblock chan struct{}
	once    sync.Once
}

func (s *heldStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *heldStream) Write(p []byte) (int, error) {
	s.entered <- len(p)
	<-s.unblock
	return 0, io.ErrClosedPipe
}
func (s *heldStream) Close() error { s.once.Do(func() { close(s.unblock) }); return nil }

func TestCarrierAggregateWriteBudgetCancellation(t *testing.T) {
	stream := &heldStream{entered: make(chan int, 2), unblock: make(chan struct{})}
	c, err := New(&heldSession{stream: stream, receive: 8}, Config{MaxStreamsPerCarrier: 2, MaxInflight: 4, MaxBuffer: 12})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, _ := c.OpenStream(ctx)
	defer first.Release()
	second, _ := c.OpenStream(ctx)
	defer second.Release()
	done := make(chan error, 2)
	go func() { _, err := first.Stream.Write(make([]byte, 100)); done <- err }()
	select {
	case n := <-stream.entered:
		if n != 4 {
			t.Fatalf("chunk=%d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("write never entered")
	}
	go func() { _, err := second.Stream.Write(make([]byte, 100)); done <- err }()
	until := time.Now().Add(time.Second)
	for c.Stats().BudgetWaits == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if c.Stats().BudgetWaits == 0 {
		t.Fatal("second writer did not enter the shared budget wait")
	}
	select {
	case <-stream.entered:
		t.Fatal("aggregate budget exceeded")
	case <-time.After(20 * time.Millisecond):
	}
	if got := c.InflightBytes(); got != 4 {
		t.Fatalf("inflight=%d", got)
	}
	cancel()
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled write succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled write leaked")
		}
	}
	if got := c.InflightBytes(); got != 0 {
		t.Fatalf("retained=%d", got)
	}
	stats := c.Stats()
	if stats.PeakInflightBytes != 4 || stats.BudgetWaits == 0 || stats.BudgetWaitDuration <= 0 || stats.InflightBytes != 0 {
		t.Fatalf("backpressure statistics do not reflect blocked/canceled writes: %+v", stats)
	}
}

func TestCarrierReceiveCapacityIncludedInBufferBudget(t *testing.T) {
	s := &heldSession{receive: 9}
	if _, err := New(s, Config{MaxStreamsPerCarrier: 1, MaxInflight: 4, MaxBuffer: 12}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized receive buffer accepted: %v", err)
	}
}

func TestPoolBoundsCarriersAndReusesClosedSlots(t *testing.T) {
	p, err := NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var first *Carrier
	for i := range 4 {
		stream := &heldStream{entered: make(chan int, 1), unblock: make(chan struct{})}
		c, err := New(&heldSession{stream: stream}, Config{MaxStreamsPerCarrier: 1})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = c
		}
		if err = p.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	extra, err := New(&heldSession{stream: &heldStream{entered: make(chan int, 1), unblock: make(chan struct{})}}, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if err = p.Add(extra); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("pool overflow=%v", err)
	}
	first.Close()
	if err = p.Add(extra); err != nil {
		t.Fatalf("closed slot not reused: %v", err)
	}
}

type notifiedSession struct {
	heldSession
	done chan struct{}
}

func (s *notifiedSession) Done() <-chan struct{} { return s.done }
func TestDisconnectedBackendCannotSatisfyReadiness(t *testing.T) {
	backend := &notifiedSession{heldSession: heldSession{stream: &heldStream{entered: make(chan int, 1), unblock: make(chan struct{})}}, done: make(chan struct{})}
	c, err := New(backend, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	close(backend.done)
	if !c.Closed() {
		t.Fatal("disconnected backend reported healthy")
	}
	if _, err = c.OpenStream(context.Background()); !errors.Is(err, ErrCarrierClosed) {
		t.Fatalf("dead carrier open=%v", err)
	}
	p, err := NewPool(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = p.WaitReady(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dead carrier satisfied readiness: %v", err)
	}
}

type observedConn struct {
	net.Conn
	mu        sync.Mutex
	attempted int
	once      sync.Once
	blocked   chan struct{}
}

func (c *observedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.attempted += len(p)
	if c.attempted > 65537 {
		c.once.Do(func() { close(c.blocked) })
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}
func TestCanceledWriteRetiresBlockedRealMuxCarrier(t *testing.T) {
	left, right := net.Pipe()
	wire := &observedConn{Conn: left, blocked: make(chan struct{})}
	backend := mux.NewSmuxBackend()
	cfg := mux.Config{MaxReceiveBuffer: 131072, MaxStreamBuffer: 65536, MaxFrameSize: 16384}
	peer, err := backend.Server(right, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, err := backend.Client(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	c, err := New(local, Config{MaxStreamsPerCarrier: 1, MaxInflight: 16384, MaxBuffer: 262144})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease, err := c.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	done := make(chan error, 1)
	go func() { _, err := lease.Stream.Write(make([]byte, 1<<20)); done <- err }()
	select {
	case <-wire.blocked:
	case <-time.After(time.Second):
		t.Fatal("write did not reach receive-capacity boundary")
	}
	select {
	case err := <-done:
		t.Fatalf("unread bounded carrier write ended before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled real backend write leaked")
	}
	if !c.Closed() || c.InflightBytes() != 0 {
		t.Fatal("canceled backend retained carrier payload")
	}
}
