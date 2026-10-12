package carrier

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"io"
	"sync"
	"testing"
	"time"
)

type phaseLifetimeStream struct {
	closed  bool
	carrier *Carrier
}

func (s *phaseLifetimeStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *phaseLifetimeStream) Write(p []byte) (int, error) {
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func (s *phaseLifetimeStream) Close() error {
	if s.carrier != nil {
		_ = s.carrier.ActiveStreams()
	}
	s.closed = true
	return nil
}

type phaseLifetimeBackend struct {
	stream           mux.Stream
	entered, release chan struct{}
}

func (b *phaseLifetimeBackend) OpenStream(context.Context) (mux.Stream, error) {
	if b.entered != nil {
		close(b.entered)
		<-b.release
	}
	return b.stream, nil
}
func (b *phaseLifetimeBackend) AcceptStream(context.Context) (mux.Stream, error) {
	return nil, errors.New("unused")
}
func (b *phaseLifetimeBackend) Close() error            { return nil }
func (b *phaseLifetimeBackend) ReceiveBufferLimit() int { return 0 }
func TestOpeningPhaseDoesNotOwnEstablishedStreamLifetime(t *testing.T) {
	stream := &phaseLifetimeStream{}
	backend := &phaseLifetimeBackend{stream: stream}
	c, e := New(backend, Config{MaxStreamsPerCarrier: 1})
	if e != nil {
		t.Fatal(e)
	}
	opening, cancel := context.WithCancel(context.Background())
	lease, e := c.OpenStreamForLifetime(opening, context.Background())
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	if _, e = lease.Stream.Write([]byte("established")); e != nil {
		t.Fatal("established stream retained opening context", e)
	}
	_ = lease.Release()
	if c.ActiveStreams() != 0 || c.InflightBytes() != 0 {
		t.Fatal("established stream reservation leaked")
	}
}
func TestCanceledOpeningClosesLateResultOutsideCarrierGuard(t *testing.T) {
	stream := &phaseLifetimeStream{}
	backend := &phaseLifetimeBackend{stream: stream, entered: make(chan struct{}), release: make(chan struct{})}
	c, e := New(backend, Config{MaxStreamsPerCarrier: 1})
	if e != nil {
		t.Fatal(e)
	}
	stream.carrier = c
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := c.OpenStreamForLifetime(ctx, context.Background()); done <- e }()
	<-backend.entered
	cancel()
	close(backend.release)
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("late close held carrier guard")
	}
	if !stream.closed || c.ActiveStreams() != 0 {
		t.Fatal("late result retained stream reservation")
	}
}

type budgetHeldStream struct {
	entered, closed chan struct{}
	once            sync.Once
}

func (s *budgetHeldStream) Read([]byte) (int, error) { <-s.closed; return 0, io.EOF }
func (s *budgetHeldStream) Write([]byte) (int, error) {
	close(s.entered)
	<-s.closed
	return 0, io.ErrClosedPipe
}
func (s *budgetHeldStream) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func TestClosingOneStreamCancelsItsInflightBudgetWait(t *testing.T) {
	held := &budgetHeldStream{entered: make(chan struct{}), closed: make(chan struct{})}
	backend := &fakeSession{next: []mux.Stream{held, &fakeStream{}}}
	c, e := New(backend, Config{MaxStreamsPerCarrier: 2, MaxInflight: 1, MaxBuffer: 1})
	if e != nil {
		t.Fatal(e)
	}
	first, e := c.OpenStream(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	second, e := c.OpenStream(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { _, e := first.Stream.Write([]byte("x")); firstDone <- e }()
	<-held.entered
	go func() { _, e := second.Stream.Write([]byte("y")); secondDone <- e }()
	deadline := time.Now().Add(time.Second)
	for c.Stats().BudgetWaits == 0 {
		if time.Now().After(deadline) {
			t.Fatal("second stream did not enter bounded budget wait")
		}
		time.Sleep(time.Millisecond)
	}
	_ = second.Release()
	select {
	case e := <-secondDone:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("stream close retained budget waiter")
	}
	if c.Closed() {
		t.Fatal("closing a budget waiter retired the healthy carrier")
	}
	_ = first.Release()
	<-firstDone
	if c.ActiveStreams() != 0 || c.InflightBytes() != 0 {
		t.Fatal("budget cancellation retained resources")
	}
}
