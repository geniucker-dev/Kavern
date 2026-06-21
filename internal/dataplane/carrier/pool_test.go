package carrier

import (
	"context"
	"errors"
	"testing"
)

func TestPoolChoosesAvailableCarrier(t *testing.T) {
	fullSession := &fakeSession{}
	full, err := New(fullSession, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := full.OpenStream(context.Background()); err != nil {
		t.Fatal(err)
	}
	available, err := New(&fakeSession{}, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(full, available)
	if err != nil {
		t.Fatal(err)
	}

	lease, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if lease == nil {
		t.Fatal("expected lease")
	}
}

func TestPoolReturnsClearErrorWhenAllCarriersFullOrClosed(t *testing.T) {
	full, err := New(&fakeSession{}, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := full.OpenStream(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed, err := New(&fakeSession{}, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(full, closed)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Acquire(context.Background()); !errors.Is(err, ErrNoCarrierAvailable) {
		t.Fatalf("acquire error = %v, want %v", err, ErrNoCarrierAvailable)
	}
}

func TestPoolChecksContextBeforeOpen(t *testing.T) {
	session := &fakeSession{}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(carrier)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := pool.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire error = %v, want %v", err, context.Canceled)
	}
	if session.OpenCount() != 0 {
		t.Fatalf("opens = %d, want 0", session.OpenCount())
	}
}

func TestClosingPoolClosesAllCarriersAndRejectsFutureAcquire(t *testing.T) {
	sessionA := &fakeSession{}
	sessionB := &fakeSession{}
	carrierA, err := New(sessionA, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	carrierB, err := New(sessionB, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(carrierA, carrierB)
	if err != nil {
		t.Fatal(err)
	}

	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if sessionA.closeCount != 1 || sessionB.closeCount != 1 {
		t.Fatalf("close counts = %d,%d; want 1,1", sessionA.closeCount, sessionB.closeCount)
	}
	if _, err := pool.Acquire(context.Background()); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("acquire after close error = %v, want %v", err, ErrPoolClosed)
	}
}
