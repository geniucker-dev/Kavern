package legacy_npc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestLegacyMuxOpenControlCapacityCancellationHasNoTombstone(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	// The unread initial ping occupies the raw writer, while the sole reader
	// processes valid peer opens into the real bounded rejection queue.
	waitForMuxState(t, mux, func() bool { return mux.pingCount == 1 && len(mux.pingQueue) == 0 })
	for i := 0; i < 72; i++ {
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamOpen, StreamID: int32(1000 + i)})
	}
	waitForMuxState(t, mux, func() bool { return mux.openCount == 72 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	runRobustnessWorker(t, mux, func() { _, err := mux.OpenStream(ctx); result <- err })
	waitForMuxState(t, mux, func() bool {
		for _, s := range mux.streams {
			return s.open != nil && s.open.state == legacyOpenWaiting
		}
		return false
	})
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("capacity-blocked open lost cancellation")
		}
	case <-time.After(robustnessWait):
		t.Fatal("capacity-blocked open did not stop")
	}
	mux.mu.Lock()
	valid := len(mux.streams) == 0 && len(mux.tombstones) == 0 && mux.tombstoneReservations == 0 && mux.openCount == 72 && !mux.closed
	mux.mu.Unlock()
	if !valid {
		t.Fatal("definitely-unsent canceled open leaked state or disturbed control capacity")
	}
	assertLegacyMuxQueueAccounting(t, mux)
}

func TestLegacyMuxCanceledInflightOpenProtectsTombstoneUntilRawWriteCompletes(t *testing.T) {
	cfg := LegacyMuxConfig{
		OpenTimeout:  time.Second,
		TombstoneTTL: time.Second,
	}
	mux, peer := newLegacyMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	waitForInitialPingSettled(t, mux)

	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(parent)
		result <- err
	}()
	waitForMuxState(t, mux, func() bool {
		for _, stream := range mux.streams {
			return stream.open != nil && stream.open.writeInFlight
		}
		return false
	})
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenStream() error = %v, want cancellation", err)
	}

	var streamID int32
	mux.mu.Lock()
	if len(mux.tombstones) != 1 || mux.tombstoneReservations != 0 {
		tombstones, reservations := len(mux.tombstones), mux.tombstoneReservations
		mux.mu.Unlock()
		t.Fatalf("canceled open tombstones=%d reservations=%d, want 1/0", tombstones, reservations)
	}
	for id, tomb := range mux.tombstones {
		streamID = id
		if !tomb.openWriteInFlight || tomb.cleanupPending || tomb.cleanupInFlight || tomb.cleanupSent {
			mux.mu.Unlock()
			t.Fatalf("tombstone state = %#v, want protected open write only", tomb)
		}
	}
	oldExpiry := time.Unix(0, 0)
	mux.tombstones[streamID].expiresAt = oldExpiry
	mux.purgeTombstonesLocked(time.Now())
	if _, ok := mux.tombstones[streamID]; !ok {
		mux.mu.Unlock()
		t.Fatal("in-flight open tombstone expired before raw 0x06 completion")
	}
	mux.mu.Unlock()

	open := readPeerFrame(t, peer)
	if open.Flag != FrameFlagStreamOpen || open.StreamID != streamID {
		t.Fatalf("raw open frame = %#v, want stream %d", open, streamID)
	}
	waitForMuxState(t, mux, func() bool {
		tomb := mux.tombstones[streamID]
		return tomb != nil && !tomb.openWriteInFlight
	})
	mux.mu.Lock()
	refreshedExpiry := mux.tombstones[streamID].expiresAt
	mux.mu.Unlock()
	if !refreshedExpiry.After(oldExpiry) {
		t.Fatalf("tombstone expiry = %v, want refresh after prior expiry %v", refreshedExpiry, oldExpiry)
	}

	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: streamID})
	readPeerCleanupClose(t, peer, streamID)
	waitForMuxState(t, mux, func() bool {
		tomb := mux.tombstones[streamID]
		return tomb != nil && !tomb.openWriteInFlight && !tomb.cleanupPending && !tomb.cleanupInFlight && tomb.cleanupSent
	})
	select {
	case <-mux.Done():
		t.Fatal("late accepted open closed the mux")
	default:
	}

	mux.mu.Lock()
	mux.purgeTombstonesLocked(time.Now().Add(2 * cfg.TombstoneTTL))
	tombstones, reservations := len(mux.tombstones), mux.tombstoneReservations
	mux.mu.Unlock()
	if tombstones != 0 || reservations != 0 {
		t.Fatalf("expired completed open retained tombstones=%d reservations=%d", tombstones, reservations)
	}
}

func TestLegacyMuxLateAcceptDuringInflightOpenWriteQueuesOneCleanup(t *testing.T) {
	cfg := LegacyMuxConfig{
		OpenTimeout:  time.Second,
		TombstoneTTL: time.Second,
		PingInterval: 500 * time.Millisecond,
		PingTimeout:  time.Second,
	}
	mux, peer, observed := newDeadlineObservedMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	waitForInitialPingSettled(t, mux)

	clearGate := make(chan struct{})
	clearStarted := make(chan struct{}, 1)
	observed.blockNextDeadlineClear(clearGate, clearStarted)
	released := false
	defer func() {
		if !released {
			close(clearGate)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(ctx)
		result <- err
	}()
	open := readPeerFrame(t, peer)
	if open.Flag != FrameFlagStreamOpen {
		t.Fatalf("open frame = %#v", open)
	}
	select {
	case <-clearStarted:
	case <-time.After(time.Second):
		t.Fatal("writer did not reach raw open deadline clear")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenStream() error = %v, want cancellation", err)
	}
	waitForMuxState(t, mux, func() bool {
		tomb := mux.tombstones[open.StreamID]
		return tomb != nil && tomb.openWriteInFlight
	})

	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	waitForMuxState(t, mux, func() bool {
		tomb := mux.tombstones[open.StreamID]
		return tomb != nil && tomb.openWriteInFlight && tomb.cleanupPending && !tomb.cleanupInFlight && !tomb.cleanupSent
	})
	close(clearGate)
	released = true
	readPeerCleanupClose(t, peer, open.StreamID)
	waitForMuxState(t, mux, func() bool {
		tomb := mux.tombstones[open.StreamID]
		return tomb != nil && !tomb.openWriteInFlight && !tomb.cleanupPending && !tomb.cleanupInFlight && tomb.cleanupSent
	})
	assertNoSecondPeerCleanupClose(t, peer, open.StreamID, 10*time.Millisecond)
	select {
	case <-mux.Done():
		t.Fatal("late accepted in-flight open closed the mux")
	default:
	}
}

func TestLegacyMuxInflightOpenWriteTimeoutClearsProtectedTombstone(t *testing.T) {
	cfg := LegacyMuxConfig{
		OpenTimeout:  10 * time.Millisecond,
		TombstoneTTL: 10 * time.Millisecond,
		PingInterval: 5 * time.Millisecond,
		PingTimeout:  20 * time.Millisecond,
	}
	mux, peer := newLegacyMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	waitForInitialPingSettled(t, mux)

	result := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(context.Background())
		result <- err
	}()
	waitForMuxState(t, mux, func() bool {
		for _, stream := range mux.streams {
			return stream.open != nil && stream.open.writeInFlight
		}
		return false
	})
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OpenStream() error = %v, want open timeout", err)
	}
	waitForMuxState(t, mux, func() bool {
		for _, tomb := range mux.tombstones {
			return tomb.openWriteInFlight
		}
		return false
	})
	waitMuxDone(t, mux)
	if err := mux.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertLegacyMuxShutdownCleared(t, mux)
}

func readPeerCleanupClose(t *testing.T, peer net.Conn, streamID int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if err := peer.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(peer)
		_ = peer.SetReadDeadline(time.Time{})
		if err != nil {
			t.Fatalf("ReadFrame(peer) error = %v", err)
		}
		switch frame.Flag {
		case FrameFlagPing:
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
		case FrameFlagStreamClose:
			if frame.StreamID == streamID {
				return
			}
			t.Fatalf("cleanup close stream = %d, want %d", frame.StreamID, streamID)
		default:
			t.Fatalf("frame before cleanup close = %#v", frame)
		}
	}
}
