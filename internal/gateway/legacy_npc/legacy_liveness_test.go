package legacy_npc

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestLegacyMuxPingSimultaneousOpaqueBodiesAndOpen(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	for _, body := range [][]byte{bytes.Repeat([]byte{'a'}, 29), bytes.Repeat([]byte{'b'}, 30)} {
		writePeerFrame(t, peer, Frame{Flag: FrameFlagPing, StreamID: -1, Content: body})
	}
	// Peer pings have been received without completing the local ping.
	seen := make(map[int]int)
	localPing := false
	for !localPing || seen[29] != 1 || seen[30] != 1 {
		frame := readPeerFrame(t, peer)
		switch frame.Flag {
		case FrameFlagPing:
			localPing = true
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
		case FrameFlagPingResponse:
			if len(frame.Content) != 29 && len(frame.Content) != 30 {
				t.Fatal("opaque response length changed")
			}
			value := byte('a')
			if len(frame.Content) == 30 {
				value = 'b'
			}
			if !bytes.Equal(frame.Content, bytes.Repeat([]byte{value}, len(frame.Content))) {
				t.Fatal("opaque ping body changed")
			}
			seen[len(frame.Content)]++
		default:
			t.Fatal("unexpected control during simultaneous ping")
		}
	}
	if stream := openPeerStream(t, mux, peer); stream == nil {
		t.Fatal("ping exchange prevented stream opening")
	}
}

func TestLegacyMuxPingExpiryUsesSentTimeAndExactPong(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	frame := readPeerFrame(t, peer)
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 1 })
	mux.mu.Lock()
	sent := mux.outstandingPings[string(frame.Content)]
	mux.mu.Unlock()
	if mux.pingExpired(sent.Add(mux.cfg.PingTimeout - time.Nanosecond)) {
		t.Fatal("ping expired before its transmission-based deadline")
	}
	if !mux.pingExpired(sent.Add(mux.cfg.PingTimeout)) {
		t.Fatal("transmitted unanswered ping did not expire")
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: []byte("unmatched")})
	writePeerFrame(t, peer, Frame{Flag: FrameFlagPing, StreamID: -1, Content: []byte("barrier")})
	if reply := readPeerFrame(t, peer); reply.Flag != FrameFlagPingResponse {
		t.Fatal("ping barrier was not processed")
	}
	if !mux.pingExpired(sent.Add(mux.cfg.PingTimeout)) {
		t.Fatal("unmatched pong refreshed liveness")
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 0 })
	if mux.pingExpired(sent.Add(2 * mux.cfg.PingTimeout)) {
		t.Fatal("exact pong did not clear liveness")
	}
}

func TestLegacyMuxRawWriteDeadlineBoundsInitialPing(t *testing.T) {
	cfg := LegacyMuxConfig{PingInterval: 25 * time.Millisecond, PingTimeout: 50 * time.Millisecond}
	mux, peer, observed := newDeadlineObservedMuxPipe(t, cfg)
	defer peer.Close()

	select {
	case deadline := <-observed.deadlines:
		if deadline.IsZero() {
			t.Fatal("initial ping cleared a deadline before raw transmission")
		}
	case <-time.After(time.Second):
		t.Fatal("initial ping did not set a raw write deadline")
	}
	mux.mu.Lock()
	if len(mux.outstandingPings) != 0 {
		mux.mu.Unlock()
		t.Fatal("unsent ping appeared in outstandingPings")
	}
	mux.mu.Unlock()

	select {
	case <-mux.Done():
	case <-time.After(5 * cfg.PingTimeout):
		t.Fatal("initial raw write did not stop within the configured bound")
	}
	mux.mu.Lock()
	terminal := mux.terminalErr
	mux.mu.Unlock()
	if netErr, ok := terminal.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("terminal error = %v, want raw write timeout", terminal)
	}
	if err := mux.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertLegacyMuxShutdownCleared(t, mux)
}

func TestLegacyMuxRawWriteDeadlineWakesBlockedStreamWrite(t *testing.T) {
	cfg := LegacyMuxConfig{PingInterval: 25 * time.Millisecond, PingTimeout: 50 * time.Millisecond}
	mux, peer := newLegacyMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 0 })
	stream := openPeerStream(t, mux, peer)

	payload := bytes.Repeat([]byte{'d'}, int(defaultLegacyMuxWindow)+1)
	result := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := stream.Write(payload)
		result <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	// The peer intentionally stops reading after acceptance, leaving the first
	// data frame in the raw writer until its deadline expires.
	waitForMuxState(t, mux, func() bool { return stream.outstanding == uint64(defaultLegacyMuxWindow) && mux.dataCount > 0 })
	select {
	case <-mux.Done():
	case <-time.After(5 * cfg.PingTimeout):
		t.Fatal("data raw write did not stop within the configured bound")
	}
	mux.mu.Lock()
	terminal := mux.terminalErr
	mux.mu.Unlock()
	if netErr, ok := terminal.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("terminal error = %v, want raw write timeout", terminal)
	}
	select {
	case got := <-result:
		if got.err == nil || got.n >= len(payload) {
			t.Fatalf("blocked Write() = (%d, %v), want interrupted partial write", got.n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("raw-write shutdown did not wake blocked Write")
	}
	if err := mux.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertLegacyMuxShutdownCleared(t, mux, stream)
}

func TestLegacyMuxTombstoneCleanupTransitions(t *testing.T) {
	t.Run("pending and in-flight cleanup survive expiry", func(t *testing.T) {
		mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		now := time.Now()
		mux.mu.Lock()
		pendingID := int32(701)
		pending := &legacyTombstone{expiresAt: now.Add(-time.Second)}
		mux.tombstones[pendingID] = pending
		mux.requestTombCleanupLocked(pendingID, pending)
		mux.purgeTombstonesLocked(now)
		if mux.tombstones[pendingID] != pending || !pending.cleanupPending {
			mux.mu.Unlock()
			t.Fatal("pending cleanup tombstone expired")
		}
		// Keep the first tombstone from being selected while exercising the
		// separate in-flight transition below.
		pending.cleanupPending = false
		pending.cleanupSent = true

		inFlightID := int32(702)
		inFlight := &legacyTombstone{expiresAt: now.Add(-time.Second)}
		mux.tombstones[inFlightID] = inFlight
		mux.requestTombCleanupLocked(inFlightID, inFlight)
		if !mux.materializeOneCloseLocked() || !inFlight.cleanupInFlight || inFlight.cleanupPending || inFlight.cleanupSent {
			mux.mu.Unlock()
			t.Fatal("cleanup did not enter the expected in-flight state")
		}
		mux.purgeTombstonesLocked(now)
		if mux.tombstones[inFlightID] != inFlight {
			mux.mu.Unlock()
			t.Fatal("in-flight cleanup tombstone expired")
		}
		mux.mu.Unlock()
	})

	t.Run("sent state waits for raw write and refreshes expiry", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		start := time.Now()
		const streamID = int32(703)
		mux.mu.Lock()
		tomb := &legacyTombstone{expiresAt: start.Add(-time.Second)}
		mux.tombstones[streamID] = tomb
		mux.requestTombCleanupLocked(streamID, tomb)
		mux.notifyLocked()
		mux.mu.Unlock()
		waitForMuxState(t, mux, func() bool {
			return tomb.cleanupInFlight && !tomb.cleanupPending && !tomb.cleanupSent
		})

		mux.mu.Lock()
		if err := mux.handleDataLocked(Frame{Flag: FrameFlagDataFinal, StreamID: streamID, Content: []byte("late")}); err != nil {
			mux.mu.Unlock()
			t.Fatalf("late data during cleanup in-flight error = %v", err)
		}
		if !tomb.lateDataNoted || !tomb.cleanupInFlight || tomb.cleanupPending || tomb.cleanupSent {
			mux.mu.Unlock()
			t.Fatal("late data changed in-flight cleanup state")
		}
		mux.mu.Unlock()
		select {
		case <-mux.Done():
			t.Fatal("late data during cleanup in-flight closed the mux")
		default:
		}

		frame := readPeerFrame(t, peer)
		if frame.Flag != FrameFlagStreamClose || frame.StreamID != streamID {
			t.Fatalf("cleanup frame = %#v", frame)
		}
		waitForMuxState(t, mux, func() bool {
			return !tomb.cleanupPending && !tomb.cleanupInFlight && tomb.cleanupSent
		})
		mux.mu.Lock()
		expiresAt := tomb.expiresAt
		mux.mu.Unlock()
		if !expiresAt.After(start) {
			t.Fatalf("cleanup expiry = %v, want refresh after %v", expiresAt, start)
		}
		assertNoPeerFrame(t, peer)
	})
}

func TestLegacyMuxRawWriteDeadlineFailureStopsMux(t *testing.T) {
	t.Run("deadline setup failure", func(t *testing.T) {
		server, peer := net.Pipe()
		defer peer.Close()
		setErr := errors.New("set write deadline failed")
		mux, err := NewLegacyMux(&deadlineObservedConn{Conn: server, deadlines: make(chan time.Time, 1), setErr: setErr}, LegacyMuxConfig{})
		if err != nil {
			t.Fatalf("NewLegacyMux() error = %v", err)
		}
		waitMuxDone(t, mux)
		mux.mu.Lock()
		terminal := mux.terminalErr
		mux.mu.Unlock()
		if !errors.Is(terminal, setErr) {
			t.Fatalf("terminal error = %v, want deadline setup error", terminal)
		}
		if err := mux.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		assertLegacyMuxShutdownCleared(t, mux)
	})

	t.Run("deadline clear failure", func(t *testing.T) {
		server, peer := net.Pipe()
		defer peer.Close()
		clearErr := errors.New("clear write deadline failed")
		mux, err := NewLegacyMux(&deadlineObservedConn{Conn: server, deadlines: make(chan time.Time, 2), clearErr: clearErr}, LegacyMuxConfig{})
		if err != nil {
			t.Fatalf("NewLegacyMux() error = %v", err)
		}
		if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagPing {
			t.Fatalf("initial frame = %#v", frame)
		}
		waitMuxDone(t, mux)
		mux.mu.Lock()
		terminal := mux.terminalErr
		mux.mu.Unlock()
		if !errors.Is(terminal, clearErr) {
			t.Fatalf("terminal error = %v, want deadline clear error", terminal)
		}
		if err := mux.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		assertLegacyMuxShutdownCleared(t, mux)
	})
}
