package legacy_npc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type deadlineObservedConn struct {
	net.Conn
	deadlines chan time.Time
	setErr    error
	clearErr  error

	mu           sync.Mutex
	clearGate    <-chan struct{}
	clearStarted chan struct{}
}

// Raw progress covers writer-claim transitions that deliberately do not expose
// production instrumentation. Snapshot this signal before inspecting mux state.
type muxProgressConn struct {
	net.Conn
	mu      sync.Mutex
	changed chan struct{}
}

func observeMuxProgress(conn net.Conn) *muxProgressConn {
	return &muxProgressConn{Conn: conn, changed: make(chan struct{})}
}

func (c *muxProgressConn) progressChanged() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changed
}

func (c *muxProgressConn) SetWriteDeadline(deadline time.Time) error {
	err := c.Conn.SetWriteDeadline(deadline)
	c.mu.Lock()
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return err
}

func (c *deadlineObservedConn) SetWriteDeadline(deadline time.Time) error {
	select {
	case c.deadlines <- deadline:
	default:
	}
	if deadline.IsZero() {
		c.mu.Lock()
		gate := c.clearGate
		started := c.clearStarted
		c.mu.Unlock()
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		if gate != nil {
			<-gate
		}
		if c.clearErr != nil {
			return c.clearErr
		}
	} else if c.setErr != nil {
		return c.setErr
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *deadlineObservedConn) blockNextDeadlineClear(gate <-chan struct{}, started chan struct{}) {
	c.mu.Lock()
	c.clearGate = gate
	c.clearStarted = started
	c.mu.Unlock()
}

func newLegacyMuxPipe(t *testing.T, cfg LegacyMuxConfig) (*LegacyMux, net.Conn) {
	t.Helper()
	server, peer := net.Pipe()
	mux, err := NewLegacyMux(observeMuxProgress(server), cfg)
	if err != nil {
		_ = peer.Close()
		t.Fatalf("NewLegacyMux() error = %v", err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = mux.Close()
	})
	return mux, peer
}

func newDeadlineObservedMuxPipe(t *testing.T, cfg LegacyMuxConfig) (*LegacyMux, net.Conn, *deadlineObservedConn) {
	t.Helper()
	server, peer := net.Pipe()
	observed := &deadlineObservedConn{Conn: server, deadlines: make(chan time.Time, 16)}
	mux, err := NewLegacyMux(observeMuxProgress(observed), cfg)
	if err != nil {
		_ = server.Close()
		_ = peer.Close()
		t.Fatalf("NewLegacyMux() error = %v", err)
	}
	t.Cleanup(func() {
		_ = peer.Close()
		_ = mux.Close()
	})
	return mux, peer, observed
}

func readPeerFrame(t *testing.T, peer net.Conn) Frame {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer peer.SetReadDeadline(time.Time{})
	frame, err := ReadFrame(peer)
	if err != nil {
		t.Fatalf("ReadFrame(peer) error = %v", err)
	}
	return frame
}

func writePeerFrame(t *testing.T, peer net.Conn, frame Frame) {
	t.Helper()
	if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer peer.SetWriteDeadline(time.Time{})
	if err := WriteFrame(peer, frame); err != nil {
		t.Fatalf("WriteFrame(peer) error = %v", err)
	}
}

func assertNoPeerFrame(t *testing.T, peer net.Conn) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	defer peer.SetReadDeadline(time.Time{})
	_, err := ReadFrame(peer)
	if err == nil {
		t.Fatal("unexpected frame")
	}
	if !errors.Is(err, net.ErrClosed) {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("ReadFrame(peer) error = %v, want timeout", err)
		}
	}
}

func assertNoSecondPeerCleanupClose(t *testing.T, peer net.Conn, streamID int32, observation time.Duration) {
	t.Helper()
	deadline := time.Now().Add(observation)
	for {
		if err := peer.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(peer)
		_ = peer.SetReadDeadline(time.Time{})
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			}
			t.Fatalf("ReadFrame(peer) error = %v", err)
		}
		switch frame.Flag {
		case FrameFlagPing:
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
		case FrameFlagStreamClose:
			if frame.StreamID == streamID {
				t.Fatalf("duplicate cleanup close for stream %d", streamID)
			}
			t.Fatalf("unexpected close for stream %d", frame.StreamID)
		default:
			t.Fatalf("unexpected frame while observing cleanup close = %#v", frame)
		}
	}
}

func acknowledgeInitialPing(t *testing.T, peer net.Conn) {
	t.Helper()
	frame := readPeerFrame(t, peer)
	if frame.Flag != FrameFlagPing || frame.StreamID != -1 {
		t.Fatalf("initial frame = %#v, want ping", frame)
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
}

func waitForInitialPingSettled(t *testing.T, mux *LegacyMux) {
	t.Helper()
	waitForMuxState(t, mux, func() bool {
		return mux.localPingQueued == "" && mux.pingCount == 0 && len(mux.outstandingPings) == 0
	})
}

func openPeerStream(t *testing.T, mux *LegacyMux, peer net.Conn) *LegacyStream {
	t.Helper()
	result := make(chan struct {
		stream *LegacyStream
		err    error
	}, 1)
	go func() {
		stream, err := mux.OpenStream(context.Background())
		result <- struct {
			stream *LegacyStream
			err    error
		}{stream: stream, err: err}
	}()

	frame := readPeerFrame(t, peer)
	if frame.Flag != FrameFlagStreamOpen {
		t.Fatalf("open frame = %#v, want stream open", frame)
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: frame.StreamID})
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("OpenStream() error = %v", got.err)
		}
		return got.stream
	case <-time.After(time.Second):
		t.Fatal("OpenStream() did not return")
		return nil
	}
}

func waitMuxDone(t *testing.T, mux *LegacyMux) {
	t.Helper()
	select {
	case <-mux.Done():
	case <-time.After(time.Second):
		t.Fatal("mux did not stop")
	}
}

func assertLegacyMuxQueueAccounting(t *testing.T, mux *LegacyMux) {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	control := mux.pingCount + mux.openCount + mux.windowCount
	dataCapacity := mux.dataCapacityLocked()
	if control > mux.cfg.MaxControlFrames {
		t.Fatalf("control queued/in-flight = %d, cap = %d", control, mux.cfg.MaxControlFrames)
	}
	if mux.dataCount > dataCapacity {
		t.Fatalf("data/close queued/in-flight = %d, cap = %d", mux.dataCount, dataCapacity)
	}
	if mux.totalCount != control+mux.dataCount {
		t.Fatalf("total queued/in-flight = %d, want %d", mux.totalCount, control+mux.dataCount)
	}
	if mux.totalCount > mux.cfg.MaxQueuedFramesTotal {
		t.Fatalf("total queued/in-flight = %d, cap = %d", mux.totalCount, mux.cfg.MaxQueuedFramesTotal)
	}
}

func assertLegacyMuxShutdownCleared(t *testing.T, mux *LegacyMux, streams ...*LegacyStream) {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if len(mux.pingQueue) != 0 || len(mux.openQueue) != 0 || len(mux.windowQueue) != 0 || len(mux.dataReady) != 0 || len(mux.closeReady) != 0 {
		t.Fatalf("shutdown retained outbound queues ping=%d open=%d window=%d data_ready=%d close_ready=%d", len(mux.pingQueue), len(mux.openQueue), len(mux.windowQueue), len(mux.dataReady), len(mux.closeReady))
	}
	if len(mux.streams) != 0 || len(mux.tombstones) != 0 || len(mux.outstandingPings) != 0 || len(mux.earlyPongs) != 0 {
		t.Fatalf("shutdown retained maps streams=%d tombstones=%d pings=%d early_pongs=%d", len(mux.streams), len(mux.tombstones), len(mux.outstandingPings), len(mux.earlyPongs))
	}
	if mux.localPingQueued != "" || mux.tombstoneReservations != 0 || mux.bufferedBytes != 0 || mux.pingCount != 0 || mux.openCount != 0 || mux.windowCount != 0 || mux.dataCount != 0 || mux.totalCount != 0 {
		t.Fatalf("shutdown retained accounting local_ping=%q reservations=%d buffered=%d counts=%d/%d/%d/%d/%d", mux.localPingQueued, mux.tombstoneReservations, mux.bufferedBytes, mux.pingCount, mux.openCount, mux.windowCount, mux.dataCount, mux.totalCount)
	}
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		if stream.state != legacyStreamFullyClosed || stream.recvBlocks != nil || stream.recvBuffered != 0 || stream.dataQueue != nil || stream.windowQueued || stream.windowInFlight || stream.pendingConsumed != 0 || stream.inFlightConsumed != 0 {
			t.Fatalf("shutdown retained stream state=%d blocks=%d buffered=%d data=%d window=%t/%t pending=%d in_flight=%d", stream.state, len(stream.recvBlocks), stream.recvBuffered, len(stream.dataQueue), stream.windowQueued, stream.windowInFlight, stream.pendingConsumed, stream.inFlightConsumed)
		}
	}
}
