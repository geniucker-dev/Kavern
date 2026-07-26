package legacy_npc

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestLegacyMuxConfigFixedReceiveWindowBounds(t *testing.T) {
	for _, value := range []uint32{4085, 122549} {
		if _, err := normalizeLegacyMuxConfig(LegacyMuxConfig{FixedReceiveWindowBytes: value}); !errors.Is(err, ErrInvalidLegacyMuxConfig) {
			t.Fatalf("FixedReceiveWindowBytes=%d error = %v, want invalid config", value, err)
		}
	}
	for _, value := range []uint32{122550, 130000} {
		cfg, err := normalizeLegacyMuxConfig(LegacyMuxConfig{FixedReceiveWindowBytes: value})
		if err != nil {
			t.Fatalf("FixedReceiveWindowBytes=%d error = %v", value, err)
		}
		if cfg.FixedReceiveWindowBytes != value || cfg.HardReceiveBufferBytes < value+legacyProtocolMaxContentBytes {
			t.Fatalf("normalized config = %+v", cfg)
		}
	}
}

func TestLegacyMuxConfigControlReservations(t *testing.T) {
	cfg, err := normalizeLegacyMuxConfig(LegacyMuxConfig{})
	if err != nil {
		t.Fatalf("normalizeLegacyMuxConfig() error = %v", err)
	}
	if cfg.MaxStreams != 64 || cfg.MaxQueuedFramesTotal != 2048 || cfg.MaxControlFrames != 160 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	pingCap := legacyPingPongCapacity
	openCap := cfg.MaxStreams + 8
	windowCap := cfg.MaxStreams
	if pingCap+openCap+windowCap != 2*cfg.MaxStreams+24 || pingCap+openCap+windowCap > cfg.MaxControlFrames {
		t.Fatalf("control subcaps ping=%d open=%d window=%d total=%d cap=%d", pingCap, openCap, windowCap, pingCap+openCap+windowCap, cfg.MaxControlFrames)
	}
	for _, invalid := range []LegacyMuxConfig{
		{MaxControlFrames: 151},
		{MaxQueuedFramesTotal: 160, MaxControlFrames: 160},
		{HardReceiveBufferBytes: defaultLegacyMuxWindow + legacyProtocolMaxContentBytes - 1},
		{PingInterval: time.Second, PingTimeout: time.Second},
		{OpenTimeout: time.Second, TombstoneTTL: 500 * time.Millisecond},
		{MaxStreams: 64, MaxTombstones: 63},
	} {
		if _, err := normalizeLegacyMuxConfig(invalid); !errors.Is(err, ErrInvalidLegacyMuxConfig) {
			t.Fatalf("normalizeLegacyMuxConfig(%+v) error = %v, want invalid config", invalid, err)
		}
	}
}

func TestLegacyMuxOpenDataOwnershipAndSegmentation(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)

	payload := make([]byte, legacyProtocolMaxContentBytes+1)
	for index := range payload {
		payload[index] = byte(index % 251)
	}
	written := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := stream.Write(payload)
		written <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	result := <-written
	if result.n != len(payload) || result.err != nil {
		t.Fatalf("Write() = (%d, %v)", result.n, result.err)
	}
	for index := range payload {
		payload[index] = 0
	}

	first := readPeerFrame(t, peer)
	second := readPeerFrame(t, peer)
	if first.Flag != FrameFlagDataContinue || len(first.Content) != legacyProtocolMaxContentBytes || second.Flag != FrameFlagDataFinal || len(second.Content) != 1 {
		t.Fatalf("frames = %#v, %#v", first, second)
	}
	if first.Content[1] != byte(1%251) || second.Content[0] != byte(legacyProtocolMaxContentBytes%251) {
		t.Fatal("queued bytes changed after caller mutation")
	}
}

func TestLegacyStreamZeroWriteDoesNotQueueFrame(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	if n, err := stream.Write(nil); n != 0 || err != nil {
		t.Fatalf("Write(nil) = (%d, %v)", n, err)
	}
	mux.mu.Lock()
	queued := len(stream.dataQueue)
	dataCount := mux.dataCount
	mux.mu.Unlock()
	if queued != 0 || dataCount != 0 {
		t.Fatalf("zero Write queued=%d data_count=%d", queued, dataCount)
	}
}

func TestLegacyMuxRemoteCloseDrainsDataAndLateDataIsScoped(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	first := openPeerStream(t, mux, peer)
	second := openPeerStream(t, mux, peer)

	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: first.id, Content: []byte("one")})
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: first.id})
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: first.id, Content: []byte("late")})
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: second.id, Content: []byte("two")})

	buffer := make([]byte, 8)
	n, err := first.Read(buffer)
	if err != nil || string(buffer[:n]) != "one" {
		t.Fatalf("first Read() = (%d, %v, %q)", n, err, buffer[:n])
	}
	if _, err := first.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("first final Read() error = %v, want EOF", err)
	}
	n, err = second.Read(buffer)
	if err != nil || string(buffer[:n]) != "two" {
		t.Fatalf("second Read() = (%d, %v, %q)", n, err, buffer[:n])
	}
	select {
	case <-mux.Done():
		t.Fatal("late data closed the mux")
	default:
	}
}

func TestLegacyMuxUnknownStreamDataClosesMux(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: 99, Content: []byte("bad")})
	waitMuxDone(t, mux)
}

func TestLegacyMuxMalformedFrameClosesMux(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	if _, err := peer.Write([]byte{0x09, 1, 0, 0, 0}); err != nil {
		t.Fatalf("raw malformed frame write = %v", err)
	}
	waitMuxDone(t, mux)
}

func TestLegacyMuxPeerPingBodiesAreEchoed(t *testing.T) {
	_, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	for _, size := range []int{29, 30} {
		body := make([]byte, size)
		for index := range body {
			body[index] = byte('a' + index%26)
		}
		writePeerFrame(t, peer, Frame{Flag: FrameFlagPing, StreamID: -1, Content: body})
		response := readPeerFrame(t, peer)
		if response.Flag != FrameFlagPingResponse || string(response.Content) != string(body) {
			t.Fatalf("ping response = %#v", response)
		}
	}
}

func TestLegacyMuxPingTrackingStartsAfterRawWrite(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	// The writer has claimed the immediate ping, but net.Pipe has not accepted
	// its raw bytes. Liveness must not begin yet.
	waitForMuxState(t, mux, func() bool { return mux.pingCount == 1 && len(mux.pingQueue) == 0 })
	if mux.pingExpired(time.Now().Add(10 * defaultLegacyMuxPingTimeout)) {
		t.Fatal("unsent ping started the liveness timer")
	}

	ping := readPeerFrame(t, peer)
	if ping.Flag != FrameFlagPing {
		t.Fatalf("initial frame = %#v, want ping", ping)
	}
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 1 })

	writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: []byte("unmatched")})
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 1 })
	writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 0 })
}

func TestLegacyMuxUnmatchedTransmittedPingTimesOut(t *testing.T) {
	cfg := LegacyMuxConfig{PingInterval: 10 * time.Millisecond, PingTimeout: 20 * time.Millisecond}
	mux, peer := newLegacyMuxPipe(t, cfg)
	ping := readPeerFrame(t, peer)
	if ping.Flag != FrameFlagPing {
		t.Fatalf("initial frame = %#v, want ping", ping)
	}
	// Do not answer the raw transmitted ping.
	waitForMuxState(t, mux, func() bool { return len(mux.outstandingPings) == 1 })
	// Keep the subsequent periodic ping raw-writable so this test exercises
	// ping liveness rather than the separate raw-write timeout bound.
	if next := readPeerFrame(t, peer); next.Flag != FrameFlagPing {
		t.Fatalf("next frame = %#v, want periodic ping", next)
	}
	select {
	case <-mux.Done():
		mux.mu.Lock()
		err := mux.terminalErr
		mux.mu.Unlock()
		if !errors.Is(err, ErrLegacyPingTimeout) {
			t.Fatalf("terminal error = %v, want ping timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unmatched transmitted ping did not time out")
	}
}

func TestLegacyMuxRequiredControlOverflowClosesAndOptionalPingDefers(t *testing.T) {
	t.Run("optional local ping defers", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		waitForMuxState(t, mux, func() bool { return mux.pingCount == 1 && len(mux.pingQueue) == 0 })
		for index := 0; index < legacyPingPongCapacity-1; index++ {
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPing, StreamID: -1, Content: []byte{byte(index)}})
		}
		waitForMuxState(t, mux, func() bool { return mux.pingCount == legacyPingPongCapacity })
		mux.mu.Lock()
		beforeKey := mux.localPingQueued
		beforeCount := mux.pingCount
		mux.mu.Unlock()
		mux.queueLocalPing()
		mux.mu.Lock()
		queued := mux.localPingQueued
		count := mux.pingCount
		closed := mux.closed
		mux.mu.Unlock()
		if queued != beforeKey || count != beforeCount || closed {
			t.Fatalf("optional ping changed queued=%q->%q count=%d->%d closed=%t", beforeKey, queued, beforeCount, count, closed)
		}
		assertLegacyMuxQueueAccounting(t, mux)
	})

	t.Run("peer ping response overflow", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		waitForMuxState(t, mux, func() bool { return mux.pingCount == 1 && len(mux.pingQueue) == 0 })
		for index := 0; index < legacyPingPongCapacity; index++ {
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPing, StreamID: -1, Content: []byte{byte(index)}})
		}
		waitMuxDone(t, mux)
	})

	t.Run("peer open rejection overflow", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{MaxStreams: 1, MaxQueuedFramesTotal: 27, MaxControlFrames: 26})
		waitForMuxState(t, mux, func() bool { return mux.pingCount == 1 && len(mux.pingQueue) == 0 })
		for index := 1; index <= 10; index++ {
			writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamOpen, StreamID: int32(index)})
		}
		waitMuxDone(t, mux)
	})
}

func TestLegacyMuxPingBurstYieldsOpenControl(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	for index := 0; index < 8; index++ {
		writePeerFrame(t, peer, Frame{Flag: FrameFlagPing, StreamID: -1, Content: []byte{byte(index)}})
	}
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
	waitForMuxState(t, mux, func() bool { return mux.openCount == 1 })
	var open Frame
	for index := 0; index <= legacyPingBurst; index++ {
		frame := readPeerFrame(t, peer)
		if frame.Flag == FrameFlagStreamOpen {
			open = frame
			break
		}
		if frame.Flag != FrameFlagPingResponse {
			t.Fatalf("frame %d = %#v, want ping response or stream open", index, frame)
		}
	}
	if open.Flag != FrameFlagStreamOpen {
		t.Fatalf("open control was starved by pings")
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	if got := <-result; got.err != nil || got.stream.id != open.StreamID {
		t.Fatalf("OpenStream() = (%#v, %v)", got.stream, got.err)
	}
}

func TestLegacyMuxSupportsDefaultPendingOpenCapacity(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	results := make(chan struct {
		stream *LegacyStream
		err    error
	}, defaultLegacyMuxMaxStreams)
	for index := 0; index < defaultLegacyMuxMaxStreams; index++ {
		go func() {
			stream, err := mux.OpenStream(context.Background())
			results <- struct {
				stream *LegacyStream
				err    error
			}{stream: stream, err: err}
		}()
	}
	for index := 0; index < defaultLegacyMuxMaxStreams; index++ {
		frame := readPeerFrame(t, peer)
		if frame.Flag != FrameFlagStreamOpen {
			t.Fatalf("frame %d = %#v, want stream open", index, frame)
		}
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: frame.StreamID})
	}
	seen := make(map[int32]struct{}, defaultLegacyMuxMaxStreams)
	for index := 0; index < defaultLegacyMuxMaxStreams; index++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("OpenStream() error = %v", result.err)
		}
		if _, duplicate := seen[result.stream.id]; duplicate {
			t.Fatalf("duplicate stream id %d", result.stream.id)
		}
		seen[result.stream.id] = struct{}{}
	}
	assertLegacyMuxQueueAccounting(t, mux)
}

func TestLegacyMuxOpenRejectsAndPeerOpenIsBoundedlyRejected(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	result := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(context.Background())
		result <- err
	}()
	open := readPeerFrame(t, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamRejected, StreamID: open.StreamID})
	if err := <-result; !errors.Is(err, ErrLegacyStreamRejected) {
		t.Fatalf("OpenStream() error = %v, want rejection", err)
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamOpen, StreamID: 77})
	reject := readPeerFrame(t, peer)
	if reject.Flag != FrameFlagStreamRejected || reject.StreamID != 77 {
		t.Fatalf("incoming open rejection = %#v", reject)
	}
}

func TestLegacyMuxRejectedOpenReleasesReservationWithoutTombstone(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{MaxStreams: 1, MaxTombstones: 1})
	acknowledgeInitialPing(t, peer)
	for attempt := 0; attempt < 3; attempt++ {
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(context.Background())
			result <- err
		}()
		open := readPeerFrame(t, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamRejected, StreamID: open.StreamID})
		if err := <-result; !errors.Is(err, ErrLegacyStreamRejected) {
			t.Fatalf("attempt %d OpenStream() error = %v", attempt, err)
		}
		mux.mu.Lock()
		streams, tombstones, reservations := len(mux.streams), len(mux.tombstones), mux.tombstoneReservations
		mux.mu.Unlock()
		if streams != 0 || tombstones != 0 || reservations != 0 {
			t.Fatalf("attempt %d retained streams=%d tombstones=%d reservations=%d", attempt, streams, tombstones, reservations)
		}
	}
}

func TestLegacyMuxUnknownCloseIsIgnored(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: 991})
	select {
	case <-mux.Done():
		t.Fatal("unknown close stopped the mux")
	default:
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("still-open")})
	buffer := make([]byte, len("still-open"))
	if n, err := stream.Read(buffer); err != nil || string(buffer[:n]) != "still-open" {
		t.Fatalf("unrelated stream Read() = (%d, %v, %q)", n, err, buffer[:n])
	}
	mux.mu.Lock()
	_, tombstoned := mux.tombstones[991]
	mux.mu.Unlock()
	if tombstoned {
		t.Fatal("unknown close allocated a tombstone")
	}
}

func TestLegacyMuxExpiredTombstoneReleasesCapacityAndDuplicateCloseIsIgnored(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{MaxStreams: 1, MaxTombstones: 1})
	acknowledgeInitialPing(t, peer)
	ctx, cancel := context.WithCancel(context.Background())
	canceled := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(ctx)
		canceled <- err
	}()
	open := readPeerFrame(t, peer)
	cancel()
	if err := <-canceled; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled OpenStream() error = %v", err)
	}
	waitForMuxState(t, mux, func() bool {
		tomb := mux.tombstones[open.StreamID]
		return tomb != nil && !tomb.openWriteInFlight
	})
	mux.mu.Lock()
	mux.tombstones[open.StreamID].expiresAt = time.Now().Add(-time.Second)
	mux.purgeTombstonesLocked(time.Now())
	_, stillPresent := mux.tombstones[open.StreamID]
	mux.mu.Unlock()
	if stillPresent {
		t.Fatal("expired tombstone retained capacity")
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: open.StreamID})
	select {
	case <-mux.Done():
		t.Fatal("duplicate close after tombstone expiry stopped the mux")
	default:
	}

	result := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(context.Background())
		result <- err
	}()
	next := readPeerFrame(t, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamRejected, StreamID: next.StreamID})
	if err := <-result; !errors.Is(err, ErrLegacyStreamRejected) {
		t.Fatalf("OpenStream() after expiry error = %v", err)
	}
}

func TestLegacyMuxSupportsDefaultWindowDescriptorCapacity(t *testing.T) {
	mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	mux.mu.Lock()
	for index := 1; index <= mux.cfg.MaxStreams; index++ {
		stream := newLegacyStream(mux, int32(index))
		stream.state = legacyStreamOpen
		stream.pendingConsumed = 1
		mux.streams[stream.id] = stream
		mux.tombstoneReservations++
		mux.ensureWindowDescriptorLocked(stream)
	}
	windowCount := mux.windowCount
	mux.mu.Unlock()
	if windowCount != defaultLegacyMuxMaxStreams {
		t.Fatalf("window descriptor reservations = %d, want %d", windowCount, defaultLegacyMuxMaxStreams)
	}
	assertLegacyMuxQueueAccounting(t, mux)
}

func TestLegacyMuxOpenWaitsForControlCapacityAndHonorsCancel(t *testing.T) {
	mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	mux.mu.Lock()
	// Represent peer-originated required reject work already holding every
	// open-control slot. The writer remains blocked on its initial ping.
	mux.openCount = mux.cfg.MaxStreams + 8
	mux.totalCount = mux.pingCount + mux.openCount
	mux.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := mux.OpenStream(ctx)
		result <- err
	}()
	waitForMuxState(t, mux, func() bool {
		for _, stream := range mux.streams {
			return stream.open != nil && stream.open.state == legacyOpenWaiting
		}
		return false
	})
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenStream() error = %v, want context cancellation", err)
	}
	mux.mu.Lock()
	streams, reservations, tombstones := len(mux.streams), mux.tombstoneReservations, len(mux.tombstones)
	mux.mu.Unlock()
	if streams != 0 || reservations != 0 || tombstones != 0 {
		t.Fatalf("canceled unsent open streams=%d reservations=%d tombstones=%d", streams, reservations, tombstones)
	}
}

func TestLegacyMuxCloseStopsWorkersExactlyOnce(t *testing.T) {
	mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	closed := make(chan error, 1)
	go func() { closed <- mux.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() blocked waiting for mux workers")
	}
	if err := mux.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	select {
	case <-mux.Done():
	default:
		t.Fatal("Done() was not closed")
	}
}

func TestLegacyMuxShutdownClearsQueuedAndInflightState(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	if n, err := stream.Write(make([]byte, legacyProtocolMaxContentBytes*2)); n != legacyProtocolMaxContentBytes*2 || err != nil {
		t.Fatalf("Write() = (%d, %v)", n, err)
	}
	// Do not read data from the peer: the first copied frame is in flight and
	// the second remains in the stream queue when shutdown begins.
	waitForMuxState(t, mux, func() bool { return mux.dataCount == 2 && len(stream.dataQueue) == 1 })
	if err := mux.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertLegacyMuxShutdownCleared(t, mux, stream)
}

func TestLegacyMuxQueueBlockedWriteResumesAndCloseInterrupts(t *testing.T) {
	cfg := LegacyMuxConfig{MaxStreams: 1, MaxQueuedFramesTotal: 27, MaxControlFrames: 26}
	mux, peer := newLegacyMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)

	payload := make([]byte, legacyProtocolMaxContentBytes*2)
	writeDone := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := stream.Write(payload)
		writeDone <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()

	select {
	case <-writeDone:
		t.Fatal("Write() completed while the one-frame data queue was full")
	case <-time.After(30 * time.Millisecond):
	}
	first := readPeerFrame(t, peer)
	if first.Flag != FrameFlagDataContinue {
		t.Fatalf("first frame = %#v", first)
	}
	result := <-writeDone
	if result.n != len(payload) || result.err != nil {
		t.Fatalf("Write() after capacity release = (%d, %v)", result.n, result.err)
	}
	second := readPeerFrame(t, peer)
	if second.Flag != FrameFlagDataFinal {
		t.Fatalf("second frame = %#v", second)
	}

	blocked := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := stream.Write(payload)
		blocked <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	select {
	case <-blocked:
		t.Fatal("second Write() completed before Close")
	case <-time.After(30 * time.Millisecond):
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	result = <-blocked
	if result.err == nil || result.n > legacyProtocolMaxContentBytes {
		t.Fatalf("interrupted Write() = (%d, %v)", result.n, result.err)
	}
	_ = readPeerFrame(t, peer)
	closeFrame := readPeerFrame(t, peer)
	if closeFrame.Flag != FrameFlagStreamClose {
		t.Fatalf("close frame = %#v", closeFrame)
	}
}
