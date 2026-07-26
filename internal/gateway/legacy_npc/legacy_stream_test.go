package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestLegacyStreamWindowUpdatesAreLosslessWhileInFlight(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)

	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("abc")})
	buffer := make([]byte, 3)
	if n, err := stream.Read(buffer); err != nil || n != 3 {
		t.Fatalf("first Read() = (%d, %v)", n, err)
	}
	waitForMuxState(t, mux, func() bool { return stream.windowInFlight })
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("def")})
	if n, err := stream.Read(buffer); err != nil || n != 3 {
		t.Fatalf("second Read() = (%d, %v)", n, err)
	}

	first := readPeerFrame(t, peer)
	if first.Flag != FrameFlagWindow || first.WindowState&legacyWindowDeltaMask != 3 {
		t.Fatalf("first window = %#v", first)
	}
	second := readPeerFrame(t, peer)
	if second.Flag != FrameFlagWindow || second.WindowState&legacyWindowDeltaMask != 3 {
		t.Fatalf("second window = %#v", second)
	}
	waitForMuxState(t, mux, func() bool {
		return !stream.windowQueued && !stream.windowInFlight && stream.pendingConsumed == 0 && stream.inFlightConsumed == 0
	})

	mux.mu.Lock()
	queued := stream.windowQueued || stream.windowInFlight
	pending := stream.pendingConsumed
	inFlight := stream.inFlightConsumed
	mux.mu.Unlock()
	if queued || pending != 0 || inFlight != 0 {
		t.Fatalf("window state queued=%t pending=%d in_flight=%d", queued, pending, inFlight)
	}
}

func TestLegacyMuxShutdownReleasesInflightWindowDescriptor(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("window")})
	if n, err := stream.Read(make([]byte, len("window"))); n != len("window") || err != nil {
		t.Fatalf("Read() = (%d, %v)", n, err)
	}
	waitForMuxState(t, mux, func() bool { return stream.windowInFlight && mux.windowCount == 1 })
	if err := mux.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertLegacyMuxShutdownCleared(t, mux, stream)
}

func TestLegacyStreamFlowControlRecovery(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	payload := bytes.Repeat([]byte{'x'}, int(defaultLegacyMuxWindow)+1)
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

	for index := 0; index < 30; index++ {
		frame := readPeerFrame(t, peer)
		if frame.Flag != FrameFlagDataContinue && frame.Flag != FrameFlagDataFinal {
			t.Fatalf("frame %d = %#v", index, frame)
		}
	}
	select {
	case got := <-result:
		t.Fatalf("Write() completed before window update: %+v", got)
	case <-time.After(30 * time.Millisecond):
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(defaultLegacyMuxWindow, uint64(defaultLegacyMuxWindow))})
	got := <-result
	if got.n != len(payload) || got.err != nil {
		t.Fatalf("Write() after update = (%d, %v)", got.n, got.err)
	}
	last := readPeerFrame(t, peer)
	if last.Flag != FrameFlagDataFinal || len(last.Content) != 1 {
		t.Fatalf("last frame = %#v", last)
	}
}

func TestLegacyMuxRejectsImpossibleWindowState(t *testing.T) {
	states := []uint64{
		packWindowState(0, 0),
		packWindowState(legacyPeerMaxWindow+1, 0),
		uint64(defaultLegacyMuxWindow)<<32 | uint64(1)<<31,
		packWindowState(defaultLegacyMuxWindow, 1),
	}
	for _, state := range states {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: state})
		waitMuxDone(t, mux)
	}
}

func TestLegacyStreamLargePayloadRecoversWithWindowUpdates(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	payload := bytes.Repeat([]byte{'z'}, 262144)
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

	received := 0
	for received < len(payload) {
		frame := readPeerFrame(t, peer)
		if frame.Flag != FrameFlagDataContinue && frame.Flag != FrameFlagDataFinal {
			t.Fatalf("payload frame = %#v", frame)
		}
		received += len(frame.Content)
		writePeerFrame(t, peer, Frame{
			Flag:        FrameFlagWindow,
			StreamID:    stream.id,
			WindowState: packWindowState(defaultLegacyMuxWindow, uint64(len(frame.Content))),
		})
	}
	got := <-result
	if got.n != len(payload) || got.err != nil {
		t.Fatalf("Write() = (%d, %v)", got.n, got.err)
	}
	assertLegacyMuxQueueAccounting(t, mux)
}

func TestLegacyStreamCloseInterruptsFlowBlockedWrite(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(1, 0)})
	result := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("xx"))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("Write() returned before Close: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-result; !errors.Is(err, ErrLegacyStreamClosed) {
		t.Fatalf("flow-blocked Write() error = %v", err)
	}
	if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagStreamClose {
		t.Fatalf("close frame = %#v", frame)
	}
}

func TestLegacyStreamLocalCloseReleasesReceiveBudget(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("buffered")})
	waitForMuxState(t, mux, func() bool { return mux.bufferedBytes == uint64(len("buffered")) })
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	buffered := mux.bufferedBytes
	mux.mu.Unlock()
	if buffered != 0 {
		t.Fatalf("global buffered bytes = %d, want 0", buffered)
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrLegacyStreamClosed) {
		t.Fatalf("Read after local Close error = %v", err)
	}
}

func TestLegacyMuxReceiveLimitsAreBoundedWithoutSoftWindowFailure(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	content := bytes.Repeat([]byte{'r'}, legacyProtocolMaxContentBytes)
	for index := 0; index < 31; index++ {
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: content})
	}
	select {
	case <-mux.Done():
		t.Fatal("mux stopped at the soft receive window or its permitted overshoot")
	default:
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("x")})
	waitMuxDone(t, mux)
}

func TestLegacyMuxAggregateReceiveLimit(t *testing.T) {
	cfg := LegacyMuxConfig{MaxBufferedBytesTotal: uint64(defaultLegacyMuxWindow + legacyProtocolMaxContentBytes)}
	mux, peer := newLegacyMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	first := openPeerStream(t, mux, peer)
	second := openPeerStream(t, mux, peer)
	content := bytes.Repeat([]byte{'g'}, legacyProtocolMaxContentBytes)
	for index := 0; index < 30; index++ {
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: first.id, Content: content})
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: second.id, Content: content})
	writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: second.id, Content: []byte("x")})
	waitMuxDone(t, mux)
}

func TestLegacyStreamCloseIsOrderedAfterAcceptedData(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)

	if n, err := stream.Write([]byte("queued")); n != len("queued") || err != nil {
		t.Fatalf("Write() = (%d, %v)", n, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	data := readPeerFrame(t, peer)
	closeFrame := readPeerFrame(t, peer)
	if data.Flag != FrameFlagDataFinal || string(data.Content) != "queued" {
		t.Fatalf("data frame = %#v", data)
	}
	if closeFrame.Flag != FrameFlagStreamClose || closeFrame.StreamID != stream.id {
		t.Fatalf("close frame = %#v", closeFrame)
	}
	assertLegacyMuxQueueAccounting(t, mux)
}

func TestLegacyStreamConcurrentWritesStayGrouped(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)

	first := append(bytes.Repeat([]byte{'a'}, legacyProtocolMaxContentBytes), 'a')
	second := append(bytes.Repeat([]byte{'b'}, legacyProtocolMaxContentBytes), 'b')
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, payload := range [][]byte{first, second} {
		payload := payload
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := stream.Write(payload)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	frames := []Frame{readPeerFrame(t, peer), readPeerFrame(t, peer), readPeerFrame(t, peer), readPeerFrame(t, peer)}
	for index := 0; index < len(frames); index += 2 {
		if frames[index].Flag != FrameFlagDataContinue || frames[index+1].Flag != FrameFlagDataFinal {
			t.Fatalf("write group %d frames = %#v, %#v", index/2, frames[index], frames[index+1])
		}
		if frames[index].Content[0] != frames[index+1].Content[0] || len(frames[index+1].Content) != 1 {
			t.Fatalf("write group %d interleaved: %#v, %#v", index/2, frames[index], frames[index+1])
		}
	}
}

func TestLegacyMuxOpenCancellationBeforeAndAfterWireWrite(t *testing.T) {
	t.Run("queued unsent releases without tombstone", func(t *testing.T) {
		cfg := LegacyMuxConfig{MaxStreams: 2, MaxQueuedFramesTotal: 29, MaxControlFrames: 28}
		mux, peer := newLegacyMuxPipe(t, cfg)
		// Leave the initial server ping unread after the writer has claimed it.
		// That deterministically blocks raw writes before the local 0x06 can run.
		waitForMuxState(t, mux, func() bool { return mux.pingCount == 1 && len(mux.pingQueue) == 0 })
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(ctx)
			result <- err
		}()
		waitForMuxState(t, mux, func() bool { return len(mux.openQueue) == 1 })
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenStream() error = %v", err)
		}
		mux.mu.Lock()
		streams, tombstones, reservations := len(mux.streams), len(mux.tombstones), mux.tombstoneReservations
		mux.mu.Unlock()
		if streams != 0 || tombstones != 0 || reservations != 0 {
			t.Fatalf("unsent cancellation streams=%d tombstones=%d reservations=%d", streams, tombstones, reservations)
		}
		_ = peer.Close()
	})

	t.Run("written open creates tombstone and cleans late accept", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(ctx)
			result <- err
		}()
		open := readPeerFrame(t, peer)
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenStream() error = %v", err)
		}
		mux.mu.Lock()
		tombstones := len(mux.tombstones)
		mux.mu.Unlock()
		if tombstones != 1 {
			t.Fatalf("tombstones = %d, want 1", tombstones)
		}
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
		if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagStreamClose || frame.StreamID != open.StreamID {
			t.Fatalf("late accept cleanup = %#v", frame)
		}
	})

	t.Run("tombstoned late data is discarded and cleaned", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(ctx)
			result <- err
		}()
		open := readPeerFrame(t, peer)
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenStream() error = %v", err)
		}
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: open.StreamID, Content: []byte("late")})
		if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagStreamClose || frame.StreamID != open.StreamID {
			t.Fatalf("late data cleanup = %#v", frame)
		}
		mux.mu.Lock()
		buffered := mux.bufferedBytes
		mux.mu.Unlock()
		if buffered != 0 {
			t.Fatalf("late tombstone data consumed %d receive bytes", buffered)
		}
	})

	t.Run("tombstone capacity is enforced", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{MaxStreams: 1, MaxTombstones: 1})
		acknowledgeInitialPing(t, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(ctx)
			result <- err
		}()
		_ = readPeerFrame(t, peer)
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenStream() error = %v", err)
		}
		if _, err := mux.OpenStream(context.Background()); !errors.Is(err, ErrLegacyTombstoneLimit) {
			t.Fatalf("OpenStream() error = %v, want tombstone limit", err)
		}
	})
}

func TestLegacyMuxResolvedOpenWinsCancellationWakeup(t *testing.T) {
	t.Run("accepted before cancellation", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan struct {
			stream *LegacyStream
			err    error
		}, 1)
		go func() {
			stream, err := mux.OpenStream(ctx)
			result <- struct {
				stream *LegacyStream
				err    error
			}{stream: stream, err: err}
		}()
		open := readPeerFrame(t, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
		waitForMuxState(t, mux, func() bool {
			stream := mux.streams[open.StreamID]
			return stream != nil && stream.state == legacyStreamOpen
		})
		cancel()
		got := <-result
		if got.err != nil || got.stream == nil {
			t.Fatalf("OpenStream() = (%#v, %v), want accepted stream", got.stream, got.err)
		}
		if err := got.stream.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagStreamClose {
			t.Fatalf("close frame = %#v", frame)
		}
	})

	t.Run("rejected before cancellation", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(ctx)
			result <- err
		}()
		open := readPeerFrame(t, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamRejected, StreamID: open.StreamID})
		waitForMuxState(t, mux, func() bool {
			return len(mux.streams) == 0 && mux.tombstoneReservations == 0
		})
		cancel()
		if err := <-result; !errors.Is(err, ErrLegacyStreamRejected) {
			t.Fatalf("OpenStream() error = %v, want rejection", err)
		}
		mux.mu.Lock()
		tombstones := len(mux.tombstones)
		mux.mu.Unlock()
		if tombstones != 0 {
			t.Fatalf("rejected open left %d tombstones", tombstones)
		}
	})

	t.Run("accepted then immediately remotely closed", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
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
		open := readPeerFrame(t, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: open.StreamID})
		got := <-result
		if got.err != nil || got.stream == nil {
			t.Fatalf("OpenStream() = (%#v, %v)", got.stream, got.err)
		}
		if _, err := got.stream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, ErrLegacyStreamClosed) {
			t.Fatalf("Read after immediate remote close error = %v", err)
		}
		if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagStreamClose || frame.StreamID != open.StreamID {
			t.Fatalf("remote close cleanup = %#v", frame)
		}
		waitForMuxState(t, mux, func() bool { return mux.tombstoneReservations == 0 && len(mux.streams) == 0 })
	})
}

func TestLegacyStreamCloseDoesNotReinstallStateAfterMuxShutdown(t *testing.T) {
	for attempt := 0; attempt < 25; attempt++ {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		stream.writeMu.Lock()
		closeResult := make(chan error, 1)
		go func() {
			closeResult <- stream.Close()
		}()
		waitForMuxState(t, mux, func() bool {
			return stream.state == legacyStreamLocalClose && stream.localClosed
		})
		if err := mux.Close(); err != nil {
			t.Fatalf("attempt %d mux.Close() error = %v", attempt, err)
		}
		stream.writeMu.Unlock()
		select {
		case err := <-closeResult:
			if err != nil {
				t.Fatalf("attempt %d stream.Close() error = %v", attempt, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("attempt %d stream.Close() did not return", attempt)
		}
		mux.mu.Lock()
		state := stream.state
		closePending := stream.closePending
		closeInFlight := stream.closeInFlight
		closeSent := stream.closeSent
		mux.mu.Unlock()
		if state != legacyStreamFullyClosed || closePending || closeInFlight || closeSent {
			t.Fatalf("attempt %d stream state=%d close=%t/%t/%t after shutdown", attempt, state, closePending, closeInFlight, closeSent)
		}
		assertLegacyMuxShutdownCleared(t, mux, stream)
	}
}

func waitForMuxState(t *testing.T, mux *LegacyMux, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mux.mu.Lock()
		ready := predicate()
		mux.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for mux state")
}
