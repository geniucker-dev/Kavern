package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestLegacyMuxConcurrentStreamMatrixAndLocalLimit(t *testing.T) {
	for _, count := range []int{1, 2, 8, 32, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
			peer := newRobustnessPeer(t, remote, true, true)
			streams := make([]*LegacyStream, count)
			ctx, cancel := context.WithTimeout(context.Background(), robustnessWait)
			defer cancel()
			errs := make(chan error, count)
			start, done := make(chan struct{}), make(chan struct{})
			var workers sync.WaitGroup
			t.Cleanup(func() {
				_ = mux.Close()
				joined := make(chan struct{})
				go func() { workers.Wait(); close(joined) }()
				awaitRobustness(t, joined)
			})
			for i := range streams {
				workers.Add(1)
				go func(i int) {
					defer workers.Done()
					<-start
					var err error
					streams[i], err = mux.OpenStream(ctx)
					errs <- err
				}(i)
			}
			close(start)
			go func() { workers.Wait(); close(done) }()
			awaitRobustness(t, done)
			for range streams {
				if err := <-errs; err != nil {
					t.Fatal("concurrent open:", err)
				}
			}
			seen := make(map[int32]bool)
			for _, stream := range streams {
				if stream.id <= 0 || seen[stream.id] {
					t.Fatal("invalid or duplicate stream ID")
				}
				seen[stream.id] = true
			}
			waitForMuxState(t, mux, func() bool { return mux.openCount == 0 })
			if count == 64 {
				mux.mu.Lock()
				next := mux.nextID
				mux.mu.Unlock()
				_, err := mux.OpenStream(ctx)
				if !errors.Is(err, ErrLegacyStreamLimit) {
					t.Fatal("65th stream was not locally rejected by MaxStreams")
				}
				mux.mu.Lock()
				unchanged := mux.nextID == next && mux.openCount == 0 && len(mux.openQueue) == 0 && len(mux.streams) == 64
				mux.mu.Unlock()
				if !unchanged {
					t.Fatal("local limit rejection allocated an ID or queued 0x06")
				}
			}
			// Every original stream remains usable after the local limit failure.
			done = make(chan struct{})
			for i, stream := range streams {
				workers.Add(1)
				go func(i int, stream *LegacyStream) {
					defer workers.Done()
					want := deterministicPayload(8192+i, i)
					n, err := stream.Write(want)
					if err == nil && n != len(want) {
						err = io.ErrShortWrite
					}
					got := make([]byte, len(want))
					if err == nil {
						_, err = io.ReadFull(stream, got)
					}
					if err == nil && !bytes.Equal(got, want) {
						err = errors.New("stream cross-talk or corrupted bytes")
					}
					errs <- err
				}(i, stream)
			}
			go func() { workers.Wait(); close(done) }()
			awaitRobustness(t, done)
			for range streams {
				if err := <-errs; err != nil {
					t.Fatal("concurrent transfer:", err)
				}
			}
			peer.mu.Lock()
			opens := 0
			for _, f := range peer.frames {
				if f.Flag == FrameFlagStreamOpen {
					opens++
				}
			}
			peer.mu.Unlock()
			if opens != count {
				t.Fatalf("wire opens=%d, want %d; local rejection must not emit 0x06", opens, count)
			}
			for _, stream := range streams {
				_ = stream.Close()
			}
			waitForMuxState(t, mux, func() bool {
				return len(mux.streams) == 0 && mux.tombstoneReservations == 0 && mux.dataCount == 0 && mux.windowCount == 0 && mux.bufferedBytes == 0
			})
			assertLegacyMuxQueueAccounting(t, mux)
			mux.mu.Lock()
			for _, stream := range streams {
				if stream.recvBlocks != nil || stream.dataQueue != nil {
					mux.mu.Unlock()
					t.Fatal("closed stream retained payload references")
				}
			}
			mux.mu.Unlock()
		})
	}
}

func TestLegacyStreamFlowExactInitialWindowThrough262144(t *testing.T) {
	mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
	peer := newRobustnessPeer(t, remote, false, false)
	stream := openRobustnessStream(t, mux)
	want := deterministicPayload(262144, 7)
	result := make(chan struct {
		n   int
		err error
	}, 1)
	runRobustnessWorker(t, mux, func() {
		n, err := stream.Write(want)
		result <- struct {
			n   int
			err error
		}{n, err}
	})
	peer.wait(t, func(frames []Frame) bool { return len(dataFrames(frames, stream.id)) == 30 })
	waitForMuxState(t, mux, func() bool { return stream.outstanding == 122550 && mux.dataCount == 0 })
	mux.mu.Lock()
	if stream.peerMax != 122550 || len(stream.dataQueue) != 0 || stream.outstanding+4085 <= uint64(stream.peerMax) {
		mux.mu.Unlock()
		t.Fatal("next segment was not blocked by the initial allowance")
	}
	mux.mu.Unlock()
	select {
	case <-result:
		t.Fatal("Write completed without consumed credit")
	default:
	}
	// The first thirty received frames have no automatic credit. From this
	// point each additional frame is credited exactly once by the Go peer.
	peer.mu.Lock()
	peer.credit = true
	peer.mu.Unlock()
	peer.send(t, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(122550, 122550)})
	select {
	case got := <-result:
		if got.n != len(want) || got.err != nil {
			t.Fatal("flow-controlled write did not resume completely")
		}
	case <-time.After(robustnessWait):
		t.Fatal("flow-controlled write remained blocked")
	}
	frames := peer.wait(t, func(frames []Frame) bool { return len(dataFrames(frames, stream.id)) == (len(want)+4084)/4085 })
	assertDataGroup(t, dataFrames(frames, stream.id), want)
	waitForMuxState(t, mux, func() bool { return stream.outstanding == 0 && mux.dataCount == 0 })
	mux.mu.Lock()
	clean := stream.peerMax == 122550 && len(stream.dataQueue) == 0 && stream.state == legacyStreamOpen
	mux.mu.Unlock()
	if !clean {
		t.Fatal("flow recovery leaked credit, queue slots, or stream state")
	}
	peer.mu.Lock()
	for _, f := range peer.frames {
		if f.Flag == FrameFlagWindow {
			peer.mu.Unlock()
			t.Fatal("receiving a window update emitted an unsolicited window response")
		}
	}
	peer.mu.Unlock()
	_ = stream.Close()
}

func TestLegacyStreamFlowBlockedStreamDoesNotBlockOthers(t *testing.T) {
	mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
	peer := newRobustnessPeer(t, remote, true, false)
	blocked := openRobustnessStream(t, mux)
	other := openRobustnessStream(t, mux)
	peer.mu.Lock()
	peer.held[blocked.id] = true
	peer.mu.Unlock()
	result := make(chan struct {
		n   int
		err error
	}, 1)
	runRobustnessWorker(t, mux, func() {
		n, err := blocked.Write(deterministicPayload(262144, 1))
		result <- struct {
			n   int
			err error
		}{n, err}
	})
	waitForMuxState(t, mux, func() bool { return blocked.outstanding == 122550 })
	want := deterministicPayload(19, 2)
	if n, err := other.Write(want); n != len(want) || err != nil {
		t.Fatal("unrelated stream did not progress")
	}
	frames := peer.wait(t, func(frames []Frame) bool { return len(dataFrames(frames, other.id)) == 1 })
	assertDataGroup(t, dataFrames(frames, other.id), want)
	_ = blocked.Close()
	select {
	case got := <-result:
		if got.n != 122550 || !errors.Is(got.err, ErrLegacyStreamClosed) {
			t.Fatal("close did not interrupt credit-blocked write")
		}
	case <-time.After(robustnessWait):
		t.Fatal("close did not join blocked writer")
	}
	if _, err := other.Write(want); err != nil {
		t.Fatal("one stream close damaged another")
	}
	_ = other.Close()
}

func TestLegacyStreamQueuedLargeWriteOwnsSourceBuffer(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(legacyPeerMaxWindow, 0)})
	waitForMuxState(t, mux, func() bool { return stream.peerMax == legacyPeerMaxWindow })
	want := deterministicPayload(262144, 42)
	source := append([]byte(nil), want...)
	// No peer reads occur until the complete group has been admitted and the
	// caller's buffer mutated. The raw writer is blocked on its first frame.
	if n, err := stream.Write(source); n != len(source) || err != nil {
		t.Fatal("large group was not admitted")
	}
	for i := range source {
		source[i] ^= 0xff
	}
	frames := make([]Frame, (len(want)+4084)/4085)
	for i := range frames {
		frames[i] = readPeerFrame(t, peer)
	}
	assertDataGroup(t, frames, want)
}
