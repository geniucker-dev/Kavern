package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestLegacyStreamReceiveReassemblyMatrix(t *testing.T) {
	for _, size := range []int{0, 1, 5, 19, 257, 4084, 4085, 4086, 8192, 65536, 122549, 122550, 122551, 131072, 262144} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
			peer := newRobustnessPeer(t, remote, false, false)
			stream := openRobustnessStream(t, mux)
			want := deterministicPayload(size, size)
			var got []byte
			for offset := 0; offset < len(want); {
				end := offset + 8192
				if end > len(want) {
					end = len(want)
				}
				var batch bytes.Buffer
				for pos := offset; pos < end; {
					stop := pos + 4085
					if stop > end {
						stop = end
					}
					flag := FrameFlagDataContinue
					if stop == len(want) {
						flag = FrameFlagDataFinal
					}
					if err := WriteFrame(&batch, Frame{Flag: flag, StreamID: stream.id, Content: want[pos:stop]}); err != nil {
						t.Fatal(err)
					}
					pos = stop
				}
				peer.sendCommand(t, peerWrite{raw: batch.Bytes()})
				waitForMuxState(t, mux, func() bool { return stream.recvBuffered == uint64(end-offset) })
				remaining := end - offset
				for step := 0; remaining > 0; step++ {
					n := []int{1, 5, 4090, 257}[step%4]
					if n > remaining {
						n = remaining
					}
					buffer := make([]byte, n)
					read, err := stream.Read(buffer)
					if err != nil || read != n {
						t.Fatal("partial application read did not reconstruct buffered stream")
					}
					got = append(got, buffer...)
					remaining -= read
					assertReceiveOwnershipBound(t, mux, stream)
				}
				offset = end
			}
			if !bytes.Equal(got, want) {
				t.Fatal("partial reads lost or duplicated bytes")
			}
			waitForMuxState(t, mux, func() bool {
				return mux.windowCount == 0 && stream.pendingConsumed == 0 && stream.inFlightConsumed == 0
			})
			frames := peer.wait(t, func(frames []Frame) bool {
				var credit uint64
				for _, f := range frames {
					if f.Flag == FrameFlagWindow && f.StreamID == stream.id {
						credit += f.WindowState & legacyWindowDeltaMask
					}
				}
				return credit >= uint64(size)
			})
			var credit uint64
			for _, f := range frames {
				if f.Flag == FrameFlagWindow && f.StreamID == stream.id {
					if f.WindowState>>32 != uint64(defaultLegacyMuxWindow) || f.WindowState&(1<<31) != 0 {
						t.Fatal("generated window has invalid max or reserved/wait bits")
					}
					credit += f.WindowState & legacyWindowDeltaMask
				}
			}
			if credit != uint64(size) {
				t.Fatal("application consumed credit was lost or duplicated")
			}
			assertStreamReceiveReleased(t, mux, stream)
			_ = stream.Close()
		})
	}
}

func TestLegacyStreamTinyWireFramesRespectReceiveBlockLimit(t *testing.T) {
	mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
	peer := newRobustnessPeer(t, remote, false, false)
	stream := openRobustnessStream(t, mux)
	var wire bytes.Buffer
	want := deterministicPayload(3000, 99)
	for _, value := range want {
		if err := WriteFrame(&wire, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte{value}}); err != nil {
			t.Fatal(err)
		}
	}
	peer.sendCommand(t, peerWrite{raw: wire.Bytes()})
	waitForMuxState(t, mux, func() bool { return stream.recvBuffered == 3000 })
	assertReceiveBlockCount(t, mux, stream, 1)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("tiny wire frames corrupted the byte stream")
	}
	assertReceiveOwnershipBound(t, mux, stream)
}

func TestLegacyStreamSequentialHighWaterReceiveLimitReleasesReferences(t *testing.T) {
	mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
	peer := newRobustnessPeer(t, remote, false, false)
	for iteration := 0; iteration < 16; iteration++ {
		stream := openRobustnessStream(t, mux)
		for segment := 0; segment < 31; segment++ {
			peer.send(t, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: deterministicPayload(4085, segment)})
		}
		waitForMuxState(t, mux, func() bool { return stream.recvBuffered == uint64(mux.cfg.HardReceiveBufferBytes) })
		assertReceiveOwnershipBound(t, mux, stream)
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		waitForMuxState(t, mux, func() bool {
			return len(mux.streams) == 0 && mux.dataCount == 0 && mux.bufferedBytes == 0 && mux.tombstoneReservations == 0
		})
		assertStreamReceiveReleased(t, mux, stream)
		mux.mu.Lock()
		retained := stream.dataQueue != nil
		mux.mu.Unlock()
		if retained {
			t.Fatal("high-water stream retained outbound storage")
		}
	}
	_ = mux.Close()
	assertLegacyMuxShutdownCleared(t, mux)
}

func assertReceiveOwnershipBound(t *testing.T, mux *LegacyMux, stream *LegacyStream) {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if stream.recvBuffered == 0 {
		if stream.recvBlocks != nil {
			t.Fatal("empty receive queue retained backing storage")
		}
		return
	}
	limit := (stream.recvBuffered+4084)/4085 + 1
	if uint64(len(stream.recvBlocks)) > limit {
		t.Fatal("tiny frames grew receive-block ownership beyond its bound")
	}
	var buffered uint64
	for _, block := range stream.recvBlocks {
		if len(block.data) != 4085 || block.readOffset < 0 || block.writeOffset < block.readOffset || block.writeOffset > len(block.data) {
			t.Fatal("invalid receive block")
		}
		buffered += uint64(block.writeOffset - block.readOffset)
	}
	if buffered != stream.recvBuffered {
		t.Fatal("receive byte counter disagrees with owned blocks")
	}
}

func TestLegacyStreamRemoteCloseThenLocalCloseLifecycle(t *testing.T) {
	t.Run("cleanup is not duplicated before transmission", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
		if err := stream.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		readPeerStreamClose(t, peer, stream.id)
		waitForMuxState(t, mux, func() bool {
			return len(mux.streams) == 0 && mux.tombstoneReservations == 0 && len(mux.tombstones) == 1
		})
		if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrLegacyStreamClosed) {
			t.Fatalf("Read after local Close error = %v", err)
		}
	})

	t.Run("sent cleanup then local close discards unread data", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{MaxStreams: 1})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("unread")})
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
		readPeerStreamClose(t, peer, stream.id)
		if err := stream.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		waitForMuxState(t, mux, func() bool {
			return len(mux.streams) == 0 && mux.tombstoneReservations == 0 && len(mux.tombstones) == 1
		})
		assertStreamReceiveReleased(t, mux, stream)
		mux.mu.Lock()
		queuedCloseFrames := mux.dataCount
		closeQueue := len(mux.closeReady)
		mux.mu.Unlock()
		if queuedCloseFrames != 0 || closeQueue != 0 {
			t.Fatalf("local Close queued duplicate cleanup data=%d close_ready=%d", queuedCloseFrames, closeQueue)
		}
		if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrLegacyStreamClosed) {
			t.Fatalf("Read after explicit local Close error = %v", err)
		}

		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(context.Background())
			result <- err
		}()
		next := readPeerFrame(t, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamRejected, StreamID: next.StreamID})
		if err := <-result; !errors.Is(err, ErrLegacyStreamRejected) {
			t.Fatalf("OpenStream() after local close error = %v", err)
		}
	})

	t.Run("partial read then local close", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("partial")})
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
		buffer := make([]byte, 3)
		if n, err := stream.Read(buffer); n != 3 || err != nil || string(buffer) != "par" {
			t.Fatalf("partial Read() = (%d, %v, %q)", n, err, buffer)
		}
		readPeerStreamClose(t, peer, stream.id)
		if err := stream.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && mux.tombstoneReservations == 0 })
		assertStreamReceiveReleased(t, mux, stream)
	})

	t.Run("tombstoned remote EOF becomes explicitly locally closed", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
		readPeerStreamClose(t, peer, stream.id)
		waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && len(mux.tombstones) == 1 })
		if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("Read after remote close = %v, want EOF", err)
		}
		mux.mu.Lock()
		tomb := mux.tombstones[stream.id]
		reservations := mux.tombstoneReservations
		mux.mu.Unlock()
		if err := stream.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("second Close() error = %v", err)
		}
		if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrLegacyStreamClosed) {
			t.Fatalf("Read after explicit local Close error = %v", err)
		}
		assertNoPeerFrame(t, peer)
		mux.mu.Lock()
		if mux.tombstones[stream.id] != tomb || mux.tombstoneReservations != reservations {
			mux.mu.Unlock()
			t.Fatal("local Close changed tombstone or reservation accounting")
		}
		mux.mu.Unlock()
	})
}

func TestLegacyMuxTombstonesDoNotDuplicateSuccessfulClose(t *testing.T) {
	t.Run("local close tombstone ignores late data and acceptance", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		if err := stream.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		readPeerStreamClose(t, peer, stream.id)
		waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && len(mux.tombstones) == 1 })
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("late")})
		waitForMuxState(t, mux, func() bool { return mux.tombstones[stream.id].lateDataNoted })
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: stream.id})
		assertNoPeerFrame(t, peer)
		assertTombstoneCleanupSent(t, mux, stream.id)
	})

	t.Run("remote cleanup tombstone ignores late data", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
		readPeerStreamClose(t, peer, stream.id)
		waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && len(mux.tombstones) == 1 })
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataContinue, StreamID: stream.id, Content: []byte("late")})
		waitForMuxState(t, mux, func() bool { return mux.tombstones[stream.id].lateDataNoted })
		assertNoPeerFrame(t, peer)
		assertTombstoneCleanupSent(t, mux, stream.id)
	})

	t.Run("canceled sent open permits one late-accept cleanup", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := mux.OpenStream(ctx)
			result <- err
		}()
		open := readPeerFrame(t, peer)
		if open.Flag != FrameFlagStreamOpen {
			t.Fatalf("open frame = %#v", open)
		}
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("OpenStream() error = %v", err)
		}
		waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && len(mux.tombstones) == 1 })
		mux.mu.Lock()
		if mux.tombstones[open.StreamID].cleanupSent {
			mux.mu.Unlock()
			t.Fatal("canceled sent open pre-marked cleanup sent")
		}
		mux.mu.Unlock()
		writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
		readPeerStreamClose(t, peer, open.StreamID)
		writePeerFrame(t, peer, Frame{Flag: FrameFlagDataFinal, StreamID: open.StreamID, Content: []byte("late")})
		waitForMuxState(t, mux, func() bool { return mux.tombstones[open.StreamID].lateDataNoted })
		assertNoPeerFrame(t, peer)
		assertTombstoneCleanupSent(t, mux, open.StreamID)
	})
}

func TestLegacyStreamReceiveBlocksReleaseStorage(t *testing.T) {
	t.Run("three thousand one-byte frames share one block", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		want := make([]byte, 3000)
		for index := range want {
			want[index] = byte(index % 251)
			injectStreamData(t, mux, stream, want[index:index+1])
		}
		assertReceiveBlockCount(t, mux, stream, 1)
		got := make([]byte, len(want))
		if n, err := stream.Read(got); n != len(want) || err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Read() = (%d, %v, %d bytes), want exact one-byte frame order", n, err, len(got))
		}
		assertStreamReceiveReleased(t, mux, stream)
	})

	t.Run("reads span fixed blocks in byte order", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		want := make([]byte, legacyProtocolMaxContentBytes+5)
		for index := range want {
			want[index] = byte(index % 251)
		}
		// The second input frame starts in the partially filled first block and
		// spills into the next block.
		injectStreamData(t, mux, stream, want[:3])
		injectStreamData(t, mux, stream, want[3:3+legacyProtocolMaxContentBytes])
		injectStreamData(t, mux, stream, want[3+legacyProtocolMaxContentBytes:])
		assertReceiveBlockCount(t, mux, stream, 2)
		first := make([]byte, legacyProtocolMaxContentBytes-3)
		second := make([]byte, len(want)-len(first))
		if n, err := stream.Read(first); n != len(first) || err != nil {
			t.Fatalf("first Read() = (%d, %v)", n, err)
		}
		if n, err := stream.Read(second); n != len(second) || err != nil {
			t.Fatalf("second Read() = (%d, %v)", n, err)
		}
		if got := append(first, second...); !bytes.Equal(got, want) {
			t.Fatal("read data did not preserve byte-stream order across receive blocks")
		}
		assertStreamReceiveReleased(t, mux, stream)
	})

	t.Run("fixed receive window of one-byte frames has bounded block count", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		stream := openPeerStream(t, mux, peer)
		byteValue := []byte{0}
		for index := 0; index < int(defaultLegacyMuxWindow); index++ {
			byteValue[0] = byte(index)
			injectStreamData(t, mux, stream, byteValue)
		}
		assertReceiveBlockCount(t, mux, stream, 30)
		drainLegacyStream(t, stream, int(defaultLegacyMuxWindow))
		assertStreamReceiveReleased(t, mux, stream)
	})

	t.Run("repeated small-frame drains and streams retain no historical blocks", func(t *testing.T) {
		mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		first := openPeerStream(t, mux, peer)
		second := openPeerStream(t, mux, peer)
		for _, stream := range []*LegacyStream{first, second} {
			for cycle := 0; cycle < 3; cycle++ {
				for index := 0; index < 3000; index++ {
					injectStreamData(t, mux, stream, []byte{byte(index)})
				}
				assertReceiveBlockCount(t, mux, stream, 1)
				drainLegacyStream(t, stream, 3000)
				assertStreamReceiveReleased(t, mux, stream)
			}
		}
	})

	t.Run("local close, tombstoning, and shutdown release blocks", func(t *testing.T) {
		t.Run("local close tombstones without retained blocks", func(t *testing.T) {
			mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
			acknowledgeInitialPing(t, peer)
			stream := openPeerStream(t, mux, peer)
			injectStreamData(t, mux, stream, bytes.Repeat([]byte{'c'}, legacyProtocolMaxContentBytes+1))
			assertReceiveBlockCount(t, mux, stream, 2)
			if err := stream.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			readPeerStreamClose(t, peer, stream.id)
			waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && len(mux.tombstones) == 1 })
			assertStreamReceiveReleased(t, mux, stream)
		})

		t.Run("mux shutdown clears buffered blocks", func(t *testing.T) {
			mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
			acknowledgeInitialPing(t, peer)
			stream := openPeerStream(t, mux, peer)
			injectStreamData(t, mux, stream, bytes.Repeat([]byte{'s'}, legacyProtocolMaxContentBytes+1))
			assertReceiveBlockCount(t, mux, stream, 2)
			if err := mux.Close(); err != nil {
				t.Fatalf("mux.Close() error = %v", err)
			}
			assertLegacyMuxShutdownCleared(t, mux, stream)
		})
	})
}

func TestLegacyMuxDrainedOutboundDataQueueReleasesReferences(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	payload := bytes.Repeat([]byte{'q'}, legacyProtocolMaxContentBytes*2)
	if n, err := stream.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("Write() = (%d, %v)", n, err)
	}
	first := readPeerFrame(t, peer)
	second := readPeerFrame(t, peer)
	if first.Flag != FrameFlagDataContinue || second.Flag != FrameFlagDataFinal {
		t.Fatalf("frames = %#v, %#v", first, second)
	}
	waitForMuxState(t, mux, func() bool { return stream.dataQueue == nil && !stream.dataReady && mux.dataCount == 0 })
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if frame := readPeerFrame(t, peer); frame.Flag != FrameFlagStreamClose {
		t.Fatalf("close frame = %#v", frame)
	}
	waitForMuxState(t, mux, func() bool { return len(mux.streams) == 0 && len(mux.tombstones) == 1 })
	mux.mu.Lock()
	queue := stream.dataQueue
	mux.mu.Unlock()
	if queue != nil {
		t.Fatalf("tombstoned stream retained data queue len=%d", len(queue))
	}
}

func drainLegacyStream(t *testing.T, stream *LegacyStream, total int) {
	t.Helper()
	buffer := make([]byte, 8192)
	for total > 0 {
		if len(buffer) > total {
			buffer = buffer[:total]
		}
		n, err := stream.Read(buffer)
		if err != nil || n == 0 {
			t.Fatalf("Read() = (%d, %v)", n, err)
		}
		total -= n
	}
}

func assertStreamReceiveReleased(t *testing.T, mux *LegacyMux, stream *LegacyStream) {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if stream.recvBlocks != nil || stream.recvBuffered != 0 || mux.bufferedBytes != 0 {
		t.Fatalf("receive storage retained blocks=%d buffered=%d mux_buffered=%d", len(stream.recvBlocks), stream.recvBuffered, mux.bufferedBytes)
	}
}

func injectStreamData(t *testing.T, mux *LegacyMux, stream *LegacyStream, content []byte) {
	t.Helper()
	mux.mu.Lock()
	err := mux.handleDataLocked(Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: content})
	mux.mu.Unlock()
	if err != nil {
		t.Fatalf("handleDataLocked() error = %v", err)
	}
}

func assertReceiveBlockCount(t *testing.T, mux *LegacyMux, stream *LegacyStream, want int) {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if got := len(stream.recvBlocks); got != want {
		t.Fatalf("receive block count = %d, want %d", got, want)
	}
}

func assertTombstoneCleanupSent(t *testing.T, mux *LegacyMux, streamID int32) {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	tomb := mux.tombstones[streamID]
	if tomb == nil || !tomb.cleanupSent || tomb.cleanupPending || tomb.cleanupInFlight {
		t.Fatalf("tombstone cleanup state = %#v, want sent without pending cleanup", tomb)
	}
}

func readPeerStreamClose(t *testing.T, peer net.Conn, streamID int32) {
	t.Helper()
	for {
		frame := readPeerFrame(t, peer)
		if frame.Flag == FrameFlagStreamClose && frame.StreamID == streamID {
			return
		}
		if frame.Flag != FrameFlagWindow || frame.StreamID != streamID {
			t.Fatalf("frame before cleanup close = %#v", frame)
		}
	}
}
