package legacy_npc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type slicedTransport struct {
	net.Conn
	readSizes, writeSizes []int
	reads, writes         int
	active                atomic.Int32
	concurrent            atomic.Bool
}

func (c *slicedTransport) Read(p []byte) (int, error) {
	if len(c.readSizes) > 0 {
		n := c.readSizes[c.reads%len(c.readSizes)]
		c.reads++
		if n < len(p) {
			p = p[:n]
		}
	}
	return c.Conn.Read(p)
}

func (c *slicedTransport) Write(p []byte) (int, error) {
	if c.active.Add(1) != 1 {
		c.concurrent.Store(true)
	}
	defer c.active.Add(-1)
	if len(c.writeSizes) > 0 {
		n := c.writeSizes[c.writes%len(c.writeSizes)]
		c.writes++
		if n < len(p) {
			p = p[:n]
		}
	}
	return c.Conn.Write(p)
}

func TestLegacyMuxFragmentedCoalescedTransport(t *testing.T) {
	for _, tc := range []struct {
		name          string
		reads, writes []int
	}{
		{"one_byte", []int{1}, []int{1}},
		{"split_five_byte_header", []int{2, 3}, []int{2, 1, 3}},
		{"split_content_header_body", []int{5, 1, 1, 11, 3}, []int{5, 1, 11}},
		{"coalesced_frames_and_next_header", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, remote := net.Pipe()
			transport := &slicedTransport{Conn: server, readSizes: tc.reads, writeSizes: tc.writes}
			mux, err := NewLegacyMux(observeMuxProgress(transport), LegacyMuxConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mux.Close(); _ = remote.Close() })
			peer := newRobustnessPeer(t, remote, true, false)
			stream := openRobustnessStream(t, mux)
			want := deterministicPayload(8192, 1)
			if n, err := stream.Write(want); n != len(want) || err != nil {
				t.Fatal("outbound write failed")
			}
			frames := peer.wait(t, func(frames []Frame) bool { return len(dataFrames(frames, stream.id)) == 3 })
			assertDataGroup(t, dataFrames(frames, stream.id), want)
			var batch bytes.Buffer
			for _, f := range dataFrames(frames, stream.id) {
				if err := WriteFrame(&batch, f); err != nil {
					t.Fatal(err)
				}
			}
			// One raw write contains complete frames and body/next-header joins.
			peer.sendCommand(t, peerWrite{raw: batch.Bytes()})
			waitForMuxState(t, mux, func() bool { return stream.recvBuffered == uint64(len(want)) })
			got := make([]byte, len(want))
			if n, err := stream.Read(got[:5000]); n != 5000 || err != nil {
				t.Fatal("read did not span frame boundaries")
			}
			if _, err := io.ReadFull(stream, got[5000:]); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) || transport.concurrent.Load() {
				t.Fatal("transport corrupted data or allowed concurrent writes")
			}
			_ = stream.Close()
		})
	}
}

func assertDataGroup(t *testing.T, frames []Frame, want []byte) {
	t.Helper()
	count := (len(want) + legacyProtocolMaxContentBytes - 1) / legacyProtocolMaxContentBytes
	if len(frames) != count {
		t.Fatalf("data frames=%d want=%d", len(frames), count)
	}
	var got []byte
	for i, frame := range frames {
		flag := FrameFlagDataContinue
		length := legacyProtocolMaxContentBytes
		if i == len(frames)-1 {
			flag = FrameFlagDataFinal
			length = len(want) - i*legacyProtocolMaxContentBytes
		}
		if frame.Flag != flag || len(frame.Content) != length {
			t.Fatalf("segment %d has wrong flag or length", i)
		}
		got = append(got, frame.Content...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("segmented data differs from original bytes")
	}
}

func TestLegacyMuxSegmentationMatrix(t *testing.T) {
	for _, n := range []int{0, 1, 5, 19, 257, 4084, 4085, 4086, 8192, 65536, 122549, 122550, 122551, 131072, 262144} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			mux, remote := newLegacyMuxPipe(t, LegacyMuxConfig{})
			peer := newRobustnessPeer(t, remote, false, false)
			stream := openRobustnessStream(t, mux)
			// Shape proof only: valid zero-delta advertisement prevents the
			// initial 122550 allowance from confounding segmentation.
			peer.send(t, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(legacyPeerMaxWindow, 0)})
			waitForMuxState(t, mux, func() bool { return stream.peerMax == legacyPeerMaxWindow })
			want := deterministicPayload(n, n)
			if got, err := stream.Write(want); got != n || err != nil {
				t.Fatal("matrix write did not admit the complete group")
			}
			_ = stream.Close()
			frames := peer.wait(t, func(frames []Frame) bool {
				for _, f := range frames {
					if f.StreamID == stream.id && f.Flag == FrameFlagStreamClose {
						return true
					}
				}
				return false
			})
			assertDataGroup(t, dataFrames(frames, stream.id), want)
		})
	}
}

func TestLegacyMuxMalformedWireMatrix(t *testing.T) {
	control := func(flag byte, id uint32) []byte {
		b := make([]byte, 5)
		b[0] = flag
		binary.LittleEndian.PutUint32(b[1:], id)
		return b
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown_flag", control(0xff, 1)},
		{"invalid_control_id", control(0x06, 0)},
		{"invalid_ping_id", append(control(0x00, 1), 0, 0)},
		{"invalid_data_id", append(control(0x03, 0xffffffff), 0, 0)},
		{"oversized_declaration", append(control(0x03, 1), 0xf6, 0x0f)},
		{"never_existing_data", append(control(0x03, 77), 0, 0)},
		{"unexpected_accept", control(0x01, 77)},
		{"unexpected_reject", control(0x02, 77)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
			acknowledgeInitialPing(t, peer)
			if err := writeAll(peer, tc.raw); err != nil {
				t.Fatal("malformed fixture delivery failed")
			}
			waitMuxDone(t, mux)
			_, err := mux.OpenStream(context.Background())
			if !errors.Is(err, ErrLegacyProtocol) {
				t.Fatal("malformed input did not produce protocol sentinel")
			}
		})
	}
}

func TestLegacyMuxTruncatedFramesStopWorkers(t *testing.T) {
	var full bytes.Buffer
	_ = WriteFrame(&full, Frame{Flag: FrameFlagPing, StreamID: -1, Content: []byte("bounded")})
	for n := 1; n < full.Len(); n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
			acknowledgeInitialPing(t, peer)
			if err := writeAll(peer, full.Bytes()[:n]); err != nil {
				t.Fatal("truncated fixture delivery failed")
			}
			_ = peer.Close()
			waitMuxDone(t, mux)
			_ = mux.Close()
			assertLegacyMuxShutdownCleared(t, mux)
		})
	}
}

func TestLegacyMuxDuplicateResolvedOpenControlIsProtocolFailure(t *testing.T) {
	for _, flag := range []FrameFlag{FrameFlagStreamAccepted, FrameFlagStreamRejected} {
		t.Run(fmt.Sprint(flag), func(t *testing.T) {
			mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
			acknowledgeInitialPing(t, peer)
			stream := openPeerStream(t, mux, peer)
			writePeerFrame(t, peer, Frame{Flag: flag, StreamID: stream.id})
			waitMuxDone(t, mux)
			if _, err := stream.Write([]byte("x")); !errors.Is(err, ErrLegacyProtocol) {
				t.Fatal("duplicate resolved control was not a protocol failure")
			}
		})
	}
}

type addressFailureConn struct {
	net.Conn
	cause error
}

type explicitCloseObservedConn struct {
	net.Conn
	writes         atomic.Int32
	cleanupStarted chan struct{}
}

func (c *explicitCloseObservedConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	if len(p) == 5 && p[0] == byte(FrameFlagStreamClose) {
		select {
		case c.cleanupStarted <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(p)
}

func TestLegacyStreamExplicitCloseAfterMuxShutdown(t *testing.T) {
	transport := &net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 9875}, Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9876}, Err: errors.New("sensitive-test-material")}
	for _, tc := range []struct {
		name  string
		cause error
	}{{"protocol", ErrLegacyProtocol}, {"transport", transport}} {
		for _, observedEOF := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/observedEOF=%t", tc.name, observedEOF), func(t *testing.T) {
				server, peer := net.Pipe()
				observed := &explicitCloseObservedConn{Conn: server, cleanupStarted: make(chan struct{}, 1)}
				mux, err := NewLegacyMux(observeMuxProgress(observed), LegacyMuxConfig{})
				if err != nil {
					_ = server.Close()
					_ = peer.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = peer.Close(); _ = mux.Close() })
				acknowledgeInitialPing(t, peer)
				stream := openPeerStream(t, mux, peer)
				buf := make([]byte, 1)
				if observedEOF {
					writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
					select {
					case <-observed.cleanupStarted:
					case <-time.After(robustnessWait):
						t.Fatal("cleanup write did not begin")
					}
					// The peer deliberately does not read: cleanup cannot finish.
					mux.mu.Lock()
					inFlight := stream.closeInFlight && !stream.closeSent
					mux.mu.Unlock()
					if !inFlight {
						t.Fatal("cleanup is not blocked in raw write")
					}
					if _, err := stream.Read(buf); err != io.EOF {
						t.Fatal("normal remote EOF was not observed")
					}
				}
				mux.shutdown(tc.cause)
				_ = mux.Close()
				assertLegacyMuxShutdownCleared(t, mux, stream)
				_, err = stream.Read(buf)
				if observedEOF {
					if err != io.EOF {
						t.Fatal("observed EOF was not stable before explicit close")
					}
				} else if tc.cause == ErrLegacyProtocol {
					if !errors.Is(err, ErrLegacyProtocol) {
						t.Fatal("protocol cause was not preserved")
					}
				} else {
					assertSanitizedMuxError(t, err)
				}
				writes := observed.writes.Load()
				for i := 0; i < 3; i++ {
					if err := stream.Close(); err != nil {
						t.Fatal(err)
					}
					if _, err := stream.Read(buf); err != ErrLegacyStreamClosed {
						t.Fatal("explicit Close did not establish local-close precedence")
					}
					assertLegacyMuxShutdownCleared(t, mux, stream)
					mux.mu.Lock()
					unchanged := mux.streams == nil && mux.tombstones == nil && !stream.closePending && !stream.closeInFlight && !stream.closeSent && !stream.tombstoneReserved && stream.outstanding == 0
					mux.mu.Unlock()
					if !unchanged || observed.writes.Load() != writes {
						t.Fatal("explicit Close changed shutdown lifecycle or emitted a wire write")
					}
				}
			})
		}
	}
}

func (c *addressFailureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		return n, c.cause
	}
	return n, nil
}

func TestLegacyStreamTransportFailureAfterReturnIsSanitized(t *testing.T) {
	server, peer := net.Pipe()
	cause := &net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 9875}, Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9876}, Err: errors.New("sensitive-test-material")}
	mux, err := NewLegacyMux(observeMuxProgress(&addressFailureConn{Conn: server, cause: cause}), LegacyMuxConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); _ = mux.Close() })
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	_ = peer.Close()
	waitMuxDone(t, mux)
	_, err = stream.Read(make([]byte, 1))
	assertSanitizedMuxError(t, err)
	_, err = stream.Write([]byte("x"))
	assertSanitizedMuxError(t, err)
}

func TestLegacyStreamRemoteEOFRemainsObservedAfterMuxFailure(t *testing.T) {
	transport := &net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 9875}, Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9876}, Err: errors.New("sensitive-test-material")}
	for _, tc := range []struct {
		name  string
		cause error
	}{{"protocol", ErrLegacyProtocol}, {"transport", transport}} {
		for _, observed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/observed=%t", tc.name, observed), func(t *testing.T) {
				mux, conn := newLegacyMuxPipe(t, LegacyMuxConfig{})
				peer := newRobustnessPeer(t, conn, true, false)
				stream := openRobustnessStream(t, mux)
				peer.send(t, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: []byte("drain")})
				peer.send(t, Frame{Flag: FrameFlagStreamClose, StreamID: stream.id})
				waitForMuxState(t, mux, func() bool { return stream.remoteEOF })
				buf := make([]byte, 5)
				if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != "drain" {
					t.Fatal("remote-close buffered data did not drain")
				}
				if observed {
					if _, err := stream.Read(buf); err != io.EOF {
						t.Fatal("normal EOF not returned")
					}
				}
				waitForMuxState(t, mux, func() bool { return stream.state == legacyStreamTombstoned })
				mux.shutdown(tc.cause)
				if err := mux.Close(); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					_, err := stream.Read(buf)
					if observed {
						if err != io.EOF {
							t.Fatal("observed logical EOF changed after mux failure")
						}
					} else if tc.cause == ErrLegacyProtocol {
						if !errors.Is(err, ErrLegacyProtocol) {
							t.Fatal("unobserved EOF hid protocol failure")
						}
					} else {
						assertSanitizedMuxError(t, err)
					}
				}
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Read(buf); !errors.Is(err, ErrLegacyStreamClosed) {
					t.Fatal("explicit local close did not override observed EOF")
				}
			})
		}
	}
}
