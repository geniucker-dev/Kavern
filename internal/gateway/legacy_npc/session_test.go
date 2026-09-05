package legacy_npc

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
)

func TestLegacyNpcSessionInstallReplaceAndClearMux(t *testing.T) {
	session, _ := newLegacySessionFixture(t)
	first, firstPeer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, firstPeer)
	firstGeneration, old, err := session.installMux(first)
	if err != nil || old != nil || firstGeneration == 0 {
		t.Fatalf("install first = (generation=%d old=%p err=%v)", firstGeneration, old, err)
	}
	if _, _, err := session.installMux(first); !errors.Is(err, ErrLegacyMuxAlreadyInstalled) {
		t.Fatalf("install same mux error = %v, want ErrLegacyMuxAlreadyInstalled", err)
	}
	if _, generation, err := session.snapshotMux(); err != nil || generation != firstGeneration {
		t.Fatalf("snapshot after identical rejection = (generation=%d err=%v)", generation, err)
	}
	stream := openPeerStream(t, first, firstPeer)
	if stream == nil {
		t.Fatal("current mux was unusable after identical-pointer rejection")
	}

	second, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	secondGeneration, old, err := session.installMux(second)
	if err != nil || old != first || secondGeneration <= firstGeneration {
		t.Fatalf("install second = (generation=%d old=%p err=%v)", secondGeneration, old, err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close old mux: %v", err)
	}
	if session.clearMuxIfCurrent(first, firstGeneration) {
		t.Fatal("old mux completion cleared current mux")
	}
	if !session.clearMuxIfCurrent(second, secondGeneration) {
		t.Fatal("current mux was not cleared")
	}
	if _, _, err := session.snapshotMux(); !errors.Is(err, ErrLegacyDataChannelUnavailable) {
		t.Fatalf("snapshot after clear error = %v", err)
	}
}

func TestInstallTerminatedMuxIsAtomicAndPreservesCurrent(t *testing.T) {
	t.Run("terminated incoming is never published", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		incoming, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		incoming.shutdown(ErrLegacyProtocol)
		waitMuxDone(t, incoming)
		if _, _, err := session.installMux(incoming); !errors.Is(err, ErrLegacyProtocol) {
			t.Fatalf("install terminated mux error = %v, want ErrLegacyProtocol", err)
		}
		if _, _, err := session.snapshotMux(); !errors.Is(err, ErrLegacyDataChannelUnavailable) {
			t.Fatalf("terminated mux was published: %v", err)
		}
	})

	t.Run("failed incoming leaves healthy current usable", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		current, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
		acknowledgeInitialPing(t, peer)
		generation, _, err := session.installMux(current)
		if err != nil {
			t.Fatal(err)
		}
		incoming, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		incoming.shutdown(ErrLegacyProtocol)
		waitMuxDone(t, incoming)
		if _, _, err := session.installMux(incoming); !errors.Is(err, ErrLegacyProtocol) {
			t.Fatalf("install terminated replacement error = %v", err)
		}
		got, gotGeneration, err := session.snapshotMux()
		if err != nil || got != current || gotGeneration != generation {
			t.Fatalf("current after failed install = (%p, %d, %v)", got, gotGeneration, err)
		}
		if stream := openPeerStream(t, current, peer); stream == nil {
			t.Fatal("healthy current mux became unusable")
		}
	})

	t.Run("shutdown wins before install linearization", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		incoming, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		incoming.mu.Lock()
		started := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			close(started)
			_, _, err := session.installMux(incoming)
			result <- err
		}()
		<-started
		incoming.closed = true
		incoming.terminalErr = ErrLegacyProtocol
		incoming.mu.Unlock()
		if err := <-result; !errors.Is(err, ErrLegacyProtocol) {
			t.Fatalf("install after terminal linearization error = %v", err)
		}
		if _, _, err := session.snapshotMux(); !errors.Is(err, ErrLegacyDataChannelUnavailable) {
			t.Fatalf("terminal incoming mux was published: %v", err)
		}
	})

	t.Run("concurrent install and shutdown has one valid winner", func(t *testing.T) {
		for iteration := 0; iteration < 16; iteration++ {
			session, _ := newLegacySessionFixture(t)
			incoming, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
			start := make(chan struct{})
			installDone := make(chan error, 1)
			shutdownDone := make(chan struct{})
			go func() {
				<-start
				_, _, err := session.installMux(incoming)
				installDone <- err
			}()
			go func() {
				<-start
				incoming.shutdown(ErrLegacyProtocol)
				close(shutdownDone)
			}()
			close(start)
			installErr := <-installDone
			<-shutdownDone
			current, _, snapshotErr := session.snapshotMux()
			switch {
			case installErr == nil:
				if snapshotErr != nil || current != incoming {
					t.Fatalf("iteration %d: successful install did not publish incoming mux", iteration)
				}
			case errors.Is(installErr, ErrLegacyProtocol):
				if !errors.Is(snapshotErr, ErrLegacyDataChannelUnavailable) {
					t.Fatalf("iteration %d: rejected terminal mux was published: %v", iteration, snapshotErr)
				}
			default:
				t.Fatalf("iteration %d: install error = %v", iteration, installErr)
			}
		}
	})
}

func TestMuxSessionSnapshotPreservesTerminalAndFinalSessionState(t *testing.T) {
	t.Run("protocol survives clear", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		generation, _, err := session.installMux(mux)
		if err != nil {
			t.Fatal(err)
		}
		mux.mu.Lock()
		started := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			close(started)
			result <- session.mapMuxOperationError(context.Background(), mux, generation, nil)
		}()
		<-started
		mux.closed = true
		mux.terminalErr = ErrLegacyProtocol
		if !session.clearMuxIfCurrent(mux, generation) {
			mux.mu.Unlock()
			t.Fatal("failed to clear expected mux")
		}
		mux.mu.Unlock()
		if got := <-result; !errors.Is(got, ErrLegacyProtocol) {
			t.Fatalf("mapping after protocol shutdown and clear = %v, want ErrLegacyProtocol", got)
		}
	})

	t.Run("replacement wins over old protocol", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		generation, _, err := session.installMux(mux)
		if err != nil {
			t.Fatal(err)
		}
		mux.mu.Lock()
		result := make(chan error, 1)
		go func() {
			result <- session.mapMuxOperationError(context.Background(), mux, generation, ErrLegacyProtocol)
		}()
		replacement, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		if _, old, err := session.installMux(replacement); err != nil || old != mux {
			mux.mu.Unlock()
			t.Fatalf("install replacement = (old=%p err=%v)", old, err)
		}
		mux.closed = true
		mux.terminalErr = ErrLegacyProtocol
		mux.mu.Unlock()
		if got := <-result; !errors.Is(got, ErrLegacyDataChannelReplaced) {
			t.Fatalf("old protocol mapping after replacement = %v", got)
		}
	})
}

func TestLegacyNpcSessionErrorMappingUsesFinalAuthoritativeSnapshot(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		generation, _, err := session.installMux(mux)
		if err != nil {
			t.Fatal(err)
		}
		mux.mu.Lock()
		result := make(chan error, 1)
		go func() { result <- session.mapMuxOperationError(context.Background(), mux, generation, nil) }()
		replacement, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		if _, old, err := session.installMux(replacement); err != nil || old != mux {
			mux.mu.Unlock()
			t.Fatalf("install replacement = (old=%p err=%v)", old, err)
		}
		mux.mu.Unlock()
		if got := <-result; !errors.Is(got, ErrLegacyDataChannelReplaced) {
			t.Fatalf("nil-operation mapping = %v, want ErrLegacyDataChannelReplaced", got)
		}

		mux.mu.Lock()
		result = make(chan error, 1)
		go func() {
			result <- session.mapMuxOperationError(context.Background(), mux, generation, ErrLegacyProtocol)
		}()
		mux.mu.Unlock()
		if got := <-result; !errors.Is(got, ErrLegacyDataChannelReplaced) {
			t.Fatalf("protocol replacement mapping = %v, want ErrLegacyDataChannelReplaced", got)
		}
	})

	t.Run("session close", func(t *testing.T) {
		session, _ := newLegacySessionFixture(t)
		mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
		generation, _, err := session.installMux(mux)
		if err != nil {
			t.Fatal(err)
		}
		mux.mu.Lock()
		result := make(chan error, 1)
		go func() { result <- session.mapMuxOperationError(context.Background(), mux, generation, nil) }()
		closeDone := make(chan error, 1)
		go func() { closeDone <- session.Close(context.Background()) }()
		waitForSessionClosed(t, session)
		mux.mu.Unlock()
		if got := <-result; !errors.Is(got, ErrLegacySessionClosed) {
			t.Fatalf("close mapping = %v, want ErrLegacySessionClosed", got)
		}
		if err := <-closeDone; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
}

func TestLegacyNpcSessionReplacementBeforeAcceptWritesNoStaleMetadata(t *testing.T) {
	session, _ := newLegacySessionFixture(t)
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	if _, _, err := session.installMux(mux); err != nil {
		t.Fatal(err)
	}
	acknowledgeInitialPing(t, peer)
	result := make(chan error, 1)
	go func() {
		_, err := session.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		result <- err
	}()
	open := readPeerFrame(t, peer)
	mux.mu.Lock()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- WriteFrame(peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	}()
	replacement, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	if _, old, err := session.installMux(replacement); err != nil || old != mux {
		mux.mu.Unlock()
		t.Fatalf("install replacement = (old=%p err=%v)", old, err)
	}
	mux.mu.Unlock()
	if err := <-writeDone; err != nil {
		t.Fatalf("write stream accepted: %v", err)
	}
	if err := <-result; !errors.Is(err, ErrLegacyDataChannelReplaced) {
		t.Fatalf("OpenStream() error = %v, want ErrLegacyDataChannelReplaced", err)
	}
	assertNoDataFrameForStream(t, peer, open.StreamID)
}

func TestLegacyNpcSessionCloseReleasesResourcesAfterContextCancellation(t *testing.T) {
	session, mainPeer := newLegacySessionFixture(t)
	mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	if _, _, err := session.installMux(mux); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close(canceled) error = %v", err)
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("session Done was not closed")
	}
	waitMuxDone(t, mux)
	if _, err := mainPeer.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("main peer read after Close error = %v", err)
	}
}

func TestLegacyNpcSessionMapsMuxFailuresAcrossClearAndReplacement(t *testing.T) {
	tests := []struct {
		name    string
		cause   error
		want    error
		clear   bool
		replace bool
	}{
		{name: "protocol after clear", cause: ErrLegacyProtocol, want: ErrLegacyProtocol, clear: true},
		{name: "receive limit after clear", cause: ErrLegacyReceiveLimit, want: ErrLegacyReceiveLimit, clear: true},
		{name: "EOF after clear", cause: io.EOF, want: ErrLegacyDataChannelUnavailable, clear: true},
		{name: "internal open timeout", cause: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{name: "protocol after replacement", cause: ErrLegacyProtocol, want: ErrLegacyDataChannelReplaced, replace: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, _ := newLegacySessionFixture(t)
			mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
			generation, _, err := session.installMux(mux)
			if err != nil {
				t.Fatal(err)
			}
			if tt.cause != context.DeadlineExceeded {
				mux.shutdown(tt.cause)
				waitMuxDone(t, mux)
			}
			if tt.clear {
				session.clearMuxIfCurrent(mux, generation)
			}
			if tt.replace {
				replacement, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
				if _, old, err := session.installMux(replacement); err != nil || old != mux {
					t.Fatalf("install replacement = (old=%p err=%v)", old, err)
				}
			}
			if got := session.mapMuxOperationError(context.Background(), mux, generation, tt.cause); !errors.Is(got, tt.want) {
				t.Fatalf("mapped error = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLegacyNpcSessionMuxErrorMappingNeverLeaksNetworkAddress(t *testing.T) {
	session, _ := newLegacySessionFixture(t)
	mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	generation, _, err := session.installMux(mux)
	if err != nil {
		t.Fatal(err)
	}
	raw := &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 9443}, Err: errors.New("raw network failure")}
	got := session.mapMuxOperationError(context.Background(), mux, generation, raw)
	if !errors.Is(got, ErrLegacyDataChannelUnavailable) {
		t.Fatalf("mapped error = %v, want ErrLegacyDataChannelUnavailable", got)
	}
	if strings.Contains(got.Error(), "203.0.113.7") || strings.Contains(got.Error(), "9443") {
		t.Fatalf("mapped error leaked network address: %q", got)
	}
}

func TestLegacyNpcSessionContextCancellationPrecedesReplacementAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "shutdown"}[shutdown], func(t *testing.T) {
			session, _ := newLegacySessionFixture(t)
			mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
			generation, _, err := session.installMux(mux)
			if err != nil {
				t.Fatal(err)
			}
			if shutdown {
				mux.shutdown(ErrLegacyProtocol)
			} else {
				replacement, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
				if _, _, err := session.installMux(replacement); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if got := session.mapMuxOperationError(ctx, mux, generation, ErrLegacyMuxClosed); !errors.Is(got, context.Canceled) {
				t.Fatalf("mapped error = %v, want context.Canceled", got)
			}
		})
	}
}

func TestLegacyNpcSessionConcurrentCloseInstallAndClear(t *testing.T) {
	session, _ := newLegacySessionFixture(t)
	mux, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		<-start
		_ = session.Close(context.Background())
	}()
	go func() {
		defer wait.Done()
		<-start
		_, _, _ = session.installMux(mux)
	}()
	go func() {
		defer wait.Done()
		<-start
		session.clearMuxIfCurrent(mux, 1)
	}()
	close(start)
	completed := make(chan struct{})
	go func() {
		wait.Wait()
		close(completed)
	}()
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("concurrent session lifecycle operations did not finish")
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not close")
	}
}

func TestLegacyNpcSessionOpenStreamWritesLinkMetadata(t *testing.T) {
	session, _ := newLegacySessionFixture(t)
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	if _, _, err := session.installMux(mux); err != nil {
		t.Fatal(err)
	}
	acknowledgeInitialPing(t, peer)

	result := make(chan struct {
		stream interface{ Close() error }
		err    error
	}, 1)
	go func() {
		stream, err := session.OpenStream(context.Background(), domain.StreamOpenRequest{
			TunnelID:   "tunnel-1",
			Protocol:   domain.TunnelProtocolTCP,
			RemoteAddr: "127.0.0.1:51234",
		})
		result <- struct {
			stream interface{ Close() error }
			err    error
		}{stream: stream, err: err}
	}()

	open := readPeerFrame(t, peer)
	if open.Flag != FrameFlagStreamOpen {
		t.Fatalf("open frame = %#v", open)
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	metadata := readPeerFrame(t, peer)
	if metadata.Flag != FrameFlagDataFinal || metadata.StreamID != open.StreamID {
		t.Fatalf("metadata frame = %#v", metadata)
	}
	want, err := encodeLegacyLinkMetadata("127.0.0.1:8080", "127.0.0.1:51234")
	if err != nil {
		t.Fatal(err)
	}
	if string(metadata.Content) != string(want) {
		t.Fatalf("metadata bytes = %q, want %q", metadata.Content, want)
	}
	got := <-result
	if got.err != nil {
		t.Fatalf("OpenStream() error = %v", got.err)
	}
	_ = got.stream.Close()
}

func TestLegacyNpcSessionOpenStreamValidation(t *testing.T) {
	tests := []struct {
		name    string
		request domain.StreamOpenRequest
		setup   func(*store.MemoryStore)
		want    error
	}{
		{
			name:    "empty tunnel",
			request: domain.StreamOpenRequest{Protocol: domain.TunnelProtocolTCP},
			want:    ErrLegacyInvalidStreamRequest,
		},
		{
			name:    "caller target",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:1"},
			want:    ErrLegacyInvalidStreamRequest,
		},
		{
			name:    "non TCP",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolHTTP},
			want:    ErrLegacyInvalidStreamRequest,
		},
		{
			name:    "disabled tunnel",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP},
			setup: func(st *store.MemoryStore) {
				_ = st.CreateTunnel(context.Background(), domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:8080", Enabled: false})
			},
			want: ErrLegacyTunnelDisabled,
		},
		{
			name:    "disabled device",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP},
			setup: func(st *store.MemoryStore) {
				_ = st.CreateDevice(context.Background(), domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: false})
			},
			want: ErrLegacyDeviceDisabled,
		},
		{
			name:    "mismatched tunnel device",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP},
			setup: func(st *store.MemoryStore) {
				_ = st.CreateTunnel(context.Background(), domain.Tunnel{ID: "tunnel-1", DeviceID: "device-2", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:8080", Enabled: true})
			},
			want: ErrLegacyTunnelDeviceMismatch,
		},
		{
			name:    "stored non TCP",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP},
			setup: func(st *store.MemoryStore) {
				_ = st.CreateTunnel(context.Background(), domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolHTTP, TargetAddr: "127.0.0.1:8080", Enabled: true})
			},
			want: ErrLegacyUnsupportedTunnelProtocol,
		},
		{
			name:    "invalid stored target",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP},
			setup: func(st *store.MemoryStore) {
				_ = st.CreateTunnel(context.Background(), domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "https://example.test:443", Enabled: true})
			},
			want: ErrLegacyInvalidTargetAddress,
		},
		{
			name:    "invalid remote address",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP, RemoteAddr: "bad remote"},
			want:    ErrLegacyInvalidRemoteAddress,
		},
		{
			name:    "no data channel",
			request: domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP},
			want:    ErrLegacyDataChannelUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, _ := newLegacySessionFixture(t)
			if tt.setup != nil {
				tt.setup(session.store.(*store.MemoryStore))
			}
			if _, err := session.OpenStream(context.Background(), tt.request); !errors.Is(err, tt.want) {
				t.Fatalf("OpenStream() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestLegacyLinkMetadataWriteCancellationJoinsBlockedWriter(t *testing.T) {
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(1, 0)})
	waitForMuxState(t, mux, func() bool { return stream.peerMax == 1 })
	payload, err := encodeLegacyLinkMetadata("localhost:8080", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- writeLegacyLinkMetadata(ctx, stream, payload) }()
	assertBlocked(t, result)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("metadata write error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("metadata writer did not exit after cancellation")
	}
}

func TestLegacyLinkMetadataWriteCancellationJoinsQueueBlockedWriter(t *testing.T) {
	cfg := LegacyMuxConfig{MaxQueuedFramesTotal: 153, MaxControlFrames: 152}
	mux, peer := newLegacyMuxPipe(t, cfg)
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	if _, err := stream.Write([]byte("filler")); err != nil {
		t.Fatalf("fill queue Write() error = %v", err)
	}
	waitForMuxState(t, mux, func() bool { return mux.dataCount == 1 && len(stream.dataQueue) == 0 })
	payload, err := encodeLegacyLinkMetadata("localhost:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- writeLegacyLinkMetadata(ctx, stream, payload) }()
	assertBlocked(t, result)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queue-blocked metadata write error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queue-blocked metadata writer did not exit")
	}
}

func TestLegacyLinkMetadataWriteReplacementMapsAfterWriterExit(t *testing.T) {
	session, _ := newLegacySessionFixture(t)
	mux, peer := newLegacyMuxPipe(t, LegacyMuxConfig{})
	generation, _, err := session.installMux(mux)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgeInitialPing(t, peer)
	stream := openPeerStream(t, mux, peer)
	writePeerFrame(t, peer, Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(1, 0)})
	waitForMuxState(t, mux, func() bool { return stream.peerMax == 1 })
	payload, err := encodeLegacyLinkMetadata("localhost:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- writeLegacyLinkMetadata(context.Background(), stream, payload) }()
	assertBlocked(t, result)
	replacement, _ := newLegacyMuxPipe(t, LegacyMuxConfig{})
	if _, old, err := session.installMux(replacement); err != nil || old != mux {
		t.Fatalf("install replacement = (old=%p err=%v)", old, err)
	}
	_ = mux.Close()
	writeErr := <-result
	if got := session.mapMuxOperationError(context.Background(), mux, generation, writeErr); !errors.Is(got, ErrLegacyDataChannelReplaced) {
		t.Fatalf("mapped replacement error = %v, want ErrLegacyDataChannelReplaced", got)
	}
}

func newLegacySessionFixture(t *testing.T) (*LegacyNpcSession, net.Conn) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemoryStore()
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:8080", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	main, peer := net.Pipe()
	runtime := newLegacyDeviceRuntime("device-1")
	session := newSession("session-1", "device-1", main, st, runtime, nil)
	runtime.currentMain = session
	runtime.attachedMain = session
	t.Cleanup(func() {
		_ = session.Close(context.Background())
		_ = peer.Close()
	})
	return session, peer
}

func assertBlocked(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("operation completed before unblock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
}

func waitForSessionClosed(t *testing.T, session *LegacyNpcSession) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		session.mu.Lock()
		closed := session.closed
		session.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("session did not enter closed state")
}

func assertNoDataFrameForStream(t *testing.T, peer net.Conn, streamID int32) {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
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
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			t.Fatalf("ReadFrame(peer) error = %v", err)
		}
		switch frame.Flag {
		case FrameFlagPing:
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
		case FrameFlagStreamClose:
			if frame.StreamID != streamID {
				t.Fatalf("unexpected close stream ID = %d", frame.StreamID)
			}
		case FrameFlagDataFinal, FrameFlagDataContinue:
			if frame.StreamID == streamID {
				t.Fatalf("stale metadata/data frame written to stream %d", streamID)
			}
		default:
			t.Fatalf("unexpected frame after replacement = %#v", frame)
		}
	}
}
