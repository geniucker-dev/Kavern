package legacy_npc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

func TestSlowSessionIDPreservesEarlyChan(t *testing.T) {
	for _, outcome := range []string{"success", "error", "empty"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			gateway, manager, token := newGatewayFixture(t, true)
			gateway.handshakeTimeout = 20 * time.Millisecond
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			idErr := errors.New("session ID generation failed")
			gateway.newSessionID = func() (domain.SessionID, error) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return "", ctx.Err()
				}
				switch outcome {
				case "error":
					return "", idErr
				case "empty":
					return "", nil
				default:
					return "registered-main", nil
				}
			}
			main, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
			defer main.Close()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			gateway.runtimeMu.Lock()
			entry := gateway.runtimes["device-1"]
			gateway.runtimeMu.Unlock()
			if entry == nil {
				t.Fatal("authenticated main has no runtime during ID generation")
			}
			waitPendingMainTransitions(t, ctx, entry.runtime, 1)
			peer, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
			defer peer.Close()
			acknowledgeInitialPing(t, peer)
			entry.runtime.mu.Lock()
			mux := entry.runtime.mux
			generation := entry.runtime.muxGeneration
			entry.runtime.mu.Unlock()
			select {
			case err := <-chanDone:
				t.Fatalf("chan exited during ID generation: %v", err)
			case <-time.After(2 * gateway.handshakeTimeout):
			}
			entry.runtime.mu.Lock()
			preserved := mux != nil && entry.runtime.mux == mux && entry.runtime.muxGeneration == generation
			entry.runtime.mu.Unlock()
			if !preserved {
				t.Fatal("slow ID generation lost the installed mux")
			}
			unblock()
			if outcome == "success" {
				current := waitCurrent(t, ctx, manager, "device-1")
				proveRegisteredMainStream(t, ctx, current, peer)
				_ = main.Close()
				waitDone(t, ctx, mainDone, nil)
			} else {
				want := idErr
				if outcome == "empty" {
					want = ErrInvalidHandshake
				}
				waitDone(t, ctx, mainDone, want)
			}
			waitDone(t, ctx, chanDone, nil)
			select {
			case <-mux.Done():
			default:
				t.Fatal("final main cleanup did not close orphan mux")
			}
			assertRegistrationReleased(t, gateway, entry)
		})
	}
}

type registrationAttachBarrier struct {
	session.SessionManager
	entered chan *LegacyNpcSession
	release chan struct{}
}

func (m *registrationAttachBarrier) Attach(ctx context.Context, next session.AgentSession) error {
	m.entered <- next.(*LegacyNpcSession)
	<-m.release
	return m.SessionManager.Attach(ctx, next)
}

func TestDeadMainBeforeAttachPreservesHealthySession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	aConn, aDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer aConn.Close()
	a := waitCurrent(t, ctx, manager, "device-1").(*LegacyNpcSession)
	waitPendingMainTransitions(t, ctx, a.runtime, 0)
	peer, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer peer.Close()
	acknowledgeInitialPing(t, peer)
	barrier := &registrationAttachBarrier{SessionManager: manager, entered: make(chan *LegacyNpcSession, 1), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(barrier.release) }) }
	defer unblock()
	gateway.sessions = barrier
	bConn, bDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	var b *LegacyNpcSession
	select {
	case b = <-barrier.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_ = bConn.Close()
	select {
	case <-b.mainMonitorDone:
	case <-ctx.Done():
		t.Fatal("main monitor did not detect pre-Attach EOF")
	}
	unblock()
	waitDone(t, ctx, bDone, nil)
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil || current != a || a.isClosed() {
		t.Fatalf("dead candidate displaced healthy main: %v", err)
	}
	a.runtime.mu.Lock()
	restored := a.runtime.currentMain == a && a.runtime.attachedMain == a && a.runtime.pendingMainTransitions == 0
	a.runtime.mu.Unlock()
	if !restored {
		t.Fatal("prior main ownership was not restored")
	}
	proveRegisteredMainStream(t, ctx, a, peer)
	gateway.runtimeMu.Lock()
	entry := gateway.runtimes["device-1"]
	gateway.runtimeMu.Unlock()
	_ = aConn.Close()
	waitDone(t, ctx, aDone, nil)
	waitDone(t, ctx, chanDone, nil)
	assertRegistrationReleased(t, gateway, entry)
}

func TestPublishCandidateLifecycleRejectsCanceledSession(t *testing.T) {
	a, _ := newLegacySessionFixture(t)
	runtime := a.runtime
	server, peer := net.Pipe()
	defer peer.Close()
	b := newSession("candidate", a.deviceID, server, a.store, runtime, nil)
	defer b.Close(context.Background())
	beginMainTransitionForTest(runtime)
	runtime.mu.Lock()
	notify := runtime.mainNotify
	started := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		close(started)
		_, _, published := runtime.publishMainCandidate(b)
		result <- published
	}()
	<-started
	b.lifecycleCancel()
	runtime.mu.Unlock()
	if <-result {
		t.Fatal("publication accepted a canceled lifecycle")
	}
	runtime.mu.Lock()
	unchanged := runtime.currentMain == a && runtime.attachedMain == a && runtime.mainNotify == notify
	runtime.mu.Unlock()
	if !unchanged {
		t.Fatal("rejected publication changed ownership or notification")
	}
	if mux, err := runtime.finishUnpublishedMainTransition(); err != nil || mux != nil {
		t.Fatalf("unpublished cleanup = (%p, %v)", mux, err)
	}
}

func proveRegisteredMainStream(t *testing.T, ctx context.Context, main session.AgentSession, peer net.Conn) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		stream, err := main.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		done <- err
	}()
	open := readPeerFrame(t, peer)
	if open.Flag != FrameFlagStreamOpen {
		t.Fatal("expected stream open")
	}
	writePeerFrame(t, peer, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	metadata := readPeerFrame(t, peer)
	if metadata.Flag != FrameFlagDataFinal || metadata.StreamID != open.StreamID {
		t.Fatal("expected metadata on accepted stream")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	closeFrame := readPeerFrame(t, peer)
	if closeFrame.Flag != FrameFlagStreamClose || closeFrame.StreamID != open.StreamID {
		t.Fatal("expected ordered stream cleanup")
	}
}

func assertRegistrationReleased(t *testing.T, gateway *Gateway, entry *legacyRuntimeEntry) {
	t.Helper()
	entry.runtime.mu.Lock()
	empty := entry.runtime.pendingMainTransitions == 0 && entry.runtime.currentMain == nil && entry.runtime.attachedMain == nil && entry.runtime.mux == nil
	entry.runtime.mu.Unlock()
	if !empty {
		t.Fatal("runtime state remained after registration cleanup")
	}
	gateway.runtimeMu.Lock()
	defer gateway.runtimeMu.Unlock()
	if entry.refs != 0 || len(gateway.runtimes) != 0 {
		t.Fatal("registration leases or runtime entry leaked")
	}
	for _, count := range entry.byKind {
		if count != 0 {
			t.Fatal("registration lease category leaked")
		}
	}
}
