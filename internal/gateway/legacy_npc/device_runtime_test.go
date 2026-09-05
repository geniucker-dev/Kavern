package legacy_npc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func TestDeviceRuntimeTransitionLeasePreservesEntryAfterSessionRelease(t *testing.T) {
	gateway := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
	transition := gateway.acquireRuntime("device-1", legacyRuntimeLeaseTransition)
	sessionLease := gateway.acquireRuntime("device-1", legacyRuntimeLeaseSession)
	if transition.Runtime() != sessionLease.Runtime() {
		t.Fatal("leases for one device returned different runtimes")
	}
	if err := sessionLease.Release(); err != nil {
		t.Fatal(err)
	}
	chanLease := gateway.acquireRuntime("device-1", legacyRuntimeLeaseChan)
	if chanLease.Runtime() != transition.Runtime() {
		t.Fatal("transition lease did not preserve the runtime entry")
	}
	if err := transition.Release(); err != nil {
		t.Fatal(err)
	}
	if err := chanLease.Release(); err != nil {
		t.Fatal(err)
	}
	assertRuntimeMapEmpty(t, gateway)
}

func TestDeviceRuntimeLeaseReleaseIsOneShot(t *testing.T) {
	gateway := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
	lease := gateway.acquireRuntime("device-1", legacyRuntimeLeaseSession)
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("duplicate release returned %v", err)
	}
	assertRuntimeMapEmpty(t, gateway)
}

func TestDeviceRuntimeManyTemporaryDevicesAreReclaimed(t *testing.T) {
	gateway := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
	for i := 0; i < 500; i++ {
		lease := gateway.acquireRuntime(domain.DeviceID(fmt.Sprintf("device-%d", i)), legacyRuntimeLeaseChan)
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	}
	assertRuntimeMapEmpty(t, gateway)
}

func TestDeviceRuntimeAttachedMainWinsReadyTimeout(t *testing.T) {
	runtime := newLegacyDeviceRuntime("device-1")
	mux, peer := newRuntimeTestMux(t)
	defer peer.Close()
	defer mux.Close()
	generation, _, err := runtime.installMux(mux)
	if err != nil {
		t.Fatal(err)
	}
	mainServer, mainClient := net.Pipe()
	defer mainClient.Close()
	session := newSession("session-1", "device-1", mainServer, nil, runtime, nil)
	defer session.Close(context.Background())
	runtime.mu.Lock()
	runtime.currentMain = session
	runtime.attachedMain = session
	close(runtime.mainNotify)
	runtime.mainNotify = make(chan struct{})
	runtime.mu.Unlock()

	if err := runtime.waitForMainInterest(context.Background(), mux, generation, time.Nanosecond); err != nil {
		t.Fatalf("ready main lost timeout race: %v", err)
	}
	if got, _, err := runtime.snapshotMuxForSession(session); err != nil || got != mux {
		t.Fatalf("current mux after readiness = %p, %v", got, err)
	}
}

func TestDeviceRuntimeTimeoutClearsOnlyExpectedMux(t *testing.T) {
	runtime := newLegacyDeviceRuntime("device-1")
	first, firstPeer := newRuntimeTestMux(t)
	defer firstPeer.Close()
	defer first.Close()
	firstGeneration, _, err := runtime.installMux(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.waitForMainInterest(context.Background(), first, firstGeneration, time.Millisecond); !errors.Is(err, ErrNoCurrentMainSession) {
		t.Fatalf("waitForMainInterest() error = %v", err)
	}
	runtime.mu.Lock()
	if runtime.mux != nil {
		t.Fatal("timed-out mux remained installed")
	}
	runtime.mu.Unlock()

	second, secondPeer := newRuntimeTestMux(t)
	defer secondPeer.Close()
	defer second.Close()
	secondGeneration, _, err := runtime.installMux(second)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.clearMuxIfCurrent(first, firstGeneration) {
		t.Fatal("stale cleanup cleared a replacement mux")
	}
	runtime.mu.Lock()
	if runtime.mux != second || runtime.muxGeneration != secondGeneration {
		t.Fatal("replacement mux was disturbed by stale cleanup")
	}
	runtime.mu.Unlock()
}

func TestDeviceRuntimeNotifyHasNoLostWakeup(t *testing.T) {
	runtime := newLegacyDeviceRuntime("device-1")
	mux, peer := newRuntimeTestMux(t)
	defer peer.Close()
	defer mux.Close()
	generation, _, err := runtime.installMux(mux)
	if err != nil {
		t.Fatal(err)
	}
	mainServer, mainClient := net.Pipe()
	defer mainClient.Close()
	session := newSession("session-1", "device-1", mainServer, nil, runtime, nil)
	defer session.Close(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- runtime.waitForMainInterest(context.Background(), mux, generation, time.Second)
	}()
	runtime.mu.Lock()
	runtime.currentMain = session
	runtime.attachedMain = session
	close(runtime.mainNotify)
	runtime.mainNotify = make(chan struct{})
	runtime.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("readiness notification was lost")
	}
}

func TestDeviceRuntimePendingTransitionRetainsMuxUntilLastCleanup(t *testing.T) {
	runtime := newLegacyDeviceRuntime("device-1")
	mux, peer := newRuntimeTestMux(t)
	defer peer.Close()
	generation, _, err := runtime.installMux(mux)
	if err != nil {
		t.Fatal(err)
	}
	beginMainTransitionForTest(runtime)
	if err := runtime.waitForMainInterest(context.Background(), mux, generation, time.Nanosecond); err != nil {
		t.Fatalf("pending transition did not retain mux: %v", err)
	}
	detached, err := runtime.finishUnpublishedMainTransition()
	if err != nil {
		t.Fatal(err)
	}
	if detached != mux {
		t.Fatalf("last transition detached mux = %p, want %p", detached, mux)
	}
	if err := detached.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	pending := runtime.pendingMainTransitions
	runtime.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending transitions = %d, want zero", pending)
	}
	if _, err := runtime.finishUnpublishedMainTransition(); !errors.Is(err, ErrLegacyRuntimeInvariant) {
		t.Fatalf("transition underflow error = %v, want ErrLegacyRuntimeInvariant", err)
	}
}

func TestDeviceRuntimeCommitRechecksCanceledContext(t *testing.T) {
	runtime := newLegacyDeviceRuntime("device-1")
	mainServer, mainClient := net.Pipe()
	defer mainClient.Close()
	session := newSession("session-1", "device-1", mainServer, nil, runtime, nil)
	defer session.Close(context.Background())
	beginMainTransitionForTest(runtime)
	runtime.publishMainCandidate(session)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	committed, err := runtime.commitAttachedMain(ctx, session, session)
	if err != nil {
		t.Fatal(err)
	}
	if committed {
		t.Fatal("canceled context published attachedMain")
	}
	if _, err := runtime.reconcileFailedMain(session, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	attached := runtime.attachedMain
	pending := runtime.pendingMainTransitions
	runtime.mu.Unlock()
	if attached != nil || pending != 0 {
		t.Fatalf("post-cancel state = (attached=%p pending=%d)", attached, pending)
	}
}

func TestDeviceRuntimeLastFailedQueuedTransitionDetachesMux(t *testing.T) {
	runtime := newLegacyDeviceRuntime("device-1")
	mux, peer := newRuntimeTestMux(t)
	defer peer.Close()
	if _, _, err := runtime.installMux(mux); err != nil {
		t.Fatal(err)
	}
	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	first := newSession("session-1", "device-1", firstServer, nil, runtime, nil)
	defer first.Close(context.Background())
	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	second := newSession("session-2", "device-1", secondServer, nil, runtime, nil)
	defer second.Close(context.Background())

	beginMainTransitionForTest(runtime)
	beginMainTransitionForTest(runtime)
	priorCurrent, priorAttached, _ := runtime.publishMainCandidate(first)
	detached, err := runtime.reconcileFailedMain(first, priorCurrent, priorAttached, nil)
	if err != nil {
		t.Fatal(err)
	}
	if detached != nil {
		t.Fatal("first failed transition detached mux despite queued successor")
	}
	priorCurrent, priorAttached, _ = runtime.publishMainCandidate(second)
	detached, err = runtime.reconcileFailedMain(second, priorCurrent, priorAttached, nil)
	if err != nil {
		t.Fatal(err)
	}
	if detached != mux {
		t.Fatalf("last failed transition detached mux = %p, want %p", detached, mux)
	}
	if err := detached.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	pending := runtime.pendingMainTransitions
	interest := runtime.hasMainInterestLocked()
	runtime.mu.Unlock()
	if pending != 0 || interest {
		t.Fatalf("final transition state = (pending=%d interest=%t)", pending, interest)
	}
}

func TestAtomicMainTransitionAcquisitionProtectsMuxFromPredecessorCleanup(t *testing.T) {
	gateway := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
	chanLease := gateway.acquireRuntime("device-1", legacyRuntimeLeaseChan)
	runtime := chanLease.Runtime()
	mux, peer := newRuntimeTestMux(t)
	defer peer.Close()
	if _, _, err := runtime.installMux(mux); err != nil {
		t.Fatal(err)
	}
	predecessorTransition, predecessorSession := gateway.acquireMainRuntime("device-1")
	successorTransition, successorSession := gateway.acquireMainRuntime("device-1")
	if predecessorTransition.Runtime() != runtime || successorTransition.Runtime() != runtime {
		t.Fatal("atomic main acquisition returned a different runtime entry")
	}

	detached, err := runtime.finishUnpublishedMainTransition()
	if err != nil {
		t.Fatal(err)
	}
	if detached != nil {
		t.Fatal("predecessor cleanup detached mux after successor acquisition completed")
	}
	if err := predecessorSession.Release(); err != nil {
		t.Fatal(err)
	}
	if err := predecessorTransition.Release(); err != nil {
		t.Fatal(err)
	}

	mainServer, mainClient := net.Pipe()
	defer mainClient.Close()
	successor := newSession("session-successor", "device-1", mainServer, nil, runtime, successorSession)
	runtime.publishMainCandidate(successor)
	committed, err := runtime.commitAttachedMain(context.Background(), successor, successor)
	if err != nil || !committed {
		t.Fatalf("successor commit = (%t, %v)", committed, err)
	}
	if err := successorTransition.Release(); err != nil {
		t.Fatal(err)
	}
	acknowledgeInitialPing(t, peer)
	currentMux, _, err := runtime.snapshotMuxForSession(successor)
	if err != nil || currentMux != mux {
		t.Fatalf("successor mux snapshot = (%p, %v), want original mux", currentMux, err)
	}
	if stream := openPeerStream(t, currentMux, peer); stream == nil {
		t.Fatal("successor could not use protected mux")
	}
	if err := successor.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := chanLease.Release(); err != nil {
		t.Fatal(err)
	}
	assertRuntimeMapEmpty(t, gateway)
}

func TestMainMonitorContextCancellationAndCloseAreBounded(t *testing.T) {
	gateway := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
	transitionLease, sessionLease := gateway.acquireMainRuntime("device-1")
	runtime := transitionLease.Runtime()
	ctx, cancel := context.WithCancel(context.Background())
	server, peer := net.Pipe()
	session := newSessionWithContext(ctx, "session-1", "device-1", server, nil, runtime, sessionLease)
	if err := session.startMainMonitor(); err != nil {
		t.Fatal(err)
	}
	if err := session.startMainMonitor(); !errors.Is(err, ErrLegacyRuntimeInvariant) {
		t.Fatalf("second monitor start error = %v", err)
	}
	cancel()
	session.waitMainMonitor()
	if _, err := runtime.finishUnpublishedMainTransition(); err != nil {
		t.Fatal(err)
	}
	if err := transitionLease.Release(); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- session.Close(context.Background()) }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the main monitor")
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	assertRuntimeMapEmpty(t, gateway)
}

func newRuntimeTestMux(t *testing.T) (*LegacyMux, net.Conn) {
	t.Helper()
	server, peer := net.Pipe()
	mux, err := NewLegacyMux(server, LegacyMuxConfig{})
	if err != nil {
		server.Close()
		peer.Close()
		t.Fatal(err)
	}
	return mux, peer
}

func assertRuntimeMapEmpty(t *testing.T, gateway *Gateway) {
	t.Helper()
	gateway.runtimeMu.Lock()
	defer gateway.runtimeMu.Unlock()
	if len(gateway.runtimes) != 0 {
		t.Fatalf("runtime map contains %d entries, want zero", len(gateway.runtimes))
	}
}

func beginMainTransitionForTest(runtime *legacyDeviceRuntime) {
	runtime.mu.Lock()
	runtime.pendingMainTransitions++
	runtime.notifyMainStateLocked()
	runtime.mu.Unlock()
}
