package legacy_npc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/testutil"
)

type failedAttachUnknownManager struct {
	session.SessionManager
	attachErr error
	queried   chan struct{}
}

func (m *failedAttachUnknownManager) Attach(context.Context, session.AgentSession) error {
	return m.attachErr
}
func (m *failedAttachUnknownManager) CurrentForDevice(ctx context.Context, _ domain.DeviceID) (session.AgentSession, error) {
	close(m.queried)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestFailedAttachUnknownObservationPreservesPriorMux(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	gateway.handshakeTimeout = 20 * time.Millisecond
	aConn, aDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer aConn.Close()
	a := waitCurrent(t, ctx, manager, "device-1").(*LegacyNpcSession)
	waitPendingMainTransitions(t, ctx, a.runtime, 0)
	peer, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer peer.Close()
	acknowledgeInitialPing(t, peer)
	mux, generation, err := a.snapshotMux()
	if err != nil {
		t.Fatal(err)
	}
	gateway.runtimeMu.Lock()
	entry := gateway.runtimes["device-1"]
	gateway.runtimeMu.Unlock()
	failure := errors.New("deliberate Attach failure")
	wrapper := &failedAttachUnknownManager{SessionManager: manager, attachErr: failure, queried: make(chan struct{})}
	gateway.sessions = wrapper
	bConn, bDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer bConn.Close()
	waitDone(t, ctx, bDone, failure)
	select {
	case <-wrapper.queried:
	default:
		t.Fatal("cleanup observation was not attempted")
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil || current != a {
		t.Fatalf("manager lost prior: %v", err)
	}
	a.runtime.mu.Lock()
	preserved := a.runtime.currentMain == a && a.runtime.attachedMain == a &&
		a.runtime.mux == mux && a.runtime.muxGeneration == generation && a.runtime.pendingMainTransitions == 0
	a.runtime.mu.Unlock()
	if !preserved {
		t.Fatal("unknown observation discarded healthy prior state")
	}
	gateway.runtimeMu.Lock()
	accounted := entry.refs == 2 && entry.byKind[legacyRuntimeLeaseTransition] == 0 &&
		entry.byKind[legacyRuntimeLeaseSession] == 1 && entry.byKind[legacyRuntimeLeaseChan] == 1
	gateway.runtimeMu.Unlock()
	if !accounted {
		t.Fatal("failed candidate leaked leases")
	}
	proveRegisteredMainStream(t, ctx, a, peer)
	_ = aConn.Close()
	waitDone(t, ctx, aDone, nil)
	waitDone(t, ctx, chanDone, nil)
	assertRegistrationReleased(t, gateway, entry)
}

func TestFailedAttachKnownAndUnknownObservationsCleanOrphans(t *testing.T) {
	for _, mode := range []string{"unknown_dead", "known_none", "known_different"} {
		t.Run(mode, func(t *testing.T) {
			gateway := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
			aTransition, aLease := gateway.acquireMainRuntime("device-1")
			runtime := aLease.Runtime()
			aServer, aPeer := net.Pipe()
			defer aPeer.Close()
			a := newSession("a", "device-1", aServer, nil, runtime, aLease)
			defer a.Close(context.Background())
			runtime.publishMainCandidate(a)
			if ok, err := runtime.commitAttachedMain(context.Background(), a, a); !ok || err != nil {
				t.Fatalf("commit: %v", err)
			}
			if err := aTransition.Release(); err != nil {
				t.Fatal(err)
			}
			chanLease := gateway.acquireRuntime("device-1", legacyRuntimeLeaseChan)
			mux, peer := newRuntimeTestMux(t)
			defer peer.Close()
			defer mux.Close()
			if _, _, err := runtime.installMux(mux); err != nil {
				t.Fatal(err)
			}
			bTransition, bLease := gateway.acquireMainRuntime("device-1")
			bServer, bPeer := net.Pipe()
			defer bPeer.Close()
			b := newSession("b", "device-1", bServer, nil, runtime, bLease)
			defer b.Close(context.Background())
			prior, attached, ok := runtime.publishMainCandidate(b)
			if !ok {
				t.Fatal("candidate publication failed")
			}
			var observed managerObservation
			switch mode {
			case "unknown_dead":
				a.lifecycleCancel()
				observed = observeManager(nil, context.DeadlineExceeded)
			case "known_none":
				observed = observeManager(nil, session.ErrNoCurrentSession)
			case "known_different":
				observed = observeManager(testutil.NewFakeSession("kap", "device-1"), nil)
			}
			detached, err := runtime.reconcileFailedAttach(b, prior, attached, observed)
			if err != nil || detached != mux {
				t.Fatalf("orphan reconciliation = (%p, %v)", detached, err)
			}
			runtime.mu.Lock()
			invalid := runtime.currentMain != nil || runtime.pendingMainTransitions != 0 || runtime.hasMainInterestLocked()
			runtime.mu.Unlock()
			if invalid {
				t.Fatal("stale prior main was restored")
			}
			_ = detached.Close()
			_ = b.Close(context.Background())
			if err := bTransition.Release(); err != nil {
				t.Fatal(err)
			}
			_ = a.Close(context.Background())
			if err := chanLease.Release(); err != nil {
				t.Fatal(err)
			}
			assertRegistrationReleased(t, gateway, bLease.entry)
		})
	}
}

func TestManagerObservationClassification(t *testing.T) {
	current := testutil.NewFakeSession("current", "device")
	for _, tc := range []struct {
		current session.AgentSession
		err     error
		want    managerObservationKind
	}{
		{current, nil, managerKnownCurrent},
		{nil, fmt.Errorf("wrapped: %w", session.ErrNoCurrentSession), managerKnownNone},
		{nil, context.DeadlineExceeded, managerUnknown},
		{current, context.Canceled, managerUnknown},
		{nil, errors.New("query failure"), managerUnknown},
		{nil, nil, managerUnknown},
	} {
		got := observeManager(tc.current, tc.err)
		if got.kind != tc.want {
			t.Fatalf("observation = %v, want %v", got.kind, tc.want)
		}
		if got.kind != managerKnownCurrent && got.current != nil {
			t.Fatal("unknown observation retained an unverified session")
		}
	}
}
