package agent_v1

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func TestLifecycleReviewRegressionFinishMustBelongToThisTransport(t *testing.T) {
	owner, svc, _, secret := syncOwnedFixture(t)
	serverTrust, clientTrust, _ := syncTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	foreignStart := lifecycleFrame("auth_start", "device-1", "")
	foreignStart.ClientNonce = mustNonce(t)
	foreign, err := svc.beginLifecycleAuth(ctx, foreignStart)
	if err != nil {
		t.Fatal(err)
	}
	finish := foreign
	finish.Type = "auth_finish"
	finish, err = SignLifecycleFrame(secret, finish)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	server := tls.Server(left, serverTrust)
	client := tls.Client(right, clientTrust)
	joined := make(chan struct{})
	go func() { defer close(joined); _ = svc.ServeSyncTransport(ctx, server, owner, nil) }()
	t.Cleanup(func() {
		cancel()
		_ = left.Close()
		_ = right.Close()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("transport did not join")
		}
	})
	if err = client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	localStart := lifecycleFrame("auth_start", "device-1", "")
	localStart.ClientNonce = mustNonce(t)
	if err = WriteLifecycleFrame(client, localStart); err != nil {
		t.Fatal(err)
	}
	local, err := ReadLifecycleFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if local.ChallengeID == foreign.ChallengeID {
		t.Fatal("fixture exchanges collided")
	}
	if err = WriteLifecycleFrame(client, finish); err != nil {
		t.Fatal(err)
	}
	grant, err := ReadLifecycleFrame(client)
	if err == nil && grant.Type == "auth_ok" {
		t.Fatal("transport authenticated a different exchange instead of rejecting its mismatched finish")
	}
	svc.challengesMu.Lock()
	_, foreignRetained := svc.challenges[foreign.ChallengeID]
	svc.challengesMu.Unlock()
	if !foreignRetained {
		t.Fatal("mismatched transport consumed another exchange")
	}

}

func TestLifecycleReviewRegressionCanceledInitialCompletionDetachesPublishedSession(t *testing.T) {
	backend := &blockedPredecessorBackend{entered: make(chan struct{}), release: make(chan struct{})}
	owner, old, _ := ownedReady(t, backend)
	svc := old.syncController().service
	svc.lifecycleClock = newLifecycleFakeClock()
	_, secret, err := owner.ResolveKAPv1DeviceForAuth(context.Background(), old.DeviceID())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	start := lifecycleFrame("auth_start", old.DeviceID(), "")
	start.ClientNonce = mustNonce(t)
	challenge, err := svc.beginLifecycleAuth(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	finish := challenge
	finish.Type = "auth_finish"
	finish, err = SignLifecycleFrame(secret, finish)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	release := func() { once.Do(func() { close(backend.release) }) }
	completed := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); _, _, err := svc.completeLifecycleAuth(ctx, finish); completed <- err }()
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("authentication did not join")
		}
	})
	revocationBarrier(t, backend.entered)
	current, err := svc.sessions.CurrentForDevice(context.Background(), old.DeviceID())
	if err != nil || current.ID() == old.ID() {
		t.Fatal("replacement did not publish")
	}
	cancel()
	release()
	select {
	case err = <-completed:
	case <-time.After(time.Second):
		t.Fatal("completion did not return")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled completion: %v", err)
	}
	if _, err = svc.sessions.CurrentForDevice(context.Background(), old.DeviceID()); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatal("failed initial authentication retained its newly published current session")
	}
	if _, ok := svc.registry.lookup(current.ID()); ok {
		t.Fatal("failed authentication retained a registry entry")
	}
}

func TestLifecycleReviewRegressionStartupRejectsNewEnvelopeOverflow(t *testing.T) {
	ctx := context.Background()
	device := domain.DeviceID(strings.Repeat("d", 128))
	auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: device, SessionID: domain.SessionID(mustNonce(t)), ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: 1}
	snapshot := domain.NativeSnapshot{DeviceID: device, Revision: 1, Policy: domain.DefaultNativePolicy()}
	for i := 0; i < config.MaxNativeTunnels; i++ {
		snapshot.Tunnels = append(snapshot.Tunnels, domain.NativeTunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i) + strings.Repeat("x", 123)), Protocol: domain.TunnelProtocolTCP})
	}
	found := false
	for length := 360; length <= 510; length++ {
		for i := range snapshot.Tunnels {
			snapshot.Tunnels[i].TargetAddr = strings.Repeat("a", length-2) + ":1"
		}
		p := &syncPlan{tuple: syncTuple{auth.DeviceID, auth.SessionID, 1, 1}, snapshot: snapshot, total: MaxSyncTransferBytes}
		measure := func(life int) int {
			begin, _ := encodeNegotiatedSyncPayload(p.frame(0), life)
			entry, _ := encodeNegotiatedSyncPayload(p.frame(1), life)
			end, _ := encodeNegotiatedSyncPayload(p.frame(p.frames()-1), life)
			return len(begin) + len(end) + len(entry)*len(snapshot.Tunnels) + 1962
		}
		if measure(0) > MaxSyncTransferBytes || measure(1) <= MaxSyncTransferBytes {
			continue
		}
		old, err := newSyncPlan(auth, snapshot, 1)
		if err != nil {
			t.Fatal("measured old plan does not fit", err)
		}
		renewable := auth
		renewable.LifecycleVersion = 1
		if _, err = newSyncPlan(renewable, snapshot, 1); errors.Is(err, ErrSyncCapacity) {
			t.Logf("old transfer=%d bytes fits; lifecycle envelopes exceed bound at target length=%d", old.total, length)
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no valid envelope expansion fixture found")
	}
	if err := config.ValidateNativeSnapshot(snapshot); err != nil {
		t.Fatal("invalid projected fixture", err)
	}
	s := store.NewMemoryStore()
	for _, err := range []error{s.CreateUser(ctx, domain.User{ID: "u"}), s.CreateProject(ctx, domain.Project{ID: "p", UserID: "u"}), s.CreateDevice(ctx, domain.Device{ID: device, ProjectID: "p", Enabled: true}), s.SetKAPv1DeviceSecret(ctx, device, bytes.Repeat([]byte{0x33}, 32))} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, tunnel := range snapshot.Tunnels {
		if err := s.CreateTunnel(ctx, domain.Tunnel{ID: tunnel.ID, DeviceID: device, Protocol: tunnel.Protocol, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 10000+i)), TargetAddr: tunnel.TargetAddr, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "private", "state.json")
	key := bytes.Repeat([]byte{0x44}, 32)
	if err := s.SaveState(path, key); err != nil {
		t.Fatal("fixture cannot be persisted", err)
	}
	owner, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = owner.ValidateNativeStartup(ctx); err == nil {
		t.Fatal("command startup accepted durable state that cannot fit lifecycle-v1 transfer envelopes")
	}
}

func TestLifecycleReviewRegressionReadySnapshotRejectsExpiredClientAuthority(t *testing.T) {
	for _, kind := range []string{"revoked", "expiry-before-timer-callback"} {
		t.Run(kind, func(t *testing.T) {
			owner, _, _, receiver, clock := lifecycleControlFixture(t)
			snapshot, err := owner.NativeSnapshot(context.Background(), receiver.auth.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			receiver.mu.Lock()
			receiver.applied = snapshot
			receiver.lastTransfer = 1
			receiver.ready = receiver.currentTupleLocked()
			for i := 0; i < snapshot.Policy.Carriers; i++ {
				receiver.carriers[&SyncClientCarrier{carrier: &carrier.Carrier{}}] = struct{}{}
			}
			receiver.mu.Unlock()
			t.Cleanup(func() { receiver.mu.Lock(); clear(receiver.carriers); receiver.mu.Unlock() })
			if _, ok := receiver.ReadySnapshot(); !ok {
				t.Fatal("fixture was not ready")
			}
			cleaned := make(chan struct{})
			receiver.lifecycle.cleanup = func() {
				receiver.lifecycle.mu.Lock()
				receiver.lifecycle.mu.Unlock()
				receiver.mu.Lock()
				receiver.mu.Unlock()
				close(cleaned)
			}
			if kind == "revoked" {
				receiver.lifecycle.Revoke(ErrLifecycleExpired)
			} else {
				// Model an already-expired monotonic clock with its scheduler callback late.
				// Observation must check authority itself, and release both guards before cleanup.
				clock.mu.Lock()
				clock.now = clock.now.Add(lifecycleDuration)
				clock.mu.Unlock()
			}
			if _, ok := receiver.ReadySnapshot(); ok {
				t.Fatal("ReadySnapshot reported expired authority before dispatcher cleanup")
			}
			select {
			case <-cleaned:
			case <-time.After(time.Second):
				t.Fatal("observation cleanup did not run outside both guards")
			}
			if _, ok := receiver.Snapshot(); ok {
				t.Fatal("snapshot observation retained expired authority")
			}
		})
	}
}

func TestLifecycleDeliveryCapacityReservesMaximumCounterEnvelopes(t *testing.T) {
	for _, count := range []int{0, 1, 128, 1024} {
		for _, targetBytes := range []int{360, 460, 461, 512} {
			snapshot := domain.NativeSnapshot{DeviceID: domain.DeviceID(strings.Repeat("d", 128)), Revision: domain.ConfigRevision(^uint64(0)), Policy: domain.NativePolicy{Carriers: 4, MaxStreams: 1024, MaxInflight: 16 << 20, MaxBuffer: 64 << 20}}
			for i := 0; i < count; i++ {
				snapshot.Tunnels = append(snapshot.Tunnels, domain.NativeTunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i) + strings.Repeat("x", 123)), Protocol: domain.TunnelProtocolTCP, TargetAddr: strings.Repeat("a", targetBytes-2) + ":1"})
			}
			if e := config.ValidateNativeSnapshot(snapshot); e != nil {
				t.Fatal(e)
			}
			auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: snapshot.DeviceID, SessionID: domain.SessionID(mustNonce(t)), ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: 1, LifecycleVersion: 1}
			if config.ValidateNativeDeliveryCapacity(snapshot) == nil {
				plan, e := newSyncPlan(auth, snapshot, domain.ConfigRevision(^uint64(0)))
				if e != nil {
					t.Fatalf("accepted delivery capacity cannot send maximum-width counters: count=%d target=%d: %v", count, targetBytes, e)
				}
				if plan.total > MaxSyncTransferBytes {
					t.Fatal("accepted projection exceeds transfer bound")
				}
			}
			if count == 1024 {
				accepted := config.ValidateNativeDeliveryCapacity(snapshot) == nil
				if accepted != (targetBytes <= 460) {
					t.Fatalf("worst-width reservation boundary changed: target=%d accepted=%v", targetBytes, accepted)
				}
			}
		}
	}
}
