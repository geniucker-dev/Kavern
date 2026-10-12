package agent_v1

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func TestLifecycleCanceledOperationKeepsCurrentLease(t *testing.T) {
	owner, service, manager, secret := syncOwnedFixture(t)
	ctx := context.Background()
	id := domain.SessionID(mustNonce(t))
	current := newAgentSession(id, "device-1")
	interest, err := owner.AuthenticatePublication(ctx, "device-1", func(domain.Device, []byte) error {
		_, err := manager.Publish(ctx, current)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewOwnedLifecycleAuthority(&service.registrationMu, owner, manager, LifecycleScope{"device-1", id}, interest.Context)
	if err != nil {
		t.Fatal(err)
	}
	clock := newLifecycleFakeClock()
	finish := lifecycleFrame("auth_finish", "device-1", "")
	finish.ClientNonce, finish.ServerNonce, finish.ChallengeID = mustNonce(t), mustNonce(t), mustNonce(t)
	finish.LeaseMillis, finish.ProofMillis = LifecycleLeaseMillis, LifecycleAuthMillis
	finish, err = SignLifecycleFrame(secret, finish)
	if err != nil {
		t.Fatal(err)
	}
	var cleanups atomic.Int32
	lease, _, err := NewServerLease(ctx, LifecycleScope{"device-1", id}, finish, authority, clock, func() {
		cleanups.Add(1)
		_ = current.Close(ctx)
		_ = manager.Detach(ctx, id)
		interest.Finish()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Revoke(nil) })
	operation, cancel := context.WithCancel(ctx)
	cancel()
	if err = lease.Valid(operation); !errors.Is(err, context.Canceled) {
		t.Fatalf("wrong operation error: %v", err)
	}
	if cleanups.Load() != 0 {
		t.Fatalf("one canceled operation retired the whole current lease: cleanups=%d", cleanups.Load())
	}
	if err = lease.Valid(ctx); err != nil {
		t.Fatalf("live authority no longer usable: %v", err)
	}
}

func TestLifecycleRetainedChallengeNonceMismatchIsTerminal(t *testing.T) {
	server, clock, authority, finish, initial := serverLifecycleFixture(t)
	client, err := NewClientLease(context.Background(), finish, initial, clock.Now(), authority.secret, clock, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Revoke(nil) })
	clock.Advance(30 * time.Second)
	challenge, err := server.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := client.Challenge(*challenge)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := server.AcceptProof(context.Background(), *proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Grant(*grant); err != nil {
		t.Fatal(err)
	}
	bad := *challenge
	bad.Nonce = mustNonce(t)
	_, err = client.Challenge(bad)
	if !errors.Is(err, ErrLifecycle) || client.Valid() == nil {
		t.Fatalf("retained-generation nonce mismatch treated as forgotten stale state: challenge error=%v", err)
	}
}
func TestLifecycleCanceledOperationsPreserveTimersAndRenewals(t *testing.T) {
	lease, clock, authority, _, _ := serverLifecycleFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	generation := lease.Generation()
	ticket := lease.ticket
	for _, call := range []func() error{func() error { return lease.Valid(ctx) }, func() error { _, e := lease.Poll(ctx); return e }} {
		if e := call(); !errors.Is(e, context.Canceled) {
			t.Fatal("wrong operation cancellation", e)
		}
	}
	if lease.Generation() != generation || lease.ticket != ticket || clock.active() != 1 {
		t.Fatal("canceled operation changed current lifetime")
	}
	clock.Advance(30 * time.Second)
	challenge, e := lease.Poll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	proof := lifecycleProof(t, *challenge, authority.secret)
	if _, e = lease.AcceptProof(ctx, proof); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if lease.Generation() != generation || lease.pending == nil {
		t.Fatal("canceled proof changed lifetime")
	}
	if _, e = lease.AcceptProof(context.Background(), proof); e != nil {
		t.Fatal("healthy renewal unavailable", e)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if e = lease.Valid(deadline); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("operation deadline error", e)
	}
	if e = lease.Valid(context.Background()); e != nil {
		t.Fatal("one open timeout killed shared session", e)
	}
}
func TestLifecycleCanceledOperationStillObservesIndependentRevocationAndExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked", true: "expired"}[expired], func(t *testing.T) {
			lease, clock, authority, _, _ := serverLifecycleFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if expired {
				clock.Advance(90 * time.Second)
			} else {
				authority.mu.Lock()
				authority.valid = false
				authority.mu.Unlock()
			}
			if e := lease.Valid(ctx); e == nil || errors.Is(e, context.Canceled) {
				t.Fatal("caller cancellation hid terminal authority", e)
			}
			select {
			case <-lease.Done():
			default:
				t.Fatal("terminal cleanup not complete")
			}
		})
	}
}
func TestLifecycleRetainedChallengeExactMatchVersusForgottenQuota(t *testing.T) {
	server, clock, authority, finish, initial := serverLifecycleFixture(t)
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), authority.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	clock.Advance(30 * time.Second)
	challenge, e := server.Poll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	proof, e := client.Challenge(*challenge)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := server.AcceptProof(context.Background(), *proof)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Grant(*grant); e != nil {
		t.Fatal(e)
	}
	expiry := client.expiry
	if _, e = client.Challenge(*challenge); !errors.Is(e, ErrLifecycleStale) {
		t.Fatal("exact retained challenge duplicate", e)
	}
	if e = client.Valid(); e != nil || !client.expiry.Equal(expiry) {
		t.Fatal("retained duplicate extended/terminated", e)
	}
	clock.Advance(30 * time.Second)
	next, e := server.Poll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	proof, e = client.Challenge(*next)
	if e != nil {
		t.Fatal(e)
	}
	grant, e = server.AcceptProof(context.Background(), *proof)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Grant(*grant); e != nil {
		t.Fatal(e)
	}
	forgotten := *challenge
	forgotten.Nonce = mustNonce(t)
	if _, e = client.Challenge(forgotten); !errors.Is(e, ErrLifecycleStale) {
		t.Fatal("forgotten challenge matched against retained history", e)
	}
	if e = client.Valid(); e != nil {
		t.Fatal(e)
	}
}
