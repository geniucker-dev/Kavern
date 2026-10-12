package agent_v1

import (
	"bytes"
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
	"sync"
	"testing"
	"time"
)

func TestLifecycleOwnedAuthorityRechecksPublicationAndCleansOutsideGuards(t *testing.T) {
	for _, kind := range []string{"rotate", "delete", "disable", "policy", "replace"} {
		t.Run(kind, func(t *testing.T) {
			owner, svc, manager, secret := syncOwnedFixture(t)
			ctx := context.Background()
			id := domain.SessionID(mustNonce(t))
			current := newAgentSession(id, "device-1")
			interest, e := owner.AuthenticatePublication(ctx, "device-1", func(domain.Device, []byte) error { _, e := manager.Publish(ctx, current); return e })
			if e != nil {
				t.Fatal(e)
			}
			authority, e := NewOwnedLifecycleAuthority(&svc.registrationMu, owner, manager, LifecycleScope{"device-1", id}, interest.Context)
			if e != nil {
				t.Fatal(e)
			}
			clock := newLifecycleFakeClock()
			finish := lifecycleFrame("auth_finish", "device-1", "")
			finish.ClientNonce = mustNonce(t)
			finish.ServerNonce = mustNonce(t)
			finish.ChallengeID = mustNonce(t)
			finish.LeaseMillis = LifecycleLeaseMillis
			finish.ProofMillis = LifecycleAuthMillis
			finish, e = SignLifecycleFrame(secret, finish)
			if e != nil {
				t.Fatal(e)
			}
			cleaned := make(chan struct{})
			lease, _, e := NewServerLease(ctx, LifecycleScope{"device-1", id}, finish, authority, clock, func() {
				// Acquiring both guards would deadlock if cleanup ran under publication.
				svc.registrationMu.Lock()
				svc.registrationMu.Unlock()
				_ = owner.ChangeSignal()
				current.Close(ctx)
				manager.Detach(ctx, id)
				interest.Finish()
				close(cleaned)
			})
			if e != nil {
				t.Fatal(e)
			}
			defer lease.Revoke(nil)
			clock.Advance(30 * time.Second)
			challenge, e := lease.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			proof := lifecycleProof(t, *challenge, secret)
			c, e := owner.DeviceConfiguration(ctx, "device-1")
			if e != nil {
				t.Fatal(e)
			}
			w, e := owner.ManagementWindow(ctx)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "rotate":
				_, e = owner.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "rotate", Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: c.Revision, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}, nil)
			case "delete":
				_, e = owner.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "delete", Kind: "delete_device", DeviceID: "device-1", ExpectedRevision: c.Revision, Cascade: true}, nil)
			case "disable":
				c.Device.Enabled = false
				_, e = owner.Commit(ctx, []domain.DeviceConfiguration{c})
			case "policy":
				c.Policy.Carriers = 3
				_, e = owner.Commit(ctx, []domain.DeviceConfiguration{c})
			case "replace":
				next := newAgentSession(domain.SessionID(mustNonce(t)), "device-1")
				svc.registrationMu.Lock()
				_, e = manager.Publish(ctx, next)
				svc.registrationMu.Unlock()
				defer next.Close(ctx)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = lease.AcceptProof(ctx, proof); e == nil {
				t.Fatal("stale authority renewed")
			}
			select {
			case <-cleaned:
			case <-time.After(time.Second):
				t.Fatal("terminal cleanup not joined")
			}
			if clock.active() != 0 {
				t.Fatal("revoked timer retained")
			}
		})
	}
}
func TestLifecycleCredentialRecheckRejectsDuplicateAndPendingWithoutContextNotification(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "receipt"}[duplicate], func(t *testing.T) {
			lease, clock, a, _, _ := serverLifecycleFixture(t)
			clock.Advance(30 * time.Second)
			f, _ := lease.Poll(context.Background())
			proof := lifecycleProof(t, *f, a.secret)
			if duplicate {
				if _, e := lease.AcceptProof(context.Background(), proof); e != nil {
					t.Fatal(e)
				}
			}
			a.mu.Lock()
			a.secret = bytes.Repeat([]byte{0x77}, 32)
			a.mu.Unlock()
			if _, e := lease.AcceptProof(context.Background(), proof); !errors.Is(e, ErrAuthFailed) {
				t.Fatal("current credential not checked", e)
			}
		})
	}
}
func TestLifecycleConstructorCanceledInterestAndConcurrentTimerRevoke(t *testing.T) {
	for i := 0; i < 50; i++ {
		clock, a, finish := lifecycleFixture(t)
		a.cancel()
		if _, _, e := NewServerLease(context.Background(), a.scope, finish, a, clock, func() {}); e == nil {
			t.Fatal("canceled owner constructed")
		}
	}
	lease, clock, _, _, _ := serverLifecycleFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); clock.Advance(90 * time.Second); lease.Revoke(nil) }()
	}
	wg.Wait()
	select {
	case <-lease.Done():
	default:
		t.Fatal("timer/revoke cleanup incomplete")
	}
}
