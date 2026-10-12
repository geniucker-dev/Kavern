package agent_v1

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"testing"
)

func TestOwnedCredentialRotationRejectsPendingProofAndRetiresPublishedSession(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "rotation-before-publication", false: "publication-before-rotation"}[before], func(t *testing.T) {
			ctx := context.Background()
			owner, svc, manager, secret := syncOwnedFixture(t)
			reached, release := make(chan struct{}), make(chan struct{})
			if before {
				svc.newSessionID = func() (domain.SessionID, error) { close(reached); <-release; return GenerateSessionID() }
			}
			nonce := mustNonce(t)
			challenge, e := svc.BeginSyncAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}, ConfigSyncVersion)
			if e != nil {
				t.Fatal(e)
			}
			proof, e := SignSyncAuthResponse(secret, "device-1", nonce, challenge.ServerNonce, ConfigSyncVersion)
			if e != nil {
				t.Fatal(e)
			}
			result := make(chan error, 1)
			go func() {
				_, e := svc.CompleteSyncAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: proof}, ConfigSyncVersion)
				result <- e
			}()
			if before {
				revocationBarrier(t, reached)
			} else if e = awaitSync(t, result); e != nil {
				t.Fatal(e)
			}
			w, e := owner.ManagementWindow(ctx)
			if e != nil {
				t.Fatal(e)
			}
			c, e := owner.DeviceConfiguration(ctx, "device-1")
			if e != nil {
				t.Fatal(e)
			}
			r, e := owner.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "rotate-proof", Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: c.Revision, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}, nil)
			if e != nil || r.Credential == "" {
				t.Fatal("rotation failed", e)
			}
			if before {
				close(release)
				if e = awaitSync(t, result); e == nil {
					t.Fatal("old pending proof authenticated")
				}
			}
			if _, e = manager.CurrentForDevice(ctx, "device-1"); !errors.Is(e, session.ErrNoCurrentSession) {
				t.Fatal("rotated session remains current", e)
			}
			svc.registry.mu.Lock()
			n := len(svc.registry.byID)
			svc.registry.mu.Unlock()
			if n != 0 {
				t.Fatal("rotated registry leaked")
			}
		})
	}
}
