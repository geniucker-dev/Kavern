package agent_v1

import (
	"context"
	"errors"
	"testing"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func syncAuthFixture(t *testing.T, s *AuthService, secret []byte) SyncAuthResult {
	t.Helper()
	nonce := mustNonce(t)
	challenge, err := s.BeginSyncAuth(context.Background(), AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}, ConfigSyncVersion)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ConfigSyncVersion != ConfigSyncVersion {
		t.Fatal("schema not selected")
	}
	response, err := SignSyncAuthResponse(secret, "device-1", nonce, challenge.ServerNonce, challenge.ConfigSyncVersion)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := s.CompleteSyncAuth(context.Background(), AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}, ConfigSyncVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.CloseSession(context.Background(), auth.SessionID) })
	return auth
}
func TestSyncAuthSchemaBindingAndNoLegacyDowngrade(t *testing.T) {
	ctx := context.Background()
	svc, _, secret := newAuthFixture(t, true)
	for _, version := range []int{0, 2} {
		if _, err := svc.BeginSyncAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: mustNonce(t)}, version); !errors.Is(err, ErrSyncSchema) {
			t.Fatal("unsupported schema accepted", err)
		}
	}
	for _, legacyFinish := range []bool{false, true} {
		nonce := mustNonce(t)
		challenge, err := svc.BeginSyncAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}, ConfigSyncVersion)
		if err != nil {
			t.Fatal(err)
		}
		response := mustAuthResponse(t, secret, "device-1", nonce, challenge.ServerNonce)
		request := AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}
		if legacyFinish {
			if _, err = svc.CompleteAuth(ctx, request); !errors.Is(err, ErrSyncSchema) {
				t.Fatal("sync challenge downgraded", err)
			}
		} else {
			if _, err = svc.CompleteSyncAuth(ctx, request, ConfigSyncVersion); !errors.Is(err, ErrAuthFailed) {
				t.Fatal("legacy HMAC authenticated sync", err)
			}
		}
	}
	auth := syncAuthFixture(t, svc, secret)
	current, err := svc.sessions.CurrentForDevice(ctx, auth.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = current.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("core-only sync session routable", err)
	}
	nonce := mustNonce(t)
	oldProof, err := SignCarrierBind(secret, auth.SessionID, auth.DeviceID, nonce, ProtocolVersion, TransportRoleDataCarrier)
	if err != nil {
		t.Fatal(err)
	}
	request := CarrierBindRequest{SessionID: auth.SessionID, CarrierNonce: nonce, ResponseHMAC: oldProof}
	if _, err = svc.BindCarrier(ctx, request); !errors.Is(err, ErrSyncSchema) {
		t.Fatal("legacy carrier attached to sync session", err)
	}
	if _, err = svc.BindSyncCarrier(ctx, request, ConfigSyncVersion); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("carrier schema not in HMAC", err)
	}
	request.ResponseHMAC, err = SignSyncCarrierBind(secret, auth.SessionID, auth.DeviceID, nonce, ConfigSyncVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.BindSyncCarrier(ctx, request, ConfigSyncVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.BindSyncCarrier(ctx, request, ConfigSyncVersion); !errors.Is(err, ErrCarrierNonceReplay) {
		t.Fatal("sync carrier nonce replay accepted", err)
	}
	if err = VerifyCarrierBind(secret, request.ResponseHMAC, auth.SessionID, auth.DeviceID, nonce, ProtocolVersion, TransportRoleDataCarrier); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("sync HMAC valid in legacy native mode", err)
	}
}

func TestSyncAuthorityRejectsDisabledExpiredReplacedAndNonSyncSessions(t *testing.T) {
	ctx := context.Background()
	svc, st, secret := newAuthFixture(t, true)
	auth := syncAuthFixture(t, svc, secret)
	if err := svc.withSyncSession(ctx, auth, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	device, err := st.GetDevice(ctx, auth.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	device.Enabled = false
	_ = st.CreateDevice(ctx, device)
	if err = svc.withSyncSession(ctx, auth, func() error { t.Fatal("disabled publication callback ran"); return nil }); err == nil {
		t.Fatal("disabled session accepted")
	}
	device.Enabled = true
	_ = st.CreateDevice(ctx, device)
	newAuth := syncAuthFixture(t, svc, secret)
	if err = svc.withSyncSession(ctx, auth, func() error { t.Fatal("superseded callback ran"); return nil }); err == nil {
		t.Fatal("replaced session accepted")
	}
	entry, _ := svc.registry.lookup(newAuth.SessionID)
	entry.session.expiresAt = svc.now()
	if err = svc.withSyncSession(ctx, newAuth, func() error { t.Fatal("expired callback ran"); return nil }); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("expired sync session accepted", err)
	}
}
