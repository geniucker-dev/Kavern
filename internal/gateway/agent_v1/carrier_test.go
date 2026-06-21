package agent_v1

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func TestBindCarrierRejectsUnknownSessionIDAloneMissingAndInvalidHMAC(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	unknownID := domain.SessionID(mustNonce(t))
	nonce := mustNonce(t)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: unknownID, CarrierNonce: nonce, ResponseHMAC: strings.Repeat("0", 64)}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("BindCarrier(unknown) error = %v, want ErrSessionNotFound", err)
	}

	result, secret := authenticate(t, svc)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("BindCarrier(session id alone) error = %v, want ErrInvalidInput", err)
	}
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("BindCarrier(missing HMAC) error = %v, want ErrInvalidInput", err)
	}
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: strings.Repeat("0", 64)}); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("BindCarrier(invalid HMAC) error = %v, want ErrAuthFailed", err)
	}
	valid := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: valid}); err != nil {
		t.Fatalf("BindCarrier(valid after invalid HMAC) error = %v", err)
	}
}

func TestBindCarrierValidOnceAndReplayFails(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)
	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	req := CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}

	if _, err := svc.BindCarrier(ctx, req); err != nil {
		t.Fatalf("BindCarrier(first) error = %v", err)
	}
	if _, err := svc.BindCarrier(ctx, req); !errors.Is(err, ErrCarrierNonceReplay) {
		t.Fatalf("BindCarrier(replay) error = %v, want ErrCarrierNonceReplay", err)
	}
}

func TestBindCarrierRejectsReplacedClosedAndDisabledDevice(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newAuthFixture(t, true)
	oldResult, oldSecret := authenticate(t, svc)
	_, _ = authenticate(t, svc)
	oldNonce := mustNonce(t)
	oldHMAC := mustCarrierHMAC(t, oldSecret, oldResult.SessionID, oldResult.DeviceID, oldNonce)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: oldResult.SessionID, CarrierNonce: oldNonce, ResponseHMAC: oldHMAC}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("BindCarrier(replaced) error = %v, want ErrSessionNotFound", err)
	}

	activeResult, activeSecret := authenticate(t, svc)
	if err := svc.CloseSession(ctx, activeResult.SessionID); err != nil {
		t.Fatalf("CloseSession() error = %v", err)
	}
	closedNonce := mustNonce(t)
	closedHMAC := mustCarrierHMAC(t, activeSecret, activeResult.SessionID, activeResult.DeviceID, closedNonce)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: activeResult.SessionID, CarrierNonce: closedNonce, ResponseHMAC: closedHMAC}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("BindCarrier(closed) error = %v, want ErrSessionNotFound", err)
	}

	disabledSvc := NewAuthService(st, session.NewManager())
	disabledResult, disabledSecret := authenticateWithExistingSecret(t, disabledSvc, activeSecret)
	_ = st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: false})
	disabledNonce := mustNonce(t)
	disabledHMAC := mustCarrierHMAC(t, disabledSecret, disabledResult.SessionID, disabledResult.DeviceID, disabledNonce)
	if _, err := disabledSvc.BindCarrier(ctx, CarrierBindRequest{SessionID: disabledResult.SessionID, CarrierNonce: disabledNonce, ResponseHMAC: disabledHMAC}); !errors.Is(err, store.ErrDisabledDevice) {
		t.Fatalf("BindCarrier(disabled) error = %v, want ErrDisabledDevice", err)
	}
}

func TestCloseSessionDetachesCurrentSessionAndRemovesCarrierBinding(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)

	if err := svc.CloseSession(ctx, result.SessionID); err != nil {
		t.Fatalf("CloseSession() error = %v", err)
	}
	if _, err := svc.sessions.CurrentForDevice(ctx, result.DeviceID); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("CurrentForDevice() error = %v, want ErrNoCurrentSession", err)
	}
	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("BindCarrier(closed) error = %v, want ErrSessionNotFound", err)
	}
}

func authenticate(t *testing.T, svc *AuthService) (AuthResult, []byte) {
	t.Helper()
	return authenticateWithExistingSecret(t, svc, []byte("device-secret"))
}

func authenticateWithExistingSecret(t *testing.T, svc *AuthService, secret []byte) (AuthResult, []byte) {
	t.Helper()
	ctx := context.Background()
	clientNonce := mustNonce(t)
	challenge, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	response := mustAuthResponse(t, secret, "device-1", clientNonce, challenge.ServerNonce)
	result, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response})
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	return result, secret
}

func mustCarrierHMAC(t *testing.T, secret []byte, sessionID domain.SessionID, deviceID domain.DeviceID, nonce string) string {
	t.Helper()
	response, err := SignCarrierBind(secret, sessionID, deviceID, nonce, ProtocolVersion, TransportRoleDataCarrier)
	if err != nil {
		t.Fatalf("SignCarrierBind() error = %v", err)
	}
	return response
}
