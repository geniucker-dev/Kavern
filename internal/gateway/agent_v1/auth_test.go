package agent_v1

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/session"
	"github.com/zhuhaoyu/kavern/internal/store"
)

func TestAuthValidChallengeResponseSucceeds(t *testing.T) {
	ctx := context.Background()
	svc, _, secret := newAuthFixture(t, true)
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
	if result.SessionID == "" || result.DeviceID != "device-1" || result.ProtocolVersion != ProtocolVersion {
		t.Fatalf("unexpected auth result: %+v", result)
	}
	current, err := svc.sessions.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	if current.ID() != result.SessionID || current.Protocol() != domain.AgentProtocolKAPv1 {
		t.Fatalf("current session does not match auth result")
	}
}

func TestAuthWrongHMACConsumesChallenge(t *testing.T) {
	ctx := context.Background()
	svc, _, secret := newAuthFixture(t, true)
	clientNonce := mustNonce(t)
	challenge, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}

	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: strings.Repeat("0", 64)}); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("CompleteAuth(wrong HMAC) error = %v, want ErrAuthFailed", err)
	} else if containsSecret(err, secret) {
		t.Fatalf("auth error includes device secret")
	}
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: strings.Repeat("0", 64)}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("CompleteAuth(reuse after failure) error = %v, want ErrChallengeNotFound", err)
	}
}

func TestAuthEmptyResponseHMACConsumesChallenge(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	challenge, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: mustNonce(t)})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CompleteAuth(empty HMAC) error = %v, want ErrInvalidInput", err)
	}
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: strings.Repeat("0", 64)}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("CompleteAuth(retry) error = %v, want ErrChallengeNotFound", err)
	}
}

func TestAuthUnknownAndDisabledDeviceFail(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	if _, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "missing", ClientNonce: mustNonce(t)}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BeginAuth(unknown) error = %v, want ErrNotFound", err)
	}

	disabledSvc, _, _ := newAuthFixture(t, false)
	if _, err := disabledSvc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: mustNonce(t)}); !errors.Is(err, store.ErrDisabledDevice) {
		t.Fatalf("BeginAuth(disabled) error = %v, want ErrDisabledDevice", err)
	}
}

func TestAuthChallengeUnknownExpiredAndReuse(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1000, 0)
	svc, _, secret := newAuthFixture(t, true, WithNow(func() time.Time { return now }), WithChallengeTTL(time.Minute))

	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: mustNonce(t), ResponseHMAC: strings.Repeat("0", 64)}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("CompleteAuth(unknown) error = %v, want ErrChallengeNotFound", err)
	}

	clientNonce := mustNonce(t)
	challenge, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	response := mustAuthResponse(t, secret, "device-1", clientNonce, challenge.ServerNonce)
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("CompleteAuth(expired) error = %v, want ErrChallengeExpired", err)
	}

	now = time.Unix(2000, 0)
	clientNonce = mustNonce(t)
	challenge, err = svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	response = mustAuthResponse(t, secret, "device-1", clientNonce, challenge.ServerNonce)
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}); err != nil {
		t.Fatalf("CompleteAuth(valid) error = %v", err)
	}
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("CompleteAuth(reuse) error = %v, want ErrChallengeNotFound", err)
	}
}

func TestAuthProtocolStructsAndChallengeStateDoNotExposeSecret(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(AuthStartRequest{}),
		reflect.TypeOf(AuthChallenge{}),
		reflect.TypeOf(AuthFinishRequest{}),
		reflect.TypeOf(AuthResult{}),
		reflect.TypeOf(CarrierBindRequest{}),
		reflect.TypeOf(CarrierBinding{}),
		reflect.TypeOf(challengeState{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(name, "secret") {
				t.Fatalf("%s exposes secret field %s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}

func TestAuthSessionIDCollisionDoesNotOverwrite(t *testing.T) {
	svc, _, _ := newAuthFixture(t, true)
	id := domain.SessionID(mustNonce(t))
	if err := svc.registry.reserve(id, newAgentSession(id, "device-1")); err != nil {
		t.Fatalf("reserve() error = %v", err)
	}
	if err := svc.registry.reserve(id, newAgentSession(id, "device-1")); !errors.Is(err, ErrSessionIDCollision) {
		t.Fatalf("reserve(collision) error = %v, want ErrSessionIDCollision", err)
	}
}

func TestCompleteAuthSessionIDCollisionFailsWithoutOverwrite(t *testing.T) {
	ctx := context.Background()
	collidingID := domain.SessionID(mustNonce(t))
	svc, _, secret := newAuthFixture(t, true, WithSessionIDGenerator(func() (domain.SessionID, error) {
		return collidingID, nil
	}))
	if err := svc.registry.reserve(collidingID, newAgentSession(collidingID, "device-1")); err != nil {
		t.Fatalf("reserve(existing) error = %v", err)
	}
	clientNonce := mustNonce(t)
	challenge, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	response := mustAuthResponse(t, secret, "device-1", clientNonce, challenge.ServerNonce)
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}); !errors.Is(err, ErrSessionIDCollision) {
		t.Fatalf("CompleteAuth(collision) error = %v, want ErrSessionIDCollision", err)
	}
}

func TestAuthReserveFailureAndAttachFailureRollback(t *testing.T) {
	ctx := context.Background()
	reserveFailSvc, _, secret := newAuthFixture(t, true, WithRegistryReserveFailure())
	clientNonce := mustNonce(t)
	challenge, err := reserveFailSvc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	response := mustAuthResponse(t, secret, "device-1", clientNonce, challenge.ServerNonce)
	if _, err := reserveFailSvc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}); !errors.Is(err, ErrRegistryReserve) {
		t.Fatalf("CompleteAuth(reserve failure) error = %v, want ErrRegistryReserve", err)
	}
	if _, err := reserveFailSvc.sessions.CurrentForDevice(ctx, "device-1"); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("CurrentForDevice after reserve failure = %v, want ErrNoCurrentSession", err)
	}

	manager := &failingSessionManager{SessionManager: session.NewManager(), failAttach: true}
	st, secret := newStoreFixture(t, true)
	attachFailSvc := NewAuthService(st, manager)
	clientNonce = mustNonce(t)
	challenge, err = attachFailSvc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonce})
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	response = mustAuthResponse(t, secret, "device-1", clientNonce, challenge.ServerNonce)
	if _, err := attachFailSvc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: response}); !errors.Is(err, errAttachFailed) {
		t.Fatalf("CompleteAuth(attach failure) error = %v, want errAttachFailed", err)
	}
	if len(attachFailSvc.registry.byID) != 0 {
		t.Fatalf("registry retained pending session after attach failure")
	}
}

func TestCompleteAuthConcurrentRegistrationKeepsRegistryAndSessionManagerConsistent(t *testing.T) {
	ctx := context.Background()
	manager := newBlockingAttachManager()
	st, secret := newStoreFixture(t, true)
	svc := NewAuthService(st, manager)

	clientNonceA := mustNonce(t)
	challengeA, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonceA})
	if err != nil {
		t.Fatalf("BeginAuth(A) error = %v", err)
	}
	responseA := mustAuthResponse(t, secret, "device-1", clientNonceA, challengeA.ServerNonce)

	clientNonceB := mustNonce(t)
	challengeB, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: clientNonceB})
	if err != nil {
		t.Fatalf("BeginAuth(B) error = %v", err)
	}
	responseB := mustAuthResponse(t, secret, "device-1", clientNonceB, challengeB.ServerNonce)

	manager.BlockNextAttach()
	resultCh := make(chan AuthResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challengeA.AuthChallengeID, ResponseHMAC: responseA})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	manager.WaitForBlockedAttach(t)

	doneB := make(chan struct{})
	var resultB AuthResult
	var errB error
	go func() {
		defer close(doneB)
		resultB, errB = svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challengeB.AuthChallengeID, ResponseHMAC: responseB})
	}()

	select {
	case <-doneB:
		t.Fatalf("CompleteAuth(B) completed while A registration was blocked")
	case <-time.After(50 * time.Millisecond):
	}

	manager.ReleaseBlockedAttach()

	var resultA AuthResult
	select {
	case err := <-errCh:
		t.Fatalf("CompleteAuth(A) error = %v", err)
	case resultA = <-resultCh:
	case <-time.After(time.Second):
		t.Fatalf("CompleteAuth(A) did not finish")
	}

	select {
	case <-doneB:
	case <-time.After(time.Second):
		t.Fatalf("CompleteAuth(B) did not finish")
	}
	if errB != nil {
		t.Fatalf("CompleteAuth(B) error = %v", errB)
	}

	nonceB := mustNonce(t)
	hmacB := mustCarrierHMAC(t, secret, resultB.SessionID, resultB.DeviceID, nonceB)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: resultB.SessionID, CarrierNonce: nonceB, ResponseHMAC: hmacB}); err != nil {
		t.Fatalf("BindCarrier(B current) error = %v", err)
	}

	nonceA := mustNonce(t)
	hmacA := mustCarrierHMAC(t, secret, resultA.SessionID, resultA.DeviceID, nonceA)
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: resultA.SessionID, CarrierNonce: nonceA, ResponseHMAC: hmacA}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("BindCarrier(A replaced) error = %v, want ErrSessionNotFound", err)
	}

	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	if current.ID() != resultB.SessionID {
		t.Fatalf("current session = %q, want bindable registry session %q", current.ID(), resultB.SessionID)
	}
}

func mustAuthResponse(t *testing.T, secret []byte, deviceID domain.DeviceID, clientNonce, serverNonce string) string {
	t.Helper()
	response, err := SignAuthResponse(secret, deviceID, clientNonce, serverNonce, ProtocolVersion, TransportRoleControl)
	if err != nil {
		t.Fatalf("SignAuthResponse() error = %v", err)
	}
	return response
}

type blockingAttachManager struct {
	session.SessionManager

	mu        sync.Mutex
	blockNext bool
	attached  chan struct{}
	release   chan struct{}
}

func newBlockingAttachManager() *blockingAttachManager {
	return &blockingAttachManager{SessionManager: session.NewManager()}
}

func (m *blockingAttachManager) BlockNextAttach() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockNext = true
	m.attached = make(chan struct{})
	m.release = make(chan struct{})
}

func (m *blockingAttachManager) Attach(ctx context.Context, sess session.AgentSession) error {
	m.mu.Lock()
	shouldBlock := m.blockNext
	if shouldBlock {
		m.blockNext = false
	}
	attached := m.attached
	release := m.release
	m.mu.Unlock()

	if err := m.SessionManager.Attach(ctx, sess); err != nil {
		return err
	}
	if shouldBlock {
		close(attached)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (m *blockingAttachManager) WaitForBlockedAttach(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	attached := m.attached
	m.mu.Unlock()
	select {
	case <-attached:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for blocked attach")
	}
}

func (m *blockingAttachManager) ReleaseBlockedAttach() {
	m.mu.Lock()
	release := m.release
	m.mu.Unlock()
	close(release)
}

func newAuthFixture(t *testing.T, enabled bool, opts ...Option) (*AuthService, *store.MemoryStore, []byte) {
	t.Helper()
	st, secret := newStoreFixture(t, enabled)
	return NewAuthService(st, session.NewManager(), opts...), st, secret
}

func newStoreFixture(t *testing.T, enabled bool) (*store.MemoryStore, []byte) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemoryStore()
	device := domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: enabled}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	secret := []byte("device-secret")
	if err := st.SetKAPv1DeviceSecret(ctx, device.ID, secret); err != nil {
		t.Fatalf("SetKAPv1DeviceSecret() error = %v", err)
	}
	return st, secret
}

func mustNonce(t *testing.T) string {
	t.Helper()
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}
	return nonce
}
