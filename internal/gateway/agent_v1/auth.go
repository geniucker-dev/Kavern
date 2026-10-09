package agent_v1

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type DeviceSecretStore interface {
	ResolveKAPv1DeviceForAuth(ctx context.Context, deviceID domain.DeviceID) (domain.Device, []byte, error)
}

type AuthService struct {
	store        DeviceSecretStore
	sessions     session.SessionManager
	registry     *sessionRegistry
	now          func() time.Time
	ttl          time.Duration
	newSessionID func() (domain.SessionID, error)

	challengesMu sync.Mutex
	challenges   map[string]challengeState

	registrationMu sync.Mutex
}

type challengeState struct {
	ChallengeID string
	DeviceID    domain.DeviceID
	ClientNonce string
	ServerNonce string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

type Option func(*AuthService)

func NewAuthService(store DeviceSecretStore, sessions session.SessionManager, opts ...Option) *AuthService {
	svc := &AuthService{
		store:        store,
		sessions:     sessions,
		registry:     newSessionRegistry(),
		now:          time.Now,
		ttl:          2 * time.Minute,
		newSessionID: GenerateSessionID,
		challenges:   make(map[string]challengeState),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func WithNow(now func() time.Time) Option {
	return func(s *AuthService) {
		s.now = now
	}
}

func WithChallengeTTL(ttl time.Duration) Option {
	return func(s *AuthService) {
		s.ttl = ttl
	}
}

func WithRegistryReserveFailure() Option {
	return func(s *AuthService) {
		s.registry.failReserve = true
	}
}

func WithSessionIDGenerator(generate func() (domain.SessionID, error)) Option {
	return func(s *AuthService) {
		s.newSessionID = generate
	}
}

func (s *AuthService) BeginAuth(ctx context.Context, req AuthStartRequest) (AuthChallenge, error) {
	if err := ctx.Err(); err != nil {
		return AuthChallenge{}, err
	}
	if req.DeviceID == "" || validateToken(req.ClientNonce) != nil {
		return AuthChallenge{}, ErrInvalidInput
	}
	if _, _, err := s.store.ResolveKAPv1DeviceForAuth(ctx, req.DeviceID); err != nil {
		return AuthChallenge{}, err
	}
	challengeID, err := GenerateChallengeID()
	if err != nil {
		return AuthChallenge{}, err
	}
	serverNonce, err := GenerateNonce()
	if err != nil {
		return AuthChallenge{}, err
	}
	now := s.now()
	expiresAt := now.Add(s.ttl)
	state := challengeState{
		ChallengeID: challengeID,
		DeviceID:    req.DeviceID,
		ClientNonce: req.ClientNonce,
		ServerNonce: serverNonce,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}
	s.challengesMu.Lock()
	for id, existing := range s.challenges {
		if !now.Before(existing.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
	if len(s.challenges) >= 4096 {
		s.challengesMu.Unlock()
		return AuthChallenge{}, ErrInvalidInput
	}
	s.challenges[challengeID] = state
	s.challengesMu.Unlock()
	return AuthChallenge{
		AuthChallengeID: challengeID,
		ServerNonce:     serverNonce,
		ProtocolVersion: ProtocolVersion,
		ExpiresAtUnix:   expiresAt.Unix(),
	}, nil
}

func (s *AuthService) CompleteAuth(ctx context.Context, req AuthFinishRequest) (AuthResult, error) {
	if err := ctx.Err(); err != nil {
		return AuthResult{}, err
	}
	if validateToken(req.AuthChallengeID) != nil {
		return AuthResult{}, ErrInvalidInput
	}
	s.challengesMu.Lock()
	state, ok := s.challenges[req.AuthChallengeID]
	if ok {
		delete(s.challenges, req.AuthChallengeID)
	}
	s.challengesMu.Unlock()
	if !ok {
		return AuthResult{}, ErrChallengeNotFound
	}
	if req.ResponseHMAC == "" {
		return AuthResult{}, ErrInvalidInput
	}
	if !s.now().Before(state.ExpiresAt) {
		return AuthResult{}, ErrChallengeExpired
	}
	device, secret, err := s.store.ResolveKAPv1DeviceForAuth(ctx, state.DeviceID)
	if err != nil {
		return AuthResult{}, err
	}
	if err := VerifyAuthResponse(secret, req.ResponseHMAC, device.ID, state.ClientNonce, state.ServerNonce, ProtocolVersion, TransportRoleControl); err != nil {
		return AuthResult{}, err
	}
	sessionID, err := s.newSessionID()
	if err != nil {
		return AuthResult{}, err
	}
	agentSession := newAgentSession(sessionID, device.ID)
	agentSession.now = s.now
	agentSession.expiresAt = s.now().Add(time.Hour)
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()
	if err := s.registry.reserve(sessionID, agentSession); err != nil {
		return AuthResult{}, err
	}
	if err := s.sessions.Attach(ctx, agentSession); err != nil {
		s.registry.remove(sessionID)
		_ = agentSession.Close(context.Background())
		return AuthResult{}, err
	}
	if err := s.registry.activate(sessionID); err != nil {
		panic(err)
	}
	return AuthResult{SessionID: sessionID, DeviceID: device.ID, ProtocolVersion: ProtocolVersion}, nil
}

func (s *AuthService) CloseSession(ctx context.Context, sessionID domain.SessionID) error {
	entry, ok := s.registry.lookup(sessionID)
	if !ok {
		return ErrSessionNotFound
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	closeErr := entry.session.Close(cleanupCtx)
	s.registry.remove(sessionID)
	return errors.Join(closeErr, s.sessions.Detach(cleanupCtx, sessionID))
}
