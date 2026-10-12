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
	SyncVersion int
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
	return s.beginAuth(ctx, req, 0)
}

func (s *AuthService) beginAuth(ctx context.Context, req AuthStartRequest, syncVersion int) (AuthChallenge, error) {
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
		SyncVersion: syncVersion,
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
	return s.completeAuth(ctx, req, 0)
}

func (s *AuthService) completeAuth(ctx context.Context, req AuthFinishRequest, syncVersion int) (AuthResult, error) {
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
	if state.SyncVersion != syncVersion {
		return AuthResult{}, ErrSyncSchema
	}
	if req.ResponseHMAC == "" {
		return AuthResult{}, ErrInvalidInput
	}
	if !s.now().Before(state.ExpiresAt) {
		return AuthResult{}, ErrChallengeExpired
	}
	device, secret, err := s.store.ResolveKAPv1DeviceForAuth(ctx, state.DeviceID)
	defer clear(secret)
	if err != nil {
		return AuthResult{}, err
	}
	if syncVersion == ConfigSyncVersion {
		if err := VerifySyncAuthResponse(secret, req.ResponseHMAC, device.ID, state.ClientNonce, state.ServerNonce, syncVersion); err != nil {
			return AuthResult{}, err
		}
	} else if err := VerifyAuthResponse(secret, req.ResponseHMAC, device.ID, state.ClientNonce, state.ServerNonce, ProtocolVersion, TransportRoleControl); err != nil {
		return AuthResult{}, err
	}
	sessionID, err := s.newSessionID()
	if err != nil {
		return AuthResult{}, err
	}
	agentSession := newAgentSession(sessionID, device.ID)
	agentSession.syncVersion = syncVersion
	agentSession.now = s.now
	agentSession.expiresAt = s.now().Add(time.Hour)
	s.registrationMu.Lock()
	var replaced session.AgentSession
	var owned *session.WorkLease
	publish := func(current domain.Device, currentSecret []byte) error {
		if syncVersion == ConfigSyncVersion {
			if err := VerifySyncAuthResponse(currentSecret, req.ResponseHMAC, current.ID, state.ClientNonce, state.ServerNonce, syncVersion); err != nil {
				return err
			}
		} else if err := VerifyAuthResponse(currentSecret, req.ResponseHMAC, current.ID, state.ClientNonce, state.ServerNonce, ProtocolVersion, TransportRoleControl); err != nil {
			return err
		}
		if err := s.registry.reserve(sessionID, agentSession); err != nil {
			return err
		}
		publisher, ok := s.sessions.(interface {
			Publish(context.Context, session.AgentSession) (session.AgentSession, error)
		})
		if !ok {
			s.registry.remove(sessionID)
			return ErrInternalInvariant
		}
		var err error
		replaced, err = publisher.Publish(ctx, agentSession)
		if err != nil {
			s.registry.remove(sessionID)
			return err
		}
		if err := s.registry.activate(sessionID); err != nil {
			panic(err)
		}
		return nil
	}
	if owner, ok := s.store.(interface {
		AuthenticatePublication(context.Context, domain.DeviceID, func(domain.Device, []byte) error) (*session.WorkLease, error)
	}); ok {
		owned, err = owner.AuthenticatePublication(ctx, device.ID, publish)
	} else {
		err = s.registry.reserve(sessionID, agentSession)
		if err == nil {
			err = s.sessions.Attach(ctx, agentSession)
			if err != nil {
				s.registry.remove(sessionID)
			} else if err = s.registry.activate(sessionID); err != nil {
				panic(err)
			}
		}
	}
	s.registrationMu.Unlock()
	if err != nil {
		_ = agentSession.Close(context.Background())
		return AuthResult{}, err
	}
	if owned != nil {
		go func() {
			defer owned.Finish()
			select {
			case <-owned.Context.Done():
			case <-agentSession.Done():
			}
			// Close joins any concurrent pool cleanup before releasing ownership.
			_ = agentSession.Close(context.Background())
			s.registry.remove(sessionID)
			_ = s.sessions.Detach(context.Background(), sessionID)
		}()
	}

	// The published replacement owns its lifecycle before predecessor cleanup,
	// which may block independently of revocation of this new session.
	if replaced != nil {
		_ = replaced.Close(context.Background())
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
