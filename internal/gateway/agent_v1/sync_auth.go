package agent_v1

import (
	"context"
	"errors"

	"github.com/geniucker-dev/kavern/internal/domain"
)

const ConfigSyncVersion = 1

var (
	ErrSyncSchema   = errors.New("unsupported configuration sync schema")
	ErrSyncNotReady = errors.New("configuration sync session not routable")
	ErrSyncTransfer = errors.New("invalid configuration transfer")
	ErrSyncStale    = errors.New("stale configuration transfer")
	ErrSyncCapacity = errors.New("configuration staging capacity exhausted")
	ErrSyncDeadline = errors.New("configuration transfer deadline exceeded")
)

type SyncAuthChallenge struct {
	AuthChallenge
	ConfigSyncVersion int
}
type SyncAuthResult struct {
	AuthResult
	ConfigSyncVersion int
	LifecycleVersion  int
}

// These opt-in entry points do not change the current command transport. The
// selected schema is retained in the challenge and bound into both HMACs.
func (s *AuthService) BeginSyncAuth(ctx context.Context, req AuthStartRequest, version int) (SyncAuthChallenge, error) {
	if version != ConfigSyncVersion {
		return SyncAuthChallenge{}, ErrSyncSchema
	}
	c, err := s.beginAuth(ctx, req, version)
	return SyncAuthChallenge{AuthChallenge: c, ConfigSyncVersion: version}, err
}

func (s *AuthService) CompleteSyncAuth(ctx context.Context, req AuthFinishRequest, version int) (SyncAuthResult, error) {
	if version != ConfigSyncVersion {
		return SyncAuthResult{}, ErrSyncSchema
	}
	r, err := s.completeAuth(ctx, req, version)
	return SyncAuthResult{AuthResult: r, ConfigSyncVersion: version}, err
}

func (s *AuthService) BindSyncCarrier(ctx context.Context, req CarrierBindRequest, version int) (CarrierBinding, error) {
	if version != ConfigSyncVersion {
		return CarrierBinding{}, ErrSyncSchema
	}
	return s.bindCarrier(ctx, req, version)
}

func syncAuthMessage(device domain.DeviceID, client, server string, version int) ([]byte, error) {
	if version != ConfigSyncVersion {
		return nil, ErrSyncSchema
	}
	base, err := CanonicalAuthMessage(device, client, server, ProtocolVersion, TransportRoleControl)
	if err != nil {
		return nil, err
	}
	return append(base, []byte("config_sync_version=1\n")...), nil
}
func SignSyncAuthResponse(secret []byte, device domain.DeviceID, client, server string, version int) (string, error) {
	message, err := syncAuthMessage(device, client, server, version)
	if err != nil {
		return "", err
	}
	return signHMAC(secret, message)
}
func VerifySyncAuthResponse(secret []byte, response string, device domain.DeviceID, client, server string, version int) error {
	message, err := syncAuthMessage(device, client, server, version)
	if err != nil {
		return err
	}
	return verifyHMAC(secret, response, message)
}
func syncCarrierMessage(id domain.SessionID, device domain.DeviceID, nonce string, version int) ([]byte, error) {
	if version != ConfigSyncVersion {
		return nil, ErrSyncSchema
	}
	base, err := CanonicalCarrierBindMessage(id, device, nonce, ProtocolVersion, TransportRoleDataCarrier)
	if err != nil {
		return nil, err
	}
	return append(base, []byte("config_sync_version=1\n")...), nil
}
func SignSyncCarrierBind(secret []byte, id domain.SessionID, device domain.DeviceID, nonce string, version int) (string, error) {
	message, err := syncCarrierMessage(id, device, nonce, version)
	if err != nil {
		return "", err
	}
	return signHMAC(secret, message)
}
func VerifySyncCarrierBind(secret []byte, response string, id domain.SessionID, device domain.DeviceID, nonce string, version int) error {
	message, err := syncCarrierMessage(id, device, nonce, version)
	if err != nil {
		return err
	}
	return verifyHMAC(secret, response, message)
}

// registrationMu makes replacement and protocol-state publication mutually
// exclusive. The callback must not perform I/O or call authentication methods.
func (s *AuthService) withSyncSession(ctx context.Context, auth SyncAuthResult, apply func() error) error {
	if auth.LifecycleVersion == LifecycleVersion {
		entry, ok := s.registry.lookup(auth.SessionID)
		if !ok || entry.deviceID != auth.DeviceID || entry.session.lifecycleVersion != LifecycleVersion {
			return ErrSessionNotFound
		}
		lease := entry.session.serverLease()
		if lease == nil {
			return ErrSessionClosed
		}
		return lease.withAdmission(ctx, func(_ []byte) error {
			if auth.ConfigSyncVersion != ConfigSyncVersion || auth.ProtocolVersion != ProtocolVersion {
				return ErrSyncSchema
			}
			return apply()
		})
	}
	if auth.LifecycleVersion != 0 {
		return ErrSyncSchema
	}
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if auth.ConfigSyncVersion != ConfigSyncVersion || auth.ProtocolVersion != ProtocolVersion {
		return ErrSyncSchema
	}
	entry, ok := s.registry.lookup(auth.SessionID)
	if !ok || entry.deviceID != auth.DeviceID {
		return ErrSessionNotFound
	}
	if entry.session.syncVersion != ConfigSyncVersion || entry.session.lifecycleVersion != auth.LifecycleVersion {
		return ErrSyncSchema
	}
	if entry.session.closed() || !s.now().Before(entry.session.expiresAt) {
		return ErrSessionClosed
	}
	current, err := s.sessions.CurrentForDevice(ctx, auth.DeviceID)
	if err != nil {
		return err
	}
	if current.ID() != auth.SessionID {
		return ErrSessionNotCurrent
	}
	if _, _, err = s.store.ResolveKAPv1DeviceForAuth(ctx, auth.DeviceID); err != nil {
		return err
	}
	return apply()
}
