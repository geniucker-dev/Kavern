package agent_v1

import (
	"context"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func (s *AuthService) BindCarrier(ctx context.Context, req CarrierBindRequest) (CarrierBinding, error) {
	return s.bindCarrier(ctx, req, 0)
}

func (s *AuthService) bindCarrier(ctx context.Context, req CarrierBindRequest, syncVersion int) (CarrierBinding, error) {
	if err := ctx.Err(); err != nil {
		return CarrierBinding{}, err
	}
	if validateToken(string(req.SessionID)) != nil || validateToken(req.CarrierNonce) != nil || req.ResponseHMAC == "" {
		return CarrierBinding{}, ErrInvalidInput
	}
	entry, ok := s.registry.lookup(req.SessionID)
	if !ok {
		return CarrierBinding{}, ErrSessionNotFound
	}
	if entry.session.syncVersion != syncVersion {
		return CarrierBinding{}, ErrSyncSchema
	}
	if entry.session.Protocol() != domain.AgentProtocolKAPv1 {
		return CarrierBinding{}, ErrSessionNotFound
	}
	if !s.now().Before(entry.session.expiresAt) {
		_ = s.CloseSession(context.Background(), req.SessionID)
		return CarrierBinding{}, ErrSessionClosed
	}
	if entry.session.closed() {
		s.registry.remove(req.SessionID)
		return CarrierBinding{}, ErrSessionClosed
	}
	current, err := s.sessions.CurrentForDevice(ctx, entry.deviceID)
	if err != nil {
		return CarrierBinding{}, err
	}
	if current.ID() != req.SessionID {
		s.registry.remove(req.SessionID)
		return CarrierBinding{}, ErrSessionNotCurrent
	}
	if _, secret, err := s.store.ResolveKAPv1DeviceForAuth(ctx, entry.deviceID); err != nil {
		return CarrierBinding{}, err
	} else if syncVersion == ConfigSyncVersion {
		if err := VerifySyncCarrierBind(secret, req.ResponseHMAC, req.SessionID, entry.deviceID, req.CarrierNonce, syncVersion); err != nil {
			return CarrierBinding{}, err
		}
	} else if err := VerifyCarrierBind(secret, req.ResponseHMAC, req.SessionID, entry.deviceID, req.CarrierNonce, ProtocolVersion, TransportRoleDataCarrier); err != nil {
		return CarrierBinding{}, err
	}
	if s.registry.nonceUsed(req.SessionID, req.CarrierNonce) {
		return CarrierBinding{}, ErrCarrierNonceReplay
	}
	if err := s.registry.markNonceUsed(req.SessionID, req.CarrierNonce); err != nil {
		return CarrierBinding{}, err
	}
	return CarrierBinding{SessionID: req.SessionID, DeviceID: entry.deviceID, CarrierNonce: req.CarrierNonce}, nil
}
