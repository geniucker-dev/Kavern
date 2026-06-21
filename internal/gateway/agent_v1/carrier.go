package agent_v1

import (
	"context"

	"github.com/zhuhaoyu/kavern/internal/domain"
)

func (s *AuthService) BindCarrier(ctx context.Context, req CarrierBindRequest) (CarrierBinding, error) {
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
	if entry.session.Protocol() != domain.AgentProtocolKAPv1 {
		return CarrierBinding{}, ErrSessionNotFound
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
