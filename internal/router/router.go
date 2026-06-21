package router

import (
	"context"
	"errors"
	"net"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

var (
	ErrDisabledTunnel = errors.New("disabled tunnel")
	ErrDisabledDevice = errors.New("disabled device")
)

type TunnelStore interface {
	GetDevice(ctx context.Context, id domain.DeviceID) (domain.Device, error)
	FindTunnelByListener(ctx context.Context, listener domain.ListenerRef) (domain.Tunnel, error)
}

type TunnelRouter interface {
	RouteTCP(ctx context.Context, tunnel domain.Tunnel, inbound net.Conn) error
	ResolveTunnel(ctx context.Context, listener domain.ListenerRef) (domain.Tunnel, error)
}

type Router struct {
	store    TunnelStore
	sessions session.SessionManager
}

func New(store TunnelStore, sessions session.SessionManager) *Router {
	return &Router{store: store, sessions: sessions}
}

func (r *Router) ResolveTunnel(ctx context.Context, listener domain.ListenerRef) (domain.Tunnel, error) {
	tunnel, err := r.store.FindTunnelByListener(ctx, listener)
	if err != nil {
		return domain.Tunnel{}, err
	}
	if !tunnel.Enabled {
		return domain.Tunnel{}, ErrDisabledTunnel
	}
	device, err := r.store.GetDevice(ctx, tunnel.DeviceID)
	if err != nil {
		return domain.Tunnel{}, err
	}
	if !device.Enabled {
		return domain.Tunnel{}, ErrDisabledDevice
	}
	return tunnel, nil
}

func (r *Router) RouteTCP(ctx context.Context, tunnel domain.Tunnel, inbound net.Conn) error {
	if inbound != nil {
		defer inbound.Close()
	}
	if !tunnel.Enabled {
		return ErrDisabledTunnel
	}
	device, err := r.store.GetDevice(ctx, tunnel.DeviceID)
	if err != nil {
		return err
	}
	if !device.Enabled {
		return ErrDisabledDevice
	}
	current, err := r.sessions.CurrentForDevice(ctx, tunnel.DeviceID)
	if err != nil {
		return err
	}
	stream, err := current.OpenStream(ctx, domain.StreamOpenRequest{
		TunnelID:   tunnel.ID,
		Protocol:   storeProtocol(tunnel),
		TargetAddr: tunnel.TargetAddr,
	})
	if err != nil {
		return err
	}
	if stream != nil {
		return stream.Close()
	}
	return nil
}

func storeProtocol(tunnel domain.Tunnel) domain.TunnelProtocol {
	if tunnel.Protocol == "" {
		return domain.TunnelProtocolTCP
	}
	return tunnel.Protocol
}

var _ TunnelRouter = (*Router)(nil)
