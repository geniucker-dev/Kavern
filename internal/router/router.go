package router

import (
	"context"
	"errors"
	"net"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

var (
	ErrDisabledTunnel           = domain.ErrDisabledTunnel
	ErrDisabledDevice           = domain.ErrDisabledDevice
	ErrInvalidInboundConnection = errors.New("invalid inbound connection")
)

type TunnelStore interface {
	RouteView(context.Context, domain.TunnelID) (domain.RouteView, error)
	RouteViewByListener(context.Context, domain.ListenerRef) (domain.RouteView, error)
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
	view, err := r.store.RouteViewByListener(ctx, listener)
	if err != nil {
		return domain.Tunnel{}, err
	}
	if !view.Tunnel.Enabled {
		return domain.Tunnel{}, ErrDisabledTunnel
	}
	if !view.Device.Enabled {
		return domain.Tunnel{}, ErrDisabledDevice
	}
	return view.Tunnel, nil
}

func (r *Router) RouteTCP(ctx context.Context, tunnel domain.Tunnel, inbound net.Conn) error {
	view, err := r.store.RouteView(ctx, tunnel.ID)
	if err != nil {
		return err
	}
	if !view.Tunnel.Enabled {
		return ErrDisabledTunnel
	}
	if !view.Device.Enabled {
		return ErrDisabledDevice
	}
	if owner, ok := r.store.(interface {
		AdmitTunnel(context.Context, domain.TunnelID, domain.ConfigRevision) (domain.RouteView, *session.WorkLease, error)
	}); ok {
		admitted, lease, err := owner.AdmitTunnel(ctx, tunnel.ID, view.Revision)
		if err != nil {
			return err
		}
		view = admitted
		if lease != nil {
			defer lease.Finish()
			ctx = lease.Context
		}
	}
	tunnel = view.Tunnel
	current, err := r.sessions.CurrentForDevice(ctx, view.Device.ID)
	if err != nil {
		return err
	}
	if inbound == nil {
		return ErrInvalidInboundConnection
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = inbound.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	remoteAddr := ""
	if inbound != nil && inbound.RemoteAddr() != nil {
		remoteAddr = inbound.RemoteAddr().String()
	}
	stream, err := current.OpenStream(ctx, domain.StreamOpenRequest{
		Revision:   view.Revision,
		TunnelID:   tunnel.ID,
		Protocol:   storeProtocol(tunnel),
		TargetAddr: "",
		RemoteAddr: remoteAddr,
	})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = stream.Close()
		return err
	}
	return session.ProxyBidirectional(ctx, inbound, stream)
}

func storeProtocol(tunnel domain.Tunnel) domain.TunnelProtocol {
	if tunnel.Protocol == "" {
		return domain.TunnelProtocolTCP
	}
	return tunnel.Protocol
}

var _ TunnelRouter = (*Router)(nil)
