package store

import (
	"context"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

const maxOwnedWork = 4096 + 512
const ownedCleanupTimeout = 5 * time.Second

func (s *MemoryStore) routeViewLocked(id domain.TunnelID) (domain.RouteView, error) {
	tunnel, ok := s.tunnels[id]
	if !ok {
		return domain.RouteView{}, ErrNotFound
	}
	device, ok := s.devices[tunnel.DeviceID]
	if !ok {
		return domain.RouteView{}, ErrNotFound
	}
	return domain.RouteView{Device: device, Tunnel: tunnel, Revision: s.revisions[device.ID]}, nil
}
func (s *MemoryStore) RouteView(ctx context.Context, id domain.TunnelID) (domain.RouteView, error) {
	if err := ctx.Err(); err != nil {
		return domain.RouteView{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routeViewLocked(id)
}
func (s *MemoryStore) RouteViewByListener(ctx context.Context, ref domain.ListenerRef) (domain.RouteView, error) {
	if err := ctx.Err(); err != nil {
		return domain.RouteView{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.listeners[ref]
	if !ok {
		return domain.RouteView{}, ErrNotFound
	}
	return s.routeViewLocked(id)
}

func (o *ConfigOwner) RouteView(ctx context.Context, id domain.TunnelID) (domain.RouteView, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.RouteView{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.RouteView{}, ErrCommitUncertain
	}
	return o.current.RouteView(ctx, id)
}
func (o *ConfigOwner) RouteViewByListener(ctx context.Context, ref domain.ListenerRef) (domain.RouteView, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.RouteView{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.RouteView{}, ErrCommitUncertain
	}
	return o.current.RouteViewByListener(ctx, ref)
}
func (o *ConfigOwner) AdmitTunnel(ctx context.Context, id domain.TunnelID, revision domain.ConfigRevision) (domain.RouteView, *session.WorkLease, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return domain.RouteView{}, nil, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.RouteView{}, nil, ErrCommitUncertain
	}
	view, err := o.current.RouteView(ctx, id)
	if err != nil {
		return domain.RouteView{}, nil, err
	}
	if !view.Device.Enabled {
		return domain.RouteView{}, nil, domain.ErrDisabledDevice
	}
	if !view.Tunnel.Enabled {
		return domain.RouteView{}, nil, domain.ErrDisabledTunnel
	}
	if revision != 0 && revision != view.Revision {
		return domain.RouteView{}, nil, domain.ErrStaleAdmission
	}
	scope := view.WorkScope()
	scope.Policy = o.current.policies[view.Device.ID]
	if lease := o.work.Existing(ctx, scope); lease != nil {
		return view, nil, nil
	}
	lease, err := o.work.Register(ctx, scope)
	return view, lease, err
}

// AuthenticatePublication serializes final proof/current-secret validation and
// memory-only session publication with disable/policy publication. The callback
// must never perform I/O or close a replaced session while this guard is held.
func (o *ConfigOwner) AuthenticatePublication(ctx context.Context, id domain.DeviceID, publish func(domain.Device, []byte) error) (*session.WorkLease, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return nil, ErrCommitUncertain
	}
	device, secret, err := o.current.ResolveKAPv1DeviceForAuth(ctx, id)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	lease, err := o.work.Register(context.Background(), domain.WorkScope{DeviceID: id, SessionOwner: true, Policy: o.current.policies[id]})
	if err != nil {
		return nil, err
	}
	if err = publish(device, secret); err != nil {
		lease.Finish()
		return nil, err
	}
	return lease, nil
}
func (o *ConfigOwner) ChangeSignal() <-chan struct{} {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.changed
}
func (o *ConfigOwner) signalLocked() { close(o.changed); o.changed = make(chan struct{}) }
func (o *ConfigOwner) publishLocked(next *MemoryStore) []*session.WorkLease {
	o.current = next
	o.signalLocked()
	return o.work.Collect(func(scope domain.WorkScope) bool {
		device, ok := next.devices[scope.DeviceID]
		if !ok || !device.Enabled {
			return true
		}
		if scope.SessionOwner {
			return next.policies[scope.DeviceID] != scope.Policy
		}
		if next.policies[scope.DeviceID] != scope.Policy {
			return true
		}
		tunnel, ok := next.tunnels[scope.TunnelID]
		return !ok || !tunnel.Enabled || tunnel.DeviceID != scope.DeviceID || tunnel.TargetAddr != scope.TargetAddr || tunnel.Listener != scope.Listener || tunnel.Protocol != scope.Protocol
	})
}
func cleanupOwned(leases []*session.WorkLease) error {
	ctx, cancel := context.WithTimeout(context.Background(), ownedCleanupTimeout)
	defer cancel()
	return session.CancelAndJoin(ctx, leases)
}
