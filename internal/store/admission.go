package store

import (
	"bytes"
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
	v, err := o.admissionViewLocked(ctx, id, revision)
	if err != nil {
		return domain.RouteView{}, nil, err
	}
	return o.registerRouteLocked(ctx, v)
}
func (o *ConfigOwner) admissionViewLocked(ctx context.Context, id domain.TunnelID, revision domain.ConfigRevision) (domain.RouteView, error) {
	if o.closed {
		return domain.RouteView{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.RouteView{}, ErrCommitUncertain
	}
	view, err := o.current.RouteView(ctx, id)
	if err != nil {
		return domain.RouteView{}, err
	}
	if !view.Device.Enabled {
		return domain.RouteView{}, domain.ErrDisabledDevice
	}
	if !view.Tunnel.Enabled {
		return domain.RouteView{}, domain.ErrDisabledTunnel
	}
	if revision != 0 && revision != view.Revision {
		return domain.RouteView{}, domain.ErrStaleAdmission
	}
	return view, nil
}
func (o *ConfigOwner) registerRouteLocked(ctx context.Context, view domain.RouteView) (domain.RouteView, *session.WorkLease, error) {
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
	prior := o.current
	credentialChanges := changedCredentials(prior, next)
	o.current = next
	o.invalidateListenersLocked()
	o.signalLocked()
	return o.work.Collect(func(scope domain.WorkScope) bool {
		device, ok := next.devices[scope.DeviceID]
		if !ok || !device.Enabled || credentialChanges[scope.DeviceID] {
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

// Credential rotation revokes every device-owned lease, including pending legacy interests.
func changedCredentials(a, b *MemoryStore) map[domain.DeviceID]bool {
	changed := map[domain.DeviceID]bool{}
	for id, secret := range a.kapv1Secret {
		if !bytes.Equal(secret, b.kapv1Secret[id]) {
			changed[id] = true
		}
	}
	for id, secret := range b.kapv1Secret {
		if !bytes.Equal(secret, a.kapv1Secret[id]) {
			changed[id] = true
		}
	}
	for id, c := range a.credentials {
		if other, ok := b.credentials[id]; !ok || c != other {
			changed[c.DeviceID] = true
			if ok {
				changed[other.DeviceID] = true
			}
		}
	}
	for id, c := range b.credentials {
		if other, ok := a.credentials[id]; !ok || c != other {
			changed[c.DeviceID] = true
			if ok {
				changed[other.DeviceID] = true
			}
		}
	}
	return changed
}

func (o *ConfigOwner) AcquireLegacyInterest(ctx context.Context, id domain.DeviceID, key string) (*session.WorkLease, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.legacyCurrentLocked(ctx, id, key); err != nil {
		return nil, err
	}
	return o.work.Register(ctx, domain.WorkScope{DeviceID: id, SessionOwner: true, Policy: o.current.policies[id]})
}

// The callback publishes memory only; resource close and joins happen outside this guard.
func (o *ConfigOwner) WithLegacyPublication(ctx context.Context, id domain.DeviceID, key string, publish func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.legacyCurrentLocked(ctx, id, key); err != nil {
		return err
	}
	if o.work.Existing(ctx, domain.WorkScope{DeviceID: id, SessionOwner: true, Policy: o.current.policies[id]}) == nil {
		return domain.ErrStaleAdmission
	}
	return publish()
}
func (o *ConfigOwner) legacyCurrentLocked(ctx context.Context, id domain.DeviceID, key string) error {
	if o.closed {
		return ErrConfigOwnerClosed
	}
	if o.uncertain {
		return ErrCommitUncertain
	}
	d, err := o.current.ResolveLegacyDeviceForAuth(ctx, key)
	if err != nil {
		return err
	}
	if d.ID != id {
		return domain.ErrStaleAdmission
	}
	return nil
}

// WithNativeInterest is the memory-only renewal authority boundary. It does not
// register a new session or refresh revoked interest; cleanup stays outside guards.
func (o *ConfigOwner) WithNativeInterest(ctx, interest context.Context, id domain.DeviceID, apply func([]byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	if o.closed {
		return ErrConfigOwnerClosed
	}
	if o.uncertain {
		return ErrCommitUncertain
	}
	if interest == nil {
		return domain.ErrStaleAdmission
	}
	if o.work.Existing(interest, domain.WorkScope{DeviceID: id, SessionOwner: true, Policy: o.current.policies[id]}) == nil {
		return domain.ErrStaleAdmission
	}
	_, secret, e := o.current.ResolveKAPv1DeviceForAuth(ctx, id)
	if e != nil {
		return e
	}
	defer clear(secret)
	return apply(secret)
}
