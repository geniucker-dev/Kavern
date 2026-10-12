package store

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"math"
	"sort"
)

type listenerBinding struct {
	generation uint64
	device     domain.DeviceID
	address    domain.ListenerRef
	protocol   domain.TunnelProtocol
}

// DesiredRoutes is one coherent generation, including disabled desired records.
func (o *ConfigOwner) DesiredRoutes(ctx context.Context) ([]domain.RouteView, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.closed {
		return nil, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return nil, ErrCommitUncertain
	}
	var views []domain.RouteView
	enabled := 0
	for id := range o.current.tunnels {
		v, err := o.current.routeViewLocked(id)
		if err != nil {
			return nil, err
		}
		views = append(views, v)
		if v.Device.Enabled && v.Tunnel.Enabled {
			enabled++
		}
	}
	if enabled > config.MaxPublicListeners {
		return nil, config.ErrInvalidBusinessConfig
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Tunnel.ID < views[j].Tunnel.ID })
	return views, nil
}
func (o *ConfigOwner) ReserveListener(ctx context.Context, id domain.TunnelID, address domain.ListenerRef) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, err := o.admissionViewLocked(ctx, id, 0)
	if err != nil {
		return 0, err
	}
	if v.Tunnel.Listener != address {
		return 0, domain.ErrStaleAdmission
	}
	if len(o.bindings) >= config.MaxPublicListeners {
		return 0, session.ErrWorkCapacity
	}
	if _, exists := o.bindings[id]; exists {
		return 0, domain.ErrStaleAdmission
	}
	if o.listenerSequence == math.MaxUint64 {
		return 0, ErrRevisionOverflow
	}
	o.listenerSequence++
	o.bindings[id] = listenerBinding{o.listenerSequence, v.Device.ID, v.Tunnel.Listener, v.Tunnel.Protocol}
	return o.listenerSequence, nil
}
func (o *ConfigOwner) ListenerCurrent(ctx context.Context, id domain.TunnelID, generation uint64) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if ctx.Err() != nil || o.closed || o.uncertain {
		return false
	}
	binding, ok := o.bindings[id]
	return ok && binding.generation == generation
}
func (o *ConfigOwner) RetireListener(id domain.TunnelID, generation uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b, ok := o.bindings[id]; ok && b.generation == generation {
		delete(o.bindings, id)
	}
}
func (o *ConfigOwner) AdmitListener(ctx context.Context, id domain.TunnelID, generation uint64) (domain.RouteView, *session.WorkLease, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, err := o.admissionViewLocked(ctx, id, 0)
	if err != nil {
		return domain.RouteView{}, nil, err
	}
	b, ok := o.bindings[id]
	if !ok || b.generation != generation {
		return domain.RouteView{}, nil, domain.ErrStaleAdmission
	}
	return o.registerRouteLocked(ctx, v)
}
func (o *ConfigOwner) invalidateListenersLocked() {
	for id, b := range o.bindings {
		v, err := o.current.routeViewLocked(id)
		if o.closed || o.uncertain || err != nil || !v.Device.Enabled || !v.Tunnel.Enabled || v.Device.ID != b.device || v.Tunnel.Listener != b.address || v.Tunnel.Protocol != b.protocol {
			delete(o.bindings, id)
		}
	}
}

// Done closes when the owner stops admitting runtime work.
func (o *ConfigOwner) Done() <-chan struct{} { return o.ctx.Done() }
