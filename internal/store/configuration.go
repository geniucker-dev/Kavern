package store

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

var (
	ErrListenerConflict = errors.New("listener already belongs to another tunnel")
	ErrTunnelOwnership  = errors.New("tunnel ownership is immutable")
	ErrRevisionOverflow = errors.New("configuration revision exhausted")
	ErrRevisionConflict = errors.New("configuration revision conflict")
	ErrNativeIneligible = errors.New("device has no native credential")
)

func (s *MemoryStore) DeviceConfiguration(ctx context.Context, id domain.DeviceID) (domain.DeviceConfiguration, error) {
	if err := ctx.Err(); err != nil {
		return domain.DeviceConfiguration{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configurationLocked(id)
}

func (s *MemoryStore) configurationLocked(id domain.DeviceID) (domain.DeviceConfiguration, error) {
	device, ok := s.devices[id]
	if !ok {
		return domain.DeviceConfiguration{}, ErrNotFound
	}
	out := domain.DeviceConfiguration{Device: device, Revision: s.revisions[id], Policy: s.policies[id]}
	for _, tunnel := range s.tunnels {
		if tunnel.DeviceID == id {
			out.Tunnels = append(out.Tunnels, tunnel)
		}
	}
	sort.Slice(out.Tunnels, func(i, j int) bool { return out.Tunnels[i].ID < out.Tunnels[j].ID })
	return out, nil
}

func (s *MemoryStore) NativeSnapshot(ctx context.Context, id domain.DeviceID) (domain.NativeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.NativeSnapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.devices[id]; !ok {
		return domain.NativeSnapshot{}, ErrNotFound
	}
	if _, ok := s.kapv1Secret[id]; !ok {
		return domain.NativeSnapshot{}, ErrNativeIneligible
	}
	if len(s.kapv1Secret[id]) != 32 {
		return domain.NativeSnapshot{}, ErrInvalidState
	}
	c, err := s.configurationLocked(id)
	if err != nil {
		return domain.NativeSnapshot{}, err
	}
	if err = config.ValidateDeviceConfiguration(c, true); err != nil {
		return domain.NativeSnapshot{}, err
	}
	return projectSnapshot(c)
}

func projectSnapshot(c domain.DeviceConfiguration) (domain.NativeSnapshot, error) {
	out := domain.NativeSnapshot{DeviceID: c.Device.ID, Revision: c.Revision, Policy: c.Policy, Tunnels: []domain.NativeTunnel{}}
	if c.Device.Enabled {
		for _, t := range c.Tunnels {
			if t.Enabled {
				out.Tunnels = append(out.Tunnels, domain.NativeTunnel{ID: t.ID, Protocol: t.Protocol, TargetAddr: t.TargetAddr})
			}
		}
	}
	return out, config.ValidateNativeSnapshot(out)
}

// cloneLocked copies the complete state; its owner must hold s.mu. It includes
// secret records so a staged configuration cannot discard unrelated credentials.
func (s *MemoryStore) cloneLocked() *MemoryStore {
	next := NewMemoryStore()
	next.stateVersion, next.now = s.stateVersion, s.now
	for k, v := range s.users {
		next.users[k] = v
	}
	for k, v := range s.projects {
		next.projects[k] = v
	}
	for k, v := range s.devices {
		next.devices[k] = v
	}
	for k, v := range s.tunnels {
		next.tunnels[k] = v
	}
	for k, v := range s.listeners {
		next.listeners[k] = v
	}
	for k, v := range s.credentials {
		next.credentials[k] = v
	}
	for k, v := range s.legacyIndex {
		next.legacyIndex[k] = v
	}
	for k, v := range s.kapv1Secret {
		next.kapv1Secret[k] = append([]byte(nil), v...)
	}
	for k, v := range s.revisions {
		next.revisions[k] = v
	}
	for k, v := range s.policies {
		next.policies[k] = v
	}
	return next
}

// validateState rebuilds neither ownership nor indexes implicitly: each index
// must already agree exactly with the complete candidate. Native admission
// bounds are separate so v1 migration can preserve previously valid records.
func (s *MemoryStore) validateState(nativeBounds bool) error {
	if len(s.devices) != len(s.revisions) || len(s.devices) != len(s.policies) {
		return ErrInvalidState
	}
	for id, v := range s.users {
		if id != v.ID || !config.ValidID(string(id)) {
			return ErrInvalidState
		}
	}
	for id, v := range s.projects {
		if id != v.ID || !config.ValidID(string(id)) {
			return ErrInvalidState
		}
		if _, ok := s.users[v.UserID]; !ok {
			return ErrInvalidState
		}
	}
	for id, v := range s.devices {
		if id != v.ID || !config.ValidID(string(id)) || s.revisions[id] == 0 || config.ValidateNativePolicy(s.policies[id]) != nil {
			return ErrInvalidState
		}
		if _, ok := s.projects[v.ProjectID]; !ok {
			return ErrInvalidState
		}
	}
	listeners := make(map[domain.ListenerRef]domain.TunnelID, len(s.tunnels))
	publicCount := 0
	for id, t := range s.tunnels {
		if id != t.ID || !config.ValidID(string(id)) || t.Protocol != domain.TunnelProtocolTCP || config.ValidateAddress(string(t.Listener)) != nil || config.ValidateAddress(t.TargetAddr) != nil {
			return ErrInvalidState
		}
		d, ok := s.devices[t.DeviceID]
		if !ok {
			return ErrInvalidState
		}
		if _, ok := listeners[t.Listener]; ok {
			return ErrListenerConflict
		}
		listeners[t.Listener] = id
		if d.Enabled && t.Enabled {
			publicCount++
		}
	}
	if len(listeners) != len(s.listeners) {
		return ErrInvalidState
	}
	for ref, id := range listeners {
		if s.listeners[ref] != id {
			return ErrInvalidState
		}
	}
	if nativeBounds && publicCount > config.MaxPublicListeners {
		return config.ErrInvalidBusinessConfig
	}
	if len(s.credentials) != len(s.legacyIndex) {
		return ErrInvalidState
	}
	for id, c := range s.credentials {
		lookup, err := hex.DecodeString(c.LegacyLookupKey)
		if id != c.ID || !config.ValidCredentialID(string(id)) || c.Kind != domain.CredentialKindLegacyNPC || err != nil || len(lookup) != 32 || s.legacyIndex[c.LegacyLookupKey] != id {
			return ErrInvalidState
		}
		if _, ok := s.devices[c.DeviceID]; !ok {
			return ErrInvalidState
		}
	}
	for id, secret := range s.kapv1Secret {
		if _, ok := s.devices[id]; !ok || len(secret) != 32 {
			return ErrInvalidState
		}
	}
	if nativeBounds {
		for id := range s.devices {
			c, _ := s.configurationLocked(id)
			_, native := s.kapv1Secret[id]
			if err := config.ValidateDeviceConfiguration(c, native); err != nil {
				return err
			}
			if native {
				if _, err := projectSnapshot(c); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
