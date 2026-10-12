package store

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
)

type MemoryStore struct {
	mu sync.RWMutex

	users        map[domain.UserID]domain.User
	projects     map[domain.ProjectID]domain.Project
	devices      map[domain.DeviceID]domain.Device
	tunnels      map[domain.TunnelID]domain.Tunnel
	listeners    map[domain.ListenerRef]domain.TunnelID
	credentials  map[domain.CredentialID]domain.DeviceCredential
	legacyIndex  map[string]domain.CredentialID
	kapv1Secret  map[domain.DeviceID][]byte
	revisions    map[domain.DeviceID]domain.ConfigRevision
	policies     map[domain.DeviceID]domain.NativePolicy
	stateVersion int

	now func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:        make(map[domain.UserID]domain.User),
		projects:     make(map[domain.ProjectID]domain.Project),
		devices:      make(map[domain.DeviceID]domain.Device),
		tunnels:      make(map[domain.TunnelID]domain.Tunnel),
		listeners:    make(map[domain.ListenerRef]domain.TunnelID),
		credentials:  make(map[domain.CredentialID]domain.DeviceCredential),
		legacyIndex:  make(map[string]domain.CredentialID),
		kapv1Secret:  make(map[domain.DeviceID][]byte),
		revisions:    make(map[domain.DeviceID]domain.ConfigRevision),
		policies:     make(map[domain.DeviceID]domain.NativePolicy),
		stateVersion: 1,
		now:          time.Now,
	}
}

func (s *MemoryStore) CreateUser(ctx context.Context, user domain.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return nil
}

func (s *MemoryStore) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	if err := ctx.Err(); err != nil {
		return domain.User{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return domain.User{}, ErrNotFound
	}
	return user, nil
}

func (s *MemoryStore) CreateProject(ctx context.Context, project domain.Project) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projects[project.ID] = project
	return nil
}

func (s *MemoryStore) GetProject(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	if err := ctx.Err(); err != nil {
		return domain.Project{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	project, ok := s.projects[id]
	if !ok {
		return domain.Project{}, ErrNotFound
	}
	return project, nil
}

func (s *MemoryStore) CreateDevice(ctx context.Context, device domain.Device) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.devices[device.ID]; ok {
		if old != device {
			if err := s.advanceRevisionLocked(device.ID); err != nil {
				return err
			}
		}
	} else {
		s.revisions[device.ID] = 1
		s.policies[device.ID] = domain.DefaultNativePolicy()
	}
	s.devices[device.ID] = device
	return nil
}

func (s *MemoryStore) GetDevice(ctx context.Context, id domain.DeviceID) (domain.Device, error) {
	if err := ctx.Err(); err != nil {
		return domain.Device{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.devices[id]
	if !ok {
		return domain.Device{}, ErrNotFound
	}
	return device, nil
}

func (s *MemoryStore) CreateTunnel(ctx context.Context, tunnel domain.Tunnel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.listeners[tunnel.Listener]; tunnel.Listener != "" && ok && owner != tunnel.ID {
		return ErrListenerConflict
	}
	old, exists := s.tunnels[tunnel.ID]
	if !exists || old != tunnel {
		// Preserve the low-level upsert used by gateway negative fixtures. The
		// durable owner separately enforces immutable tunnel ownership.
		changed := map[domain.DeviceID]bool{tunnel.DeviceID: true}
		if exists {
			changed[old.DeviceID] = true
		}
		for id := range changed {
			if _, ok := s.devices[id]; ok && s.revisions[id] == domain.ConfigRevision(math.MaxUint64) {
				return ErrRevisionOverflow
			}
		}
		for id := range changed {
			if _, ok := s.devices[id]; ok {
				_ = s.advanceRevisionLocked(id)
			}
		}
	}
	if exists && old.Listener != "" {
		delete(s.listeners, old.Listener)
	}
	s.tunnels[tunnel.ID] = tunnel
	if tunnel.Listener != "" {
		s.listeners[tunnel.Listener] = tunnel.ID
	}
	return nil
}

func (s *MemoryStore) advanceRevisionLocked(id domain.DeviceID) error {
	if s.revisions[id] == domain.ConfigRevision(math.MaxUint64) {
		return ErrRevisionOverflow
	}
	s.revisions[id]++
	return nil
}

func (s *MemoryStore) GetTunnel(ctx context.Context, id domain.TunnelID) (domain.Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return domain.Tunnel{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tunnel, ok := s.tunnels[id]
	if !ok {
		return domain.Tunnel{}, ErrNotFound
	}
	return tunnel, nil
}

func (s *MemoryStore) FindTunnelByListener(ctx context.Context, listener domain.ListenerRef) (domain.Tunnel, error) {
	if err := ctx.Err(); err != nil {
		return domain.Tunnel{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.listeners[listener]
	if !ok {
		return domain.Tunnel{}, ErrNotFound
	}
	return s.tunnels[id], nil
}

func (s *MemoryStore) IssueLegacyCredential(ctx context.Context, deviceID domain.DeviceID, serverSecret []byte) (IssuedLegacyCredential, error) {
	return s.issueLegacyCredential(ctx, deviceID, serverSecret, false)
}

func (s *MemoryStore) RotateLegacyCredential(ctx context.Context, deviceID domain.DeviceID, serverSecret []byte) (IssuedLegacyCredential, error) {
	return s.issueLegacyCredential(ctx, deviceID, serverSecret, true)
}

func (s *MemoryStore) FindDeviceByLegacyLookupKey(ctx context.Context, lookupKey string) (domain.Device, error) {
	if err := ctx.Err(); err != nil {
		return domain.Device{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findDeviceByLegacyLookupKeyLocked(lookupKey)
}

func (s *MemoryStore) ResolveLegacyDeviceForAuth(ctx context.Context, lookupKey string) (domain.Device, error) {
	if err := ctx.Err(); err != nil {
		return domain.Device{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, err := s.findDeviceByLegacyLookupKeyLocked(lookupKey)
	if err != nil {
		return domain.Device{}, err
	}
	if !device.Enabled {
		return domain.Device{}, ErrDisabledDevice
	}
	return device, nil
}

func (s *MemoryStore) SetKAPv1DeviceSecret(ctx context.Context, deviceID domain.DeviceID, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(secret) == 0 {
		return ErrMissingSecret
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[deviceID]; !ok {
		return ErrNotFound
	}
	s.kapv1Secret[deviceID] = append([]byte(nil), secret...)
	return nil
}

func (s *MemoryStore) ResolveKAPv1DeviceForAuth(ctx context.Context, deviceID domain.DeviceID) (domain.Device, []byte, error) {
	if err := ctx.Err(); err != nil {
		return domain.Device{}, nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	device, ok := s.devices[deviceID]
	if !ok {
		return domain.Device{}, nil, ErrNotFound
	}
	if !device.Enabled {
		return domain.Device{}, nil, ErrDisabledDevice
	}
	secret, ok := s.kapv1Secret[deviceID]
	if !ok || len(secret) == 0 {
		return domain.Device{}, nil, ErrMissingSecret
	}
	return device, append([]byte(nil), secret...), nil
}

func (s *MemoryStore) issueLegacyCredential(ctx context.Context, deviceID domain.DeviceID, serverSecret []byte, rotate bool) (IssuedLegacyCredential, error) {
	if err := ctx.Err(); err != nil {
		return IssuedLegacyCredential{}, err
	}
	vkey, err := security.GenerateVKey()
	if err != nil {
		return IssuedLegacyCredential{}, err
	}
	wireToken, err := security.LegacyWireTokenFromVKey(vkey)
	if err != nil {
		return IssuedLegacyCredential{}, err
	}
	lookupKey, err := security.LegacyLookupKey(serverSecret, wireToken)
	if err != nil {
		return IssuedLegacyCredential{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[deviceID]; !ok {
		return IssuedLegacyCredential{}, ErrNotFound
	}
	existing := s.legacyCredentialIDsForDeviceLocked(deviceID)
	if !rotate && len(existing) > 0 {
		return IssuedLegacyCredential{}, ErrCredentialExists
	}
	if rotate {
		for _, id := range existing {
			if credential, ok := s.credentials[id]; ok {
				delete(s.legacyIndex, credential.LegacyLookupKey)
				delete(s.credentials, id)
			}
		}
	}

	now := s.now()
	credential := domain.DeviceCredential{
		ID:              domain.CredentialID(fmt.Sprintf("cred-%s-%d", deviceID, now.UnixNano())),
		DeviceID:        deviceID,
		Kind:            domain.CredentialKindLegacyNPC,
		LegacyLookupKey: lookupKey,
		CreatedAt:       now,
	}
	if rotate {
		credential.RotatedAt = now
	}
	s.credentials[credential.ID] = credential
	s.legacyIndex[credential.LegacyLookupKey] = credential.ID
	return IssuedLegacyCredential{Credential: credential, VKey: vkey}, nil
}

func (s *MemoryStore) legacyCredentialIDsForDeviceLocked(deviceID domain.DeviceID) []domain.CredentialID {
	var ids []domain.CredentialID
	for id, credential := range s.credentials {
		if credential.DeviceID == deviceID && credential.Kind == domain.CredentialKindLegacyNPC {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *MemoryStore) findDeviceByLegacyLookupKeyLocked(lookupKey string) (domain.Device, error) {
	credentialID, ok := s.legacyIndex[lookupKey]
	if !ok {
		return domain.Device{}, ErrNotFound
	}
	credential, ok := s.credentials[credentialID]
	if !ok {
		return domain.Device{}, ErrNotFound
	}
	device, ok := s.devices[credential.DeviceID]
	if !ok {
		return domain.Device{}, ErrNotFound
	}
	return device, nil
}
