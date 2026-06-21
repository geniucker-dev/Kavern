package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/security"
)

type MemoryStore struct {
	mu sync.RWMutex

	users       map[domain.UserID]domain.User
	projects    map[domain.ProjectID]domain.Project
	devices     map[domain.DeviceID]domain.Device
	tunnels     map[domain.TunnelID]domain.Tunnel
	listeners   map[domain.ListenerRef]domain.TunnelID
	credentials map[domain.CredentialID]domain.DeviceCredential
	legacyIndex map[string]domain.CredentialID

	now func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:       make(map[domain.UserID]domain.User),
		projects:    make(map[domain.ProjectID]domain.Project),
		devices:     make(map[domain.DeviceID]domain.Device),
		tunnels:     make(map[domain.TunnelID]domain.Tunnel),
		listeners:   make(map[domain.ListenerRef]domain.TunnelID),
		credentials: make(map[domain.CredentialID]domain.DeviceCredential),
		legacyIndex: make(map[string]domain.CredentialID),
		now:         time.Now,
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
	s.tunnels[tunnel.ID] = tunnel
	if tunnel.Listener != "" {
		s.listeners[tunnel.Listener] = tunnel.ID
	}
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
