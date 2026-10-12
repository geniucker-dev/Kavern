package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

var ErrInvalidState = errors.New("invalid local state")

type sealedSecret struct {
	DeviceID   domain.DeviceID
	Ciphertext string
}
type deviceConfigState struct {
	DeviceID domain.DeviceID
	Revision domain.ConfigRevision
	Policy   domain.NativePolicy
}
type stateFile struct {
	Version        int
	Management     *managementState `json:",omitempty"`
	Users          []domain.User
	Projects       []domain.Project
	Devices        []domain.Device
	Tunnels        []domain.Tunnel
	Credentials    []domain.DeviceCredential
	Secrets        []sealedSecret
	Configurations []deviceConfigState `json:",omitempty"`
}

func MasterKeyFromEnv(name string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(os.Getenv(name))
	if err != nil || len(key) != 32 {
		return nil, errors.New("master key environment must contain 32 base64url bytes")
	}
	return key, nil
}
func stateCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalidState
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func secureStateDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private (0700)")
	}
	return nil
}
func privateFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return errors.New("state file must be regular and private (0600)")
	}
	return nil
}
func (s *MemoryStore) SaveState(path string, key []byte) error {
	// Offline rewrites also invalidate stale management windows, including no-op rewrites.
	s.mu.Lock()
	if s.stateVersion == 3 {
		if err := s.management.advance(); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()
	data, err := s.encodeState(key)
	if err != nil {
		return err
	}
	return writeState(context.Background(), path, data, defaultStateFiles())
}
func (s *MemoryStore) encodeState(key []byte) ([]byte, error) {
	aead, err := stateCipher(key)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := stateFile{Version: s.stateVersion}
	if s.stateVersion == 3 {
		copy := s.management.clone()
		state.Management = &copy
	}
	if err := s.validateState(false); err != nil {
		return nil, err
	}
	if s.stateVersion >= 2 {
		for id := range s.devices {
			state.Configurations = append(state.Configurations, deviceConfigState{DeviceID: id, Revision: s.revisions[id], Policy: s.policies[id]})
		}
		sort.Slice(state.Configurations, func(i, j int) bool { return state.Configurations[i].DeviceID < state.Configurations[j].DeviceID })
	}
	for _, v := range s.users {
		state.Users = append(state.Users, v)
	}
	for _, v := range s.projects {
		state.Projects = append(state.Projects, v)
	}
	for _, v := range s.devices {
		state.Devices = append(state.Devices, v)
	}
	for _, v := range s.tunnels {
		state.Tunnels = append(state.Tunnels, v)
	}
	for _, v := range s.credentials {
		state.Credentials = append(state.Credentials, v)
	}
	for id, secret := range s.kapv1Secret {
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return nil, err
		}
		sealed := aead.Seal(nonce, nonce, secret, []byte("kavern-state-v1:"+string(id)))
		state.Secrets = append(state.Secrets, sealedSecret{id, base64.RawURLEncoding.EncodeToString(sealed)})
	}
	sort.Slice(state.Users, func(i, j int) bool { return state.Users[i].ID < state.Users[j].ID })
	sort.Slice(state.Projects, func(i, j int) bool { return state.Projects[i].ID < state.Projects[j].ID })
	sort.Slice(state.Devices, func(i, j int) bool { return state.Devices[i].ID < state.Devices[j].ID })
	sort.Slice(state.Tunnels, func(i, j int) bool { return state.Tunnels[i].ID < state.Tunnels[j].ID })
	sort.Slice(state.Credentials, func(i, j int) bool { return state.Credentials[i].ID < state.Credentials[j].ID })
	sort.Slice(state.Secrets, func(i, j int) bool { return state.Secrets[i].DeviceID < state.Secrets[j].DeviceID })
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(data) > config.MaxJSONBytes {
		return nil, ErrInvalidState
	}

	return data, nil
}

func LoadState(path string, key []byte) (*MemoryStore, error) {
	return LoadStateWithNativePolicy(path, key, domain.DefaultNativePolicy())
}

// LoadStateWithNativePolicy reads without rewriting. Defaults apply only to v1.
func LoadStateWithNativePolicy(path string, key []byte, defaults domain.NativePolicy) (*MemoryStore, error) {
	if config.ValidateNativePolicy(defaults) != nil {
		return nil, ErrInvalidState
	}
	aead, err := stateCipher(key)
	if err != nil {
		return nil, err
	}
	if err = secureStateDir(path); err != nil {
		return nil, err
	}
	if err = privateFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var state stateFile
	if err = config.DecodeJSON(f, &state); err != nil {
		return nil, err
	}
	if state.Version != 1 && state.Version != 2 && state.Version != 3 {
		return nil, ErrInvalidState
	}
	s := NewMemoryStore()
	s.stateVersion = state.Version
	if state.Version == 3 {
		if state.Management == nil {
			return nil, ErrInvalidState
		}
		s.management = state.Management.clone()
	} else if state.Management != nil {
		return nil, ErrInvalidState
	}
	for _, v := range state.Users {
		if !config.ValidID(string(v.ID)) {
			return nil, ErrInvalidState
		}
		if _, ok := s.users[v.ID]; ok {
			return nil, ErrInvalidState
		}
		s.users[v.ID] = v
	}
	for _, v := range state.Projects {
		if !config.ValidID(string(v.ID)) {
			return nil, ErrInvalidState
		}
		if _, ok := s.projects[v.ID]; ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.users[v.UserID]; !ok {
			return nil, ErrInvalidState
		}
		s.projects[v.ID] = v
	}
	for _, v := range state.Devices {
		if !config.ValidID(string(v.ID)) {
			return nil, ErrInvalidState
		}
		if _, ok := s.devices[v.ID]; ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.projects[v.ProjectID]; !ok {
			return nil, ErrInvalidState
		}
		s.devices[v.ID] = v
	}
	for _, v := range state.Tunnels {
		if !config.ValidID(string(v.ID)) || v.Protocol != domain.TunnelProtocolTCP || config.ValidateAddress(string(v.Listener)) != nil || config.ValidateAddress(v.TargetAddr) != nil {
			return nil, ErrInvalidState
		}
		if _, ok := s.tunnels[v.ID]; ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.listeners[v.Listener]; ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.devices[v.DeviceID]; !ok {
			return nil, ErrInvalidState
		}
		s.tunnels[v.ID] = v
		s.listeners[v.Listener] = v.ID
	}
	for _, v := range state.Credentials {
		lookup, err := hex.DecodeString(v.LegacyLookupKey)
		if !config.ValidCredentialID(string(v.ID)) || v.Kind != domain.CredentialKindLegacyNPC || err != nil || len(lookup) != 32 {
			return nil, ErrInvalidState
		}
		if _, ok := s.devices[v.DeviceID]; !ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.credentials[v.ID]; ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.legacyIndex[v.LegacyLookupKey]; ok {
			return nil, ErrInvalidState
		}
		s.credentials[v.ID] = v
		s.legacyIndex[v.LegacyLookupKey] = v.ID
	}
	for _, v := range state.Secrets {
		if _, ok := s.devices[v.DeviceID]; !ok {
			return nil, ErrInvalidState
		}
		if _, ok := s.kapv1Secret[v.DeviceID]; ok {
			return nil, ErrInvalidState
		}
		data, err := base64.RawURLEncoding.DecodeString(v.Ciphertext)
		if err != nil || len(data) < aead.NonceSize()+aead.Overhead() {
			return nil, ErrInvalidState
		}
		secret, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte("kavern-state-v1:"+string(v.DeviceID)))
		if err != nil || len(secret) != 32 {
			return nil, ErrInvalidState
		}
		s.kapv1Secret[v.DeviceID] = secret
	}
	if state.Version == 1 {
		if len(state.Configurations) != 0 {
			return nil, ErrInvalidState
		}
		for id := range s.devices {
			s.revisions[id] = 1
			s.policies[id] = defaults
		}
	} else {
		for _, c := range state.Configurations {
			if _, ok := s.devices[c.DeviceID]; !ok {
				return nil, ErrInvalidState
			}
			if _, ok := s.revisions[c.DeviceID]; ok || c.Revision == 0 || config.ValidateNativePolicy(c.Policy) != nil {
				return nil, ErrInvalidState
			}
			s.revisions[c.DeviceID], s.policies[c.DeviceID] = c.Revision, c.Policy
		}
	}
	if err := s.validateState(false); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *MemoryStore) Tunnels() []domain.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Tunnel, 0, len(s.tunnels))
	for _, v := range s.tunnels {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
