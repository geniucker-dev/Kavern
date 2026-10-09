package store

import (
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
type stateFile struct {
	Version     int
	Users       []domain.User
	Projects    []domain.Project
	Devices     []domain.Device
	Tunnels     []domain.Tunnel
	Credentials []domain.DeviceCredential
	Secrets     []sealedSecret
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
	aead, err := stateCipher(key)
	if err != nil {
		return err
	}
	if err = secureStateDir(path); err != nil {
		return err
	}
	if err = privateFile(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	state := stateFile{Version: 1}
	s.mu.RLock()
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
			s.mu.RUnlock()
			return err
		}
		sealed := aead.Seal(nonce, nonce, secret, []byte("kavern-state-v1:"+string(id)))
		state.Secrets = append(state.Secrets, sealedSecret{id, base64.RawURLEncoding.EncodeToString(sealed)})
	}
	s.mu.RUnlock()
	sort.Slice(state.Users, func(i, j int) bool { return state.Users[i].ID < state.Users[j].ID })
	sort.Slice(state.Projects, func(i, j int) bool { return state.Projects[i].ID < state.Projects[j].ID })
	sort.Slice(state.Devices, func(i, j int) bool { return state.Devices[i].ID < state.Devices[j].ID })
	sort.Slice(state.Tunnels, func(i, j int) bool { return state.Tunnels[i].ID < state.Tunnels[j].ID })
	sort.Slice(state.Credentials, func(i, j int) bool { return state.Credentials[i].ID < state.Credentials[j].ID })
	sort.Slice(state.Secrets, func(i, j int) bool { return state.Secrets[i].DeviceID < state.Secrets[j].DeviceID })
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > config.MaxJSONBytes {
		return ErrInvalidState
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func LoadState(path string, key []byte) (*MemoryStore, error) {
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
	if state.Version != 1 {
		return nil, ErrInvalidState
	}
	s := NewMemoryStore()
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
