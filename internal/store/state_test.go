package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func TestEncryptedStateRoundTripAndTamper(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	_ = s.CreateUser(ctx, domain.User{ID: "user"})
	_ = s.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"})
	_ = s.CreateDevice(ctx, domain.Device{ID: "device", ProjectID: "project", Enabled: true})
	secret := bytes.Repeat([]byte{0x51}, 32)
	_ = s.SetKAPv1DeviceSecret(ctx, "device", secret)
	key := bytes.Repeat([]byte{0x62}, 32)
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if err := s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext secret persisted")
	}
	loaded, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := loaded.ResolveKAPv1DeviceForAuth(ctx, "device")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal("secret round trip failed")
	}
	if _, err = LoadState(path, bytes.Repeat([]byte{0x63}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadState(path, key); err == nil {
		t.Fatal("public state accepted")
	}
}
func TestLocalStateLockExcludesConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	unlock, err := LockState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if second, err := LockState(path); err == nil {
		second()
		t.Fatal("concurrent writer acquired lock")
	}
}

func TestLegacyCredentialStateSupportsMaximumDeviceID(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	_ = s.CreateUser(ctx, domain.User{ID: "user"})
	_ = s.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"})
	id := domain.DeviceID(strings.Repeat("d", 128))
	_ = s.CreateDevice(ctx, domain.Device{ID: id, ProjectID: "project", Enabled: true})
	issued, err := s.IssueLegacyCredential(ctx, id, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "state.json")
	key := bytes.Repeat([]byte{2}, 32)
	if err = s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	device, err := loaded.ResolveLegacyDeviceForAuth(ctx, issued.Credential.LegacyLookupKey)
	if err != nil || device.ID != id {
		t.Fatalf("legacy credential reload failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(issued.VKey)) {
		t.Fatal("raw vkey persisted")
	}
}
