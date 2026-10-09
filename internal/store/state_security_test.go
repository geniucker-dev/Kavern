package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

func TestStateCiphertextTamperDeviceBindingAndSymlink(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	_ = s.CreateUser(ctx, domain.User{ID: "user"})
	_ = s.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"})
	for _, id := range []domain.DeviceID{"a", "b"} {
		_ = s.CreateDevice(ctx, domain.Device{ID: id, ProjectID: "project", Enabled: true})
		_ = s.SetKAPv1DeviceSecret(ctx, id, bytes.Repeat([]byte(string(id)), 32))
	}
	key := bytes.Repeat([]byte{8}, 32)
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "state.json")
	if err := s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var original stateFile
	if err = json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tampered", "wrong-device"} {
		t.Run(name, func(t *testing.T) {
			var state stateFile
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			if name == "tampered" {
				b, err := base64.RawURLEncoding.DecodeString(state.Secrets[0].Ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-1] ^= 1
				state.Secrets[0].Ciphertext = base64.RawURLEncoding.EncodeToString(b)
			} else {
				state.Secrets[0].Ciphertext, state.Secrets[1].Ciphertext = state.Secrets[1].Ciphertext, state.Secrets[0].Ciphertext
			}
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadState(path, key); err == nil {
				t.Fatal("unauthenticated ciphertext accepted")
			}
		})
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadState(link, key); err == nil {
		t.Fatal("symlink read accepted")
	}
	if err = s.SaveState(link, key); err == nil {
		t.Fatal("symlink write accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("symlink target changed")
	}
	if err = s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, again) {
		t.Fatal("cipher nonce reused")
	}
}
