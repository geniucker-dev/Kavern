package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineCredentialRotationDisableAndOutputBoundaries(t *testing.T) {
	master := bytes.Repeat([]byte{33}, 32)
	server := bytes.Repeat([]byte{44}, 32)
	t.Setenv("KAVERN_TEST_MASTER", base64.RawURLEncoding.EncodeToString(master))
	t.Setenv("KAVERN_TEST_SERVER", base64.RawURLEncoding.EncodeToString(server))
	path := filepath.Join(t.TempDir(), "private", "state.json")
	common := []string{"-state", path, "-master-key-env", "KAVERN_TEST_MASTER"}
	ctx := context.Background()
	call := func(args ...string) []byte {
		t.Helper()
		var out, diagnostics bytes.Buffer
		if err := run(append(args, common...), &out, &diagnostics); err != nil {
			t.Fatalf("CLI %s failed: %v", args[0], err)
		}
		if diagnostics.Len() != 0 {
			t.Fatal("successful CLI emitted diagnostics")
		}
		return out.Bytes()
	}
	call("init-state", "-user", "user", "-project", "project")
	var native struct {
		Secret string `json:"device_secret"`
	}
	if err := json.Unmarshal(call("add-device", "-id", "native", "-project", "project"), &native); err != nil || native.Secret == "" {
		t.Fatal("native issuance missing")
	}
	old, _ := base64.RawURLEncoding.DecodeString(native.Secret)
	var next struct {
		Secret string `json:"device_secret"`
	}
	if err := json.Unmarshal(call("rotate-device", "-id", "native"), &next); err != nil || next.Secret == "" || native.Secret == next.Secret {
		t.Fatal("rotation did not replace secret")
	}
	loaded, err := store.LoadState(path, master)
	if err != nil {
		t.Fatal(err)
	}
	_, current, err := loaded.ResolveKAPv1DeviceForAuth(ctx, "native")
	if err != nil || bytes.Equal(old, current) {
		t.Fatal("old secret survived restart")
	}
	var legacy struct {
		VKey string `json:"vkey"`
	}
	if err := json.Unmarshal(call("add-device", "-id", "legacy", "-project", "project", "-kind", "legacy", "-server-secret-env", "KAVERN_TEST_SERVER"), &legacy); err != nil || legacy.VKey == "" {
		t.Fatal("legacy issuance missing")
	}
	wire, err := security.LegacyWireTokenFromVKey(legacy.VKey)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := security.LegacyLookupKey(server, wire)
	if err != nil {
		t.Fatal(err)
	}
	var legacyNext struct {
		VKey string `json:"vkey"`
	}
	if err := json.Unmarshal(call("rotate-device", "-id", "legacy", "-kind", "legacy", "-server-secret-env", "KAVERN_TEST_SERVER"), &legacyNext); err != nil || legacyNext.VKey == "" {
		t.Fatal("legacy rotation missing")
	}
	nextWire, err := security.LegacyWireTokenFromVKey(legacyNext.VKey)
	if err != nil {
		t.Fatal(err)
	}
	nextLookup, err := security.LegacyLookupKey(server, nextWire)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err = store.LoadState(path, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.ResolveLegacyDeviceForAuth(ctx, lookup); err == nil {
		t.Fatal("old legacy token survived restart")
	}
	for _, id := range []string{"native", "legacy"} {
		out := call("set-device-enabled", "-id", id, "-enabled=false")
		for _, secret := range []string{native.Secret, next.Secret, legacy.VKey, wire, lookup} {
			if bytes.Contains(out, []byte(secret)) {
				t.Fatal("credential leaked in mutation output")
			}
		}
	}
	loaded, err = store.LoadState(path, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := loaded.ResolveKAPv1DeviceForAuth(ctx, "native"); err == nil {
		t.Fatal("disabled native authenticated")
	}
	if _, err := loaded.ResolveLegacyDeviceForAuth(ctx, nextLookup); err == nil {
		t.Fatal("disabled current legacy credential authenticated")
	}
	dev, err := loaded.GetDevice(ctx, "legacy")
	if err != nil || dev.Enabled {
		t.Fatal("legacy disabled state not persisted")
	}
	call("add-tunnel", "-id", "tunnel", "-device", "native", "-listen", "127.0.0.1:0", "-target", "127.0.0.1:9")
	call("set-tunnel-enabled", "-id", "tunnel", "-enabled=false")
	loaded, err = store.LoadState(path, master)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := loaded.GetTunnel(ctx, "tunnel")
	if err != nil || tunnel.Enabled {
		t.Fatal("tunnel disabled state not persisted")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{native.Secret, next.Secret, legacy.VKey, legacyNext.VKey, wire, nextWire} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext credential persisted")
		}
	}
	var out, diag bytes.Buffer
	err = run(append([]string{"set-device-enabled", "-id", "native"}, common...), &out, &diag)
	if err == nil || out.Len() != 0 {
		t.Fatal("implicit disable accepted or output on failure")
	}
}
