package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeBootstrapMigrationDiagnosticsNeverEchoValues(t *testing.T) {
	for _, key := range []string{"targets", "carriers", "limits"} {
		t.Run(key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.json")
			secret := "fixture-sensitive-marker"
			data := `{"server":"127.0.0.1:1","device_id":"d","secret_env":"TEST","ca_file":"ca","` + key + `":"` + secret + `"}`
			_ = os.WriteFile(path, []byte(data), 0600)
			_, err := LoadNativeBootstrap(path)
			if err == nil || !strings.Contains(err.Error(), "on the server") || strings.Contains(err.Error(), secret) {
				t.Fatal("unsafe or missing migration diagnostic", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "server.json")
	_ = os.WriteFile(path, []byte(`{"limits":{"max_streams":64}}`), 0600)
	if _, err := LoadNativeServer(path); err == nil || !strings.Contains(err.Error(), "server-owned device state") {
		t.Fatal("server tuning silently ignored", err)
	}
}
func TestNativeServerKeepsExplicitLegacyBootstrapBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	_ = os.WriteFile(path, []byte(`{"control_listen":"127.0.0.1:0","legacy_listen":"127.0.0.1:0","cert_file":"c","key_file":"k","state_file":"s","master_key_env":"MASTER","server_secret_env":"LEGACY"}`), 0600)
	cfg, err := LoadNativeServer(path)
	if err != nil || cfg.LegacyListen == "" || cfg.ServerSecretEnv != "LEGACY" {
		t.Fatal("legacy transport bootstrap lost", err)
	}
}
