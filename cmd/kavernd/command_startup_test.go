package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
	"os"
	"strings"
	"testing"
)

func TestCommandStartupRejectsProjectionBeforeListenersAndReleasesLock(t *testing.T) {
	// Prepare the same valid v1 encoding-expansion case through ordinary store
	// APIs. No production listener/admin injection is used for this preflight.
	original, _, path, key, _ := serviceFixture(t, "127.0.0.1:2001")
	trust := original.trust
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err = json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var tunnels []domain.Tunnel
	for i := 0; i < config.MaxNativeTunnels; i++ {
		tunnels = append(tunnels, domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i) + strings.Repeat("x", 123)), DeviceID: "device", Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 10000+i)), TargetAddr: strings.Repeat(string(rune(0x2028)), 160) + ":1", Enabled: true})
	}
	encoded, err := json.Marshal(tunnels)
	if err != nil {
		t.Fatal(err)
	}
	file["Tunnels"] = encoded
	raw, err = json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte{92, 117, 50, 48, 50, 56}, []byte(string(rune(0x2028))))
	if len(raw) > config.MaxJSONBytes {
		t.Fatal("fixture violates input bound")
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	service, err := newSyncService(path, key, trust)
	if err == nil {
		_ = service.Close()
		t.Fatal("unusable projection passed command startup")
	}
	if service != nil || !strings.Contains(err.Error(), "native state migration required") {
		t.Fatal("startup did not fail before constructing a runnable listener service", err)
	}
	// Run cannot be entered on the nil result. Validation precedes all native,
	// legacy and public listener creation; reopening proves rejected ownership joined.
	reopened, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal("migration rejection retained state lock", err)
	}
	defer reopened.Close()
	if _, err = reopened.NativeSnapshot(context.Background(), "device"); err == nil {
		t.Fatal("fixture did not exceed full projection bound")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("startup silently rewrote incompatible state", err)
	}
}
