package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

func TestNativeStartupRejectsCanonicalProjectionOverLimit(t *testing.T) {
	owner, path, key := ownerFixture(t, defaultStateFiles())
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state stateFile
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	state.Tunnels = nil
	for i := 0; i < config.MaxNativeTunnels; i++ {
		state.Tunnels = append(state.Tunnels, domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i) + strings.Repeat("x", 123)), DeviceID: "a", Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 10000+i)), TargetAddr: strings.Repeat("\u2028", 160) + ":1", Enabled: true})
	}
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	// Valid UTF-8 JSON can represent U+2028 literally; LoadState accepts this
	// bounded v1 file. Canonical outgoing JSON escapes it and exceeds 1 MiB.
	raw = bytes.ReplaceAll(raw, []byte(`\u2028`), []byte("\u2028"))
	if len(raw) > config.MaxJSONBytes {
		t.Fatalf("fixture exceeds state input bound: %d", len(raw))
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	current, err := OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	desired, err := current.DeviceConfiguration(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = config.ValidateDeviceConfiguration(desired, true); err != nil {
		t.Fatalf("fixture violates shape bounds: %v", err)
	}
	_, snapshotErr := current.NativeSnapshot(context.Background(), "a")
	if snapshotErr == nil {
		t.Fatal("fixture did not exceed canonical snapshot bound")
	}
	if err = current.ValidateNativeStartup(context.Background()); err == nil {
		t.Fatalf("startup accepted a bounded valid state file (%d bytes) whose native snapshot cannot be sent: %v", len(raw), snapshotErr)
	}
}
