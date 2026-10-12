package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
)

func TestLifecycleStartupOverflowPreservesStateAndReleasesLock(t *testing.T) {
	// This durable projection fits schema-only transmission but not lifecycle v1.
	// It remains readable for repair; synchronized serving must reject it before
	// constructing listener services or changing the file.
	ctx := context.Background()
	state := store.NewMemoryStore()
	device := domain.DeviceID(strings.Repeat("d", 128))
	key := bytes.Repeat([]byte{0x44}, 32)
	for _, e := range []error{state.CreateUser(ctx, domain.User{ID: "u"}), state.CreateProject(ctx, domain.Project{ID: "p", UserID: "u"}), state.CreateDevice(ctx, domain.Device{ID: device, ProjectID: "p", Enabled: true}), state.SetKAPv1DeviceSecret(ctx, device, bytes.Repeat([]byte{0x33}, 32))} {
		if e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < config.MaxNativeTunnels; i++ {
		if e := state.CreateTunnel(ctx, domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i) + strings.Repeat("x", 123)), DeviceID: device, Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 10000+i)), TargetAddr: strings.Repeat("a", 499) + ":1", Enabled: true}); e != nil {
			t.Fatal(e)
		}
	}
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if e := state.SaveState(path, key); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	fixture, _, _, _, _ := serviceFixture(t, "127.0.0.1:2001")
	svc, e := newSyncService(path, key, fixture.trust)
	if e == nil {
		_ = svc.Close()
		t.Fatal("unrepresentable synchronized startup was accepted")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed startup modified durable state", e)
	}
	owner, e := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal("failed startup retained state lock", e)
	}
	defer owner.Close()
	if e = owner.ValidateNativeStartup(ctx); e == nil {
		t.Fatal("overflow fixture no longer exercises startup preflight")
	}
	desired, e := owner.DeviceConfiguration(ctx, device)
	if e != nil {
		t.Fatal("historical configuration cannot be read for repair", e)
	}
	desired.Device.Name = "proposed change"
	if _, e = owner.Commit(ctx, []domain.DeviceConfiguration{desired}); e == nil {
		t.Fatal("mutation persisted an unrepresentable projection")
	}
	after, e = os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected mutation modified durable state", e)
	}

}
