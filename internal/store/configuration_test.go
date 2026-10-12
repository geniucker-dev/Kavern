package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

func TestMemoryTunnelReindexRejectsConflictAtomically(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	_ = s.CreateDevice(ctx, domain.Device{ID: "a"})
	a := domain.Tunnel{ID: "one", DeviceID: "a", Listener: "first"}
	b := domain.Tunnel{ID: "two", DeviceID: "a", Listener: "second"}
	if err := s.CreateTunnel(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTunnel(ctx, b); err != nil {
		t.Fatal(err)
	}
	a.Listener = "second"
	if err := s.CreateTunnel(ctx, a); !errors.Is(err, ErrListenerConflict) {
		t.Fatal("conflict accepted", err)
	}
	if got, err := s.FindTunnelByListener(ctx, "first"); err != nil || got.ID != "one" {
		t.Fatal("conflict changed old index")
	}
	a.Listener = "third"
	if err := s.CreateTunnel(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindTunnelByListener(ctx, "first"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale listener retained")
	}
	if got, err := s.FindTunnelByListener(ctx, "third"); err != nil || got.ID != "one" {
		t.Fatal("replacement index missing")
	}
}

func TestConfigOwnerGlobalListenerLimitAndDisabledProjection(t *testing.T) {
	o, path, _ := ownerFixture(t, defaultStateFiles())
	c := desired(t, o, "a")
	c.Tunnels = nil
	for i := 0; i < config.MaxPublicListeners-1; i++ {
		c.Tunnels = append(c.Tunnels, domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i)), DeviceID: "a", Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 10000+i)), TargetAddr: "127.0.0.1:2001", Enabled: true})
	}
	if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err != nil {
		t.Fatal("exact global listener limit", err)
	}
	c = desired(t, o, "a")
	before := readBytes(t, path)
	c.Tunnels = append(c.Tunnels, domain.Tunnel{ID: "extra", DeviceID: "a", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:30000", TargetAddr: "127.0.0.1:2001", Enabled: true})
	if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c}); !errors.Is(err, config.ErrInvalidBusinessConfig) {
		t.Fatal("global listener limit bypassed", err)
	}
	if string(before) != string(readBytes(t, path)) {
		t.Fatal("global overflow wrote file")
	}
	c.Tunnels[len(c.Tunnels)-1].Enabled = false
	if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err != nil {
		t.Fatal("disabled record consumed public listener", err)
	}
	c = desired(t, o, "a")
	c.Device.Enabled = false
	if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err != nil {
		t.Fatal(err)
	}
	if snap, err := o.NativeSnapshot(context.Background(), "a"); err != nil || len(snap.Tunnels) != 0 {
		t.Fatal("disabled native projection exposed targets", err)
	}
}
