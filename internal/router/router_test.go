package router_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/router"
	"github.com/zhuhaoyu/kavern/internal/session"
	"github.com/zhuhaoyu/kavern/internal/store"
	"github.com/zhuhaoyu/kavern/internal/testutil"
)

func TestResolveTunnelRejectsDisabledTunnel(t *testing.T) {
	ctx := context.Background()
	st, manager := newRouterFixture(t)
	rt := router.New(st, manager)
	if err := st.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Listener: "tcp:1000", Enabled: false}); err != nil {
		t.Fatalf("CreateTunnel() error = %v", err)
	}

	if _, err := rt.ResolveTunnel(ctx, "tcp:1000"); !errors.Is(err, router.ErrDisabledTunnel) {
		t.Fatalf("ResolveTunnel() error = %v, want ErrDisabledTunnel", err)
	}
}

func TestResolveTunnelRejectsDisabledDevice(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	manager := session.NewManager()
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: false}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := st.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Listener: "tcp:1000", Enabled: true}); err != nil {
		t.Fatalf("CreateTunnel() error = %v", err)
	}

	if _, err := router.New(st, manager).ResolveTunnel(ctx, "tcp:1000"); !errors.Is(err, router.ErrDisabledDevice) {
		t.Fatalf("ResolveTunnel() error = %v, want ErrDisabledDevice", err)
	}
}

func TestRouteTCPRequiresCurrentSession(t *testing.T) {
	ctx := context.Background()
	st, manager := newRouterFixture(t)
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:80", Enabled: true}

	if err := router.New(st, manager).RouteTCP(ctx, tunnel, nil); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("RouteTCP() error = %v, want ErrNoCurrentSession", err)
	}
}

func TestRouteTCPOpensStreamForEnabledTunnelAndDevice(t *testing.T) {
	ctx := context.Background()
	st, manager := newRouterFixture(t)
	fake := testutil.NewFakeSession("session-1", "device-1")
	if err := manager.Attach(ctx, fake); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:80", Enabled: true}

	server, client := net.Pipe()
	defer client.Close()
	if err := router.New(st, manager).RouteTCP(ctx, tunnel, server); err != nil {
		t.Fatalf("RouteTCP() error = %v", err)
	}
	if fake.OpenCount() != 1 {
		t.Fatalf("OpenStream count = %d, want 1", fake.OpenCount())
	}
}

func newRouterFixture(t *testing.T) (*store.MemoryStore, *session.Manager) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemoryStore()
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	return st, session.NewManager()
}
