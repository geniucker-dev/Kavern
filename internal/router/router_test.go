package router_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"github.com/geniucker-dev/kavern/internal/testutil"
)

type capturedRouteSession struct {
	*testutil.FakeSession
	stream session.AgentStream
	opened chan struct{}
}

func (s *capturedRouteSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	_, err := s.FakeSession.OpenStream(ctx, req)
	if s.opened != nil {
		close(s.opened)
	}
	return s.stream, err
}

type routeStream struct {
	net.Conn
	closes atomic.Int32
}

func (s *routeStream) Close() error { s.closes.Add(1); return s.Conn.Close() }

func TestRouteTCPNilInboundRejectedBeforeStreamCreation(t *testing.T) {
	st, manager := newRouterFixture(t)
	fake := testutil.NewFakeSession("tracked", "device-1")
	if err := manager.Attach(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Enabled: true}
	if err := router.New(st, manager).RouteTCP(context.Background(), tunnel, nil); !errors.Is(err, router.ErrInvalidInboundConnection) {
		t.Errorf("nil inbound error = %v, want ErrInvalidInboundConnection", err)
	}
	if fake.OpenCount() != 0 {
		t.Fatal("nil inbound created a remote stream")
	}
}

func TestRouteTCPCancellationPreservesMetadataOnlyAddress(t *testing.T) {
	st, manager := newRouterFixture(t)
	stream, target := net.Pipe()
	inbound, client := net.Pipe()
	tracked := &routeStream{Conn: stream}
	fake := &capturedRouteSession{FakeSession: testutil.NewFakeSession("tracked", "device-1"), stream: tracked, opened: make(chan struct{})}
	if err := manager.Attach(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = router.New(st, manager).RouteTCP(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Enabled: true, TargetAddr: "untrusted.example:9999"}, inbound)
	}()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		_ = target.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("route handler did not finish")
		}
	})
	select {
	case <-fake.opened:
	case <-time.After(5 * time.Second):
		t.Fatal("route did not open")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("route cancellation did not finish")
	}
	req := fake.OpenRequests[0]
	if req.TargetAddr != "" || req.RemoteAddr != inbound.RemoteAddr().String() || req.TunnelID != "tunnel-1" || req.Protocol != domain.TunnelProtocolTCP {
		t.Fatal("router changed stored-target-only request semantics")
	}
	if tracked.closes.Load() != 1 {
		t.Fatal("route did not release its stream")
	}
}

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

func TestRouteTCPNilInboundRequiresCurrentSessionFirst(t *testing.T) {
	ctx := context.Background()
	st, manager := newRouterFixture(t)
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:80", Enabled: true}

	if err := router.New(st, manager).RouteTCP(ctx, tunnel, nil); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("RouteTCP() error = %v, want ErrNoCurrentSession", err)
	}
}

func TestRouteTCPNilInboundRejectsDisabledTunnelAndDeviceFirst(t *testing.T) {
	ctx := context.Background()
	st, manager := newRouterFixture(t)
	fake := testutil.NewFakeSession("session-1", "device-1")
	if err := manager.Attach(ctx, fake); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	_ = st.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Enabled: false})
	if err := router.New(st, manager).RouteTCP(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Enabled: true}, nil); !errors.Is(err, router.ErrDisabledTunnel) {
		t.Fatalf("RouteTCP(disabled tunnel) error = %v, want ErrDisabledTunnel", err)
	}
	if fake.OpenCount() != 0 {
		t.Fatalf("OpenStream count after disabled tunnel = %d, want 0", fake.OpenCount())
	}

	disabledStore := store.NewMemoryStore()
	disabledManager := session.NewManager()
	if err := disabledStore.CreateDevice(ctx, domain.Device{ID: "device-2", ProjectID: "project-1", Enabled: false}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	_ = disabledStore.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-2", DeviceID: "device-2", Enabled: true})
	disabledFake := testutil.NewFakeSession("session-2", "device-2")
	if err := disabledManager.Attach(ctx, disabledFake); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if err := router.New(disabledStore, disabledManager).RouteTCP(ctx, domain.Tunnel{ID: "tunnel-2", DeviceID: "device-2", Enabled: true}, nil); !errors.Is(err, router.ErrDisabledDevice) {
		t.Fatalf("RouteTCP(disabled device) error = %v, want ErrDisabledDevice", err)
	}
	if disabledFake.OpenCount() != 0 {
		t.Fatalf("OpenStream count after disabled device = %d, want 0", disabledFake.OpenCount())
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
	_ = client.Close()
	if err := router.New(st, manager).RouteTCP(ctx, tunnel, server); err != nil {
		t.Fatalf("RouteTCP() error = %v", err)
	}
	if fake.OpenCount() != 1 {
		t.Fatalf("OpenStream count = %d, want 1", fake.OpenCount())
	}
	req := fake.OpenRequests[0]
	if req.TunnelID != tunnel.ID || req.Protocol != domain.TunnelProtocolTCP {
		t.Fatalf("OpenStream request = %+v", req)
	}
	if req.TargetAddr != "" {
		t.Fatalf("OpenStream TargetAddr = %q, want empty", req.TargetAddr)
	}
	if req.RemoteAddr != server.RemoteAddr().String() {
		t.Fatalf("OpenStream RemoteAddr = %q, want %q", req.RemoteAddr, server.RemoteAddr())
	}
}

func newRouterFixture(t *testing.T) (*store.MemoryStore, *session.Manager) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemoryStore()
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	_ = st.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, Listener: "tcp:1000", TargetAddr: "127.0.0.1:80", Enabled: true})
	return st, session.NewManager()
}
