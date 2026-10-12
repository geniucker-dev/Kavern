package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"github.com/geniucker-dev/kavern/internal/testutil"
)

type publicRouteSession struct {
	*testutil.FakeSession
	carrier *carrier.Carrier
	opened  chan context.Context
}

func (s *publicRouteSession) OpenStream(ctx context.Context, _ domain.StreamOpenRequest) (session.AgentStream, error) {
	if s.carrier == nil {
		s.opened <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	lease, err := s.carrier.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	s.opened <- ctx
	return &publicRouteStream{Lease: lease}, nil
}

type publicRouteStream struct{ *carrier.Lease }

func (s *publicRouteStream) Read(p []byte) (int, error)  { return s.Stream.Read(p) }
func (s *publicRouteStream) Write(p []byte) (int, error) { return s.Stream.Write(p) }
func (s *publicRouteStream) Close() error                { return s.Release() }
func (s *publicRouteStream) CloseWrite() error {
	return s.Stream.(interface{ CloseWrite() error }).CloseWrite()
}

// Exercise a socket timeout before the route deadline. Directional request EOF
// must not let a silent response reader keep the route alive indefinitely.
type earlyDeadlineConn struct{ net.Conn }

func (c earlyDeadlineConn) SetDeadline(time.Time) error {
	return c.Conn.SetDeadline(time.Now().Add(25 * time.Millisecond))
}

func publicRouteFixture(t *testing.T, agent *publicRouteSession) (*router.Router, domain.Tunnel) {
	t.Helper()
	state := store.NewMemoryStore()
	ctx := context.Background()
	_ = state.CreateDevice(ctx, domain.Device{ID: "device", Enabled: true})
	manager := session.NewManager()
	if err := manager.Attach(ctx, agent); err != nil {
		t.Fatal(err)
	}
	tunnel := domain.Tunnel{ID: "tunnel", DeviceID: "device", Protocol: domain.TunnelProtocolTCP, Enabled: true}
	_ = state.CreateTunnel(ctx, tunnel)
	return router.New(state, manager), tunnel
}

func TestPublicRouteTimeoutReleasesSilentMuxLeaseAndHandlerSlot(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	left, right := net.Pipe()
	backend := mux.NewSmuxBackend()
	local, err := backend.Client(left, mux.Config{})
	if err != nil {
		left.Close()
		right.Close()
		t.Fatal(err)
	}
	defer local.Close()
	remote, err := backend.Server(right, mux.Config{})
	if err != nil {
		right.Close()
		t.Fatal(err)
	}
	defer remote.Close()
	c, err := carrier.New(local, carrier.Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	agent := &publicRouteSession{FakeSession: testutil.NewFakeSession("public-route", "device"), carrier: c, opened: make(chan context.Context, 1)}
	routes, tunnel := publicRouteFixture(t, agent)
	peerEOF := make(chan error, 1)
	release := make(chan struct{})
	peerDone := make(chan struct{})
	var releaseOnce sync.Once
	releasePeer := func() { releaseOnce.Do(func() { close(release) }) }
	go func() {
		defer close(peerDone)
		peer, err := remote.AcceptStream(parent)
		if err != nil {
			peerEOF <- err
			return
		}
		defer peer.Close()
		_, err = io.Copy(io.Discard, peer)
		peerEOF <- err
		<-release
	}()
	defer func() {
		cancel()
		releasePeer()
		remote.Close()
		local.Close()
		select {
		case <-peerDone:
		case <-time.After(time.Second):
			t.Error("silent peer worker did not join")
		}
	}()
	inbound, client := net.Pipe()
	defer client.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	routeResult := make(chan error, 1)
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		serveConnection(parent, earlyDeadlineConn{inbound}, func(conn net.Conn) {
			routeResult <- servePublicRoute(parent, routes, tunnel, conn, 300*time.Millisecond)
		}, slots)
	}()
	defer func() {
		cancel()
		select {
		case <-handled:
		case <-time.After(time.Second):
			t.Error("public handler did not join")
		}
	}()
	var routeCtx context.Context
	select {
	case routeCtx = <-agent.opened:
	case <-time.After(time.Second):
		t.Fatal("route never opened leased stream")
	}
	select {
	case err := <-peerEOF:
		if err != nil {
			t.Fatalf("request EOF failed: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("local timeout did not produce request EOF")
	}
	if routeCtx.Err() != nil {
		t.Fatal("route expired before silent-response condition was established")
	}
	if c.ActiveStreams() != 1 || len(slots) != 1 {
		t.Fatal("silent response did not retain a live route before its deadline")
	}
	select {
	case <-handled:
	case <-time.After(700 * time.Millisecond):
		t.Fatal("route deadline failed to retire silent mux response")
	}
	if err := <-routeResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("route timeout result=%v", err)
	}
	if parent.Err() != nil {
		t.Fatal("route retirement canceled daemon context")
	}
	if _, ok := routeCtx.Deadline(); !ok || !errors.Is(routeCtx.Err(), context.DeadlineExceeded) {
		t.Fatal("stream opening did not receive bounded route context")
	}
	if c.ActiveStreams() != 0 {
		t.Fatal("route deadline retained stream lease")
	}
	select {
	case slots <- struct{}{}:
		<-slots
	default:
		t.Fatal("route deadline retained handler slot")
	}
	lease, err := c.OpenStream(parent)
	if err != nil {
		t.Fatalf("released stream capacity not reusable: %v", err)
	}
	if err = lease.Release(); err != nil {
		t.Fatal(err)
	}
	releasePeer()
	<-peerDone
}

func TestPublicRouteTimeoutAlsoBoundsStreamOpening(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent := &publicRouteSession{FakeSession: testutil.NewFakeSession("opening-route", "device"), opened: make(chan context.Context, 1)}
	routes, tunnel := publicRouteFixture(t, agent)
	inbound, client := net.Pipe()
	defer client.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	handled := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(handled)
		serveConnection(parent, inbound, func(conn net.Conn) { result <- servePublicRoute(parent, routes, tunnel, conn, 25*time.Millisecond) }, slots)
	}()
	defer func() {
		cancel()
		select {
		case <-handled:
		case <-time.After(time.Second):
			t.Error("opening handler did not join")
		}
	}()
	select {
	case ctx := <-agent.opened:
		if _, ok := ctx.Deadline(); !ok {
			t.Error("stream opening context has no deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("stream opening never started")
	}
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("stream opening exceeded route deadline")
	}
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("opening timeout result=%v", err)
	}
	if len(slots) != 0 || parent.Err() != nil {
		t.Fatal("opening timeout retained slot or canceled daemon")
	}
}
