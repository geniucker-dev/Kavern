//go:build legacy_npc_integration

package legacy_npc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	legacy "github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func TestLegacyNPCTCPEcho(t *testing.T) {
	npcBin := requireNPCBin(t)
	t.Logf("expecting yisier/nps %s stock npc; NPC_BIN basename=%s sha256=%s", pinnedNPSTag, filepath.Base(npcBin), sha256File(t, npcBin))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	decoyAddr, closeDecoy := startDecoyListener(t)
	defer closeDecoy()
	payload := []byte("legacy route payload must not select " + decoyAddr)
	echoAddr, waitEcho, closeEcho := startOneShotEchoTarget(t, payload)
	defer closeEcho()

	st := store.NewMemoryStore()
	if err := st.CreateUser(ctx, domain.User{ID: "user-1", Name: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProject(ctx, domain.Project{ID: "project-1", UserID: "user-1", Name: "project"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Name: "device", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTunnel(ctx, domain.Tunnel{
		ID:         "tunnel-1",
		DeviceID:   "device-1",
		Protocol:   domain.TunnelProtocolTCP,
		Listener:   "tcp:legacy-echo",
		TargetAddr: echoAddr,
		Enabled:    true,
	}); err != nil {
		t.Fatal(err)
	}
	issued, err := st.IssueLegacyCredential(ctx, "device-1", []byte("server-secret"))
	if err != nil {
		t.Fatal(err)
	}

	manager := newNotifyingSessionManager()
	gw, err := legacy.New(legacy.Config{ServerSecret: []byte("server-secret"), Store: st, Sessions: manager})
	if err != nil {
		t.Fatal(err)
	}
	legacyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer legacyListener.Close()
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- gw.Serve(serveCtx, legacyListener) }()

	cmdCtx, stopNPC := context.WithCancel(ctx)
	defer stopNPC()
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+legacyListener.Addr().String(), "-vkey="+issued.VKey)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	t.Logf("stock npc process started: pid=%d basename=%s", cmd.Process.Pid, filepath.Base(npcBin))
	npcDone := make(chan error, 1)
	go func() { npcDone <- cmd.Wait() }()

	select {
	case attached := <-manager.attached:
		if attached.Protocol() != domain.AgentProtocolLegacyNPC || attached.DeviceID() != "device-1" {
			t.Fatalf("attached legacy session metadata is invalid")
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for legacy main session attachment: %v", ctx.Err())
	}

	route := router.New(st, manager)
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, Enabled: true}
	readyCtx, stopReady := context.WithTimeout(ctx, 20*time.Second)
	defer stopReady()
	for {
		routeErr, clientErr := runPublicRouteAttempt(readyCtx, route, tunnel, payload)
		if routeErr == nil {
			if clientErr != nil {
				t.Fatalf("public TCP client failed after route opened: %v", clientErr)
			}
			break
		}
		if !shouldRetryLegacyRoute(routeErr) {
			t.Fatalf("public route failed without retry eligibility: %v", routeErr)
		}
		select {
		case <-readyCtx.Done():
			t.Fatalf("timeout waiting for legacy data channel: %v", readyCtx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}

	select {
	case err := <-waitEcho:
		if err != nil {
			t.Fatalf("one-shot target failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("echo target did not finish: %v", ctx.Err())
	}

	stopNPC()
	select {
	case err := <-npcDone:
		t.Logf("stock npc process exited: %v", err)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timeout waiting for stock npc process exit")
	}
	waitNoCurrent(t, ctx, manager, "device-1")
	stopServe()
	_ = legacyListener.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("gateway Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for gateway Serve() exit")
	}
}

func TestLegacyNPCMainReplacement(t *testing.T) {
	npcBin := requireNPCBin(t)
	t.Logf("expecting yisier/nps %s stock npc; NPC_BIN basename=%s sha256=%s", pinnedNPSTag, filepath.Base(npcBin), sha256File(t, npcBin))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	firstPayload := []byte("legacy replacement first echo")
	firstEchoAddr, waitFirstEcho, closeFirstEcho := startOneShotEchoTarget(t, firstPayload)
	defer closeFirstEcho()

	st := store.NewMemoryStore()
	if err := st.CreateUser(ctx, domain.User{ID: "user-1", Name: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProject(ctx, domain.Project{ID: "project-1", UserID: "user-1", Name: "project"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Name: "device", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	tunnel := domain.Tunnel{
		ID:         "tunnel-1",
		DeviceID:   "device-1",
		Protocol:   domain.TunnelProtocolTCP,
		Listener:   "tcp:legacy-replacement",
		TargetAddr: firstEchoAddr,
		Enabled:    true,
	}
	if err := st.CreateTunnel(ctx, tunnel); err != nil {
		t.Fatal(err)
	}
	issued, err := st.IssueLegacyCredential(ctx, "device-1", []byte("server-secret"))
	if err != nil {
		t.Fatal(err)
	}

	manager := newNotifyingSessionManager()
	gw, err := legacy.New(legacy.Config{ServerSecret: []byte("server-secret"), Store: st, Sessions: manager})
	if err != nil {
		t.Fatal(err)
	}
	legacyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer legacyListener.Close()
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- gw.Serve(serveCtx, legacyListener) }()

	stopA, npcADone := startStockNPC(t, ctx, npcBin, legacyListener.Addr().String(), issued.VKey)
	defer stopA()
	firstSession := waitAttachedLegacySession(t, ctx, manager, "")
	route := router.New(st, manager)
	routeWithLegacyReadinessRetry(t, ctx, route, tunnel, firstPayload)
	waitTargetResult(t, ctx, waitFirstEcho, "first replacement echo")

	stopB, npcBDone := startStockNPC(t, ctx, npcBin, legacyListener.Addr().String(), issued.VKey)
	defer stopB()
	secondSession := waitAttachedLegacySession(t, ctx, manager, firstSession.ID())
	stopA()
	waitNPCExit(t, npcADone, "first stock npc")

	secondPayload := []byte("legacy replacement final echo")
	secondEchoAddr, waitSecondEcho, closeSecondEcho := startOneShotEchoTarget(t, secondPayload)
	defer closeSecondEcho()
	tunnel.TargetAddr = secondEchoAddr
	if err := st.CreateTunnel(ctx, tunnel); err != nil {
		t.Fatal(err)
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if current.ID() != secondSession.ID() {
		t.Fatalf("current session = %q, want replacement %q", current.ID(), secondSession.ID())
	}
	routeWithLegacyReadinessRetry(t, ctx, route, tunnel, secondPayload)
	waitTargetResult(t, ctx, waitSecondEcho, "second replacement echo")

	stopB()
	waitNPCExit(t, npcBDone, "second stock npc")
	waitNoCurrent(t, ctx, manager, "device-1")
	stopServe()
	_ = legacyListener.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("gateway Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for gateway Serve() exit")
	}
}

func startStockNPC(t *testing.T, parent context.Context, npcBin, serverAddr, vkey string) (func(), <-chan error) {
	t.Helper()
	cmdCtx, stop := context.WithCancel(parent)
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+serverAddr, "-vkey="+vkey)
	if err := cmd.Start(); err != nil {
		stop()
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	t.Logf("stock npc process started: pid=%d basename=%s", cmd.Process.Pid, filepath.Base(npcBin))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return stop, done
}

func waitAttachedLegacySession(t *testing.T, ctx context.Context, manager *notifyingSessionManager, previous domain.SessionID) session.AgentSession {
	t.Helper()
	for {
		select {
		case attached := <-manager.attached:
			if attached.Protocol() == domain.AgentProtocolLegacyNPC && attached.DeviceID() == "device-1" && attached.ID() != previous {
				return attached
			}
		case <-ctx.Done():
			t.Fatalf("timeout waiting for replacement legacy session: %v", ctx.Err())
		}
	}
}

func routeWithLegacyReadinessRetry(t *testing.T, ctx context.Context, route router.TunnelRouter, tunnel domain.Tunnel, payload []byte) {
	t.Helper()
	readyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		routeErr, clientErr := runPublicRouteAttempt(readyCtx, route, tunnel, payload)
		if routeErr == nil {
			if clientErr != nil {
				t.Fatalf("public TCP client failed after route opened: %v", clientErr)
			}
			return
		}
		if !shouldRetryLegacyRoute(routeErr) {
			t.Fatalf("public route failed without retry eligibility: %v", routeErr)
		}
		select {
		case <-readyCtx.Done():
			t.Fatalf("timeout waiting for legacy data channel: %v", readyCtx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func waitTargetResult(t *testing.T, ctx context.Context, result <-chan error, label string) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s failed: %v", label, err)
		}
	case <-ctx.Done():
		t.Fatalf("%s did not finish: %v", label, ctx.Err())
	}
}

func waitNPCExit(t *testing.T, done <-chan error, label string) {
	t.Helper()
	select {
	case err := <-done:
		t.Logf("%s exited: %v", label, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s exit", label)
	}
}

type notifyingSessionManager struct {
	inner    *session.Manager
	attached chan session.AgentSession
}

func newNotifyingSessionManager() *notifyingSessionManager {
	return &notifyingSessionManager{
		inner:    session.NewManager(),
		attached: make(chan session.AgentSession, 4),
	}
}

func (m *notifyingSessionManager) Attach(ctx context.Context, next session.AgentSession) error {
	if err := m.inner.Attach(ctx, next); err != nil {
		return err
	}
	select {
	case m.attached <- next:
	default:
	}
	return nil
}

func (m *notifyingSessionManager) Detach(ctx context.Context, id domain.SessionID) error {
	return m.inner.Detach(ctx, id)
}

func (m *notifyingSessionManager) CurrentForDevice(ctx context.Context, id domain.DeviceID) (session.AgentSession, error) {
	return m.inner.CurrentForDevice(ctx, id)
}

func (m *notifyingSessionManager) ListForDevice(ctx context.Context, id domain.DeviceID) ([]session.AgentSessionInfo, error) {
	return m.inner.ListForDevice(ctx, id)
}

func runPublicRouteAttempt(ctx context.Context, route router.TunnelRouter, tunnel domain.Tunnel, payload []byte) (error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err, err
	}
	defer listener.Close()
	routeDone := make(chan error, 1)
	go func() {
		inbound, err := listener.Accept()
		if err != nil {
			routeDone <- err
			return
		}
		defer inbound.Close()
		routeDone <- route.RouteTCP(ctx, tunnel, inbound)
	}()

	dialer := net.Dialer{}
	client, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return <-routeDone, err
	}
	clientDone := make(chan error, 1)
	go func() {
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		if err := writeAllIntegration(client, payload); err != nil {
			clientDone <- err
			return
		}
		if tcp, ok := client.(*net.TCPConn); ok {
			if err := tcp.CloseWrite(); err != nil {
				clientDone <- err
				return
			}
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(client, response); err != nil {
			clientDone <- err
			return
		}
		if string(response) != string(payload) {
			clientDone <- fmt.Errorf("echo payload mismatch")
			return
		}
		clientDone <- nil
	}()

	routeErr := <-routeDone
	clientErr := <-clientDone
	return routeErr, clientErr
}

func startOneShotEchoTarget(t *testing.T, payload []byte) (string, <-chan error, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workerDone := make(chan struct{})
	var connMu sync.Mutex
	var activeConn net.Conn
	go func() {
		defer close(workerDone)
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		connMu.Lock()
		activeConn = conn
		connMu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			done <- err
			return
		}
		if string(got) != string(payload) {
			done <- errors.New("target received unexpected payload")
			return
		}
		done <- writeAllIntegration(conn, got)
	}()
	cleanup := func() {
		_ = listener.Close()
		connMu.Lock()
		conn := activeConn
		connMu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		select {
		case <-workerDone:
		case <-time.After(time.Second):
			t.Fatal("one-shot echo target did not stop")
		}
	}
	return listener.Addr().String(), done, cleanup
}

func shouldRetryLegacyRoute(err error) bool {
	return errors.Is(err, legacy.ErrLegacyDataChannelUnavailable)
}

func writeAllIntegration(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func TestLegacyRouteRetryClassification(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{err: legacy.ErrLegacyDataChannelUnavailable, want: true},
		{err: fmt.Errorf("wrapped: %w", legacy.ErrLegacyDataChannelUnavailable), want: true},
		{err: legacy.ErrLegacyDataChannelReplaced, want: false},
		{err: legacy.ErrLegacyProtocol, want: false},
		{err: legacy.ErrLegacyReceiveLimit, want: false},
		{err: legacy.ErrLegacyPingTimeout, want: false},
		{err: context.DeadlineExceeded, want: false},
	}
	for _, tt := range tests {
		if got := shouldRetryLegacyRoute(tt.err); got != tt.want {
			t.Fatalf("shouldRetryLegacyRoute(%v) = %t, want %t", tt.err, got, tt.want)
		}
	}
}

func startDecoyListener(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("decoy listener did not stop")
		}
		select {
		case <-accepted:
			t.Fatal("decoy listener received a connection")
		default:
		}
	}
}

var _ session.SessionManager = (*notifyingSessionManager)(nil)
