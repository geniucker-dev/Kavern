//go:build legacy_npc_integration

package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	legacy "github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

// The acceptance fixture uses only public interfaces. Worker completion, process
// exit and session changes have explicit events; private mux state is inspected
// separately in build-tagged gateway-package companion tests.
type realMatrixManager struct {
	inner   *session.Manager
	mu      sync.Mutex
	changed chan struct{}
}

func newRealMatrixManager() *realMatrixManager {
	return &realMatrixManager{inner: session.NewManager(), changed: make(chan struct{})}
}
func (m *realMatrixManager) notify() {
	m.mu.Lock()
	close(m.changed)
	m.changed = make(chan struct{})
	m.mu.Unlock()
}
func (m *realMatrixManager) Attach(ctx context.Context, s session.AgentSession) error {
	err := m.inner.Attach(ctx, s)
	m.notify()
	return err
}
func (m *realMatrixManager) Detach(ctx context.Context, id domain.SessionID) error {
	err := m.inner.Detach(ctx, id)
	m.notify()
	return err
}
func (m *realMatrixManager) CurrentForDevice(ctx context.Context, id domain.DeviceID) (session.AgentSession, error) {
	return m.inner.CurrentForDevice(ctx, id)
}
func (m *realMatrixManager) ListForDevice(ctx context.Context, id domain.DeviceID) ([]session.AgentSessionInfo, error) {
	return m.inner.ListForDevice(ctx, id)
}
func (m *realMatrixManager) wait(t *testing.T, ctx context.Context, id domain.DeviceID, previous domain.SessionID, online bool) session.AgentSession {
	t.Helper()
	for {
		m.mu.Lock()
		change := m.changed
		m.mu.Unlock()
		s, err := m.inner.CurrentForDevice(ctx, id)
		if online && err == nil && s.ID() != previous {
			return s
		}
		if !online && errors.Is(err, session.ErrNoCurrentSession) {
			return nil
		}
		select {
		case <-change:
		case <-ctx.Done():
			t.Fatal("session transition deadline")
			return nil
		}
	}
}

type realMatrixProcess struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	once   sync.Once
}

func (p *realMatrixProcess) stop(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("NPC process did not exit")
		}
	})
}

type realMatrixTarget struct {
	listener      net.Listener
	mu            sync.Mutex
	active        map[net.Conn]struct{}
	accepted      int
	acceptedEvent chan struct{}
	acceptDone    chan struct{}
	workers       sync.WaitGroup
	once          sync.Once
	closeAfter    int
	gate          chan struct{}
	gateAt        int
	closed        chan struct{}
	probeEOF      bool
	probes        chan realMatrixEOFProbe
}
type realMatrixEOFProbe struct {
	ordinal int
	err     error
}

func newRealMatrixTarget(t *testing.T, closeAfter int) *realMatrixTarget {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &realMatrixTarget{listener: l, active: make(map[net.Conn]struct{}), acceptedEvent: make(chan struct{}), acceptDone: make(chan struct{}), closeAfter: closeAfter, probeEOF: closeAfter < 0, probes: make(chan realMatrixEOFProbe, 4), closed: make(chan struct{})}
	go func() {
		defer close(e.acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.active[c] = struct{}{}
			e.accepted++
			ordinal := e.accepted
			gate := e.gate
			if gate != nil && e.accepted == e.gateAt {
				close(gate)
				e.gate = nil
			}
			close(e.acceptedEvent)
			e.acceptedEvent = make(chan struct{})
			e.mu.Unlock()
			e.workers.Add(1)
			go func() {
				defer e.workers.Done()
				if gate != nil {
					select {
					case <-gate:
					case <-e.closed:
						return
					}
				}
				defer c.Close()
				defer func() { e.mu.Lock(); delete(e.active, c); e.mu.Unlock() }()
				if e.probeEOF {
					payload := make([]byte, 19)
					if _, err := io.ReadFull(c, payload); err != nil {
						return
					}
					if err := writeAllIntegration(c, payload); err != nil {
						return
					}
					_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
					var buf [1]byte
					_, err := c.Read(buf[:])
					e.probes <- realMatrixEOFProbe{ordinal: ordinal, err: err}
					return
				}
				if e.closeAfter > 0 {
					_, _ = io.CopyN(c, c, int64(e.closeAfter))
					return
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { e.close(t) })
	return e
}
func (e *realMatrixTarget) close(t *testing.T) {
	t.Helper()
	e.once.Do(func() {
		close(e.closed)
		_ = e.listener.Close()
		<-e.acceptDone
		e.mu.Lock()
		for c := range e.active {
			_ = c.Close()
		}
		e.mu.Unlock()
		done := make(chan struct{})
		go func() { e.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("target workers did not exit")
		}
	})
}
func (e *realMatrixTarget) hold() func() {
	e.mu.Lock()
	gate := make(chan struct{})
	e.gate = gate
	e.gateAt = -1
	e.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { e.mu.Lock(); close(gate); e.gate = nil; e.mu.Unlock() }) }
}
func (e *realMatrixTarget) waitAccepted(ctx context.Context, n int) error {
	for {
		e.mu.Lock()
		event := e.acceptedEvent
		count := e.accepted
		e.mu.Unlock()
		if count >= n {
			return nil
		}
		select {
		case <-event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (e *realMatrixTarget) barrier(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gate = make(chan struct{})
	e.gateAt = e.accepted + n
}
func (e *realMatrixTarget) count() int { e.mu.Lock(); defer e.mu.Unlock(); return e.accepted }

type realMatrixFixture struct {
	ctx        context.Context
	cancel     context.CancelFunc
	store      *store.MemoryStore
	manager    *realMatrixManager
	route      *router.Router
	gateway    *legacy.Gateway
	listener   net.Listener
	acceptDone chan struct{}
	workers    sync.WaitGroup
	processes  []*realMatrixProcess
	tunnels    map[domain.DeviceID]domain.Tunnel
	keys       map[domain.DeviceID]string
	bin        string
}

func newRealMatrixFixture(t *testing.T, devices int) *realMatrixFixture {
	t.Helper()
	bin := requireNPCBin(t)
	if sum := sha256File(t, bin); sum != "13c12ffd3ebbab07b62cfb7e396d2290276a679f00ecb018b44f0db8e5fab2c7" {
		t.Fatal("4B requires the reviewed pinned v0.26.34 Linux amd64 release binary")
	}
	t.Log("pinned NPC v0.26.34 sha256=13c12ffd3ebbab07b62cfb7e396d2290276a679f00ecb018b44f0db8e5fab2c7")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	f := &realMatrixFixture{ctx: ctx, cancel: cancel, store: store.NewMemoryStore(), manager: newRealMatrixManager(), acceptDone: make(chan struct{}), tunnels: make(map[domain.DeviceID]domain.Tunnel), keys: make(map[domain.DeviceID]string), bin: bin}
	t.Cleanup(func() {
		for _, p := range f.processes {
			p.stop(t)
		}
		cancel()
		if f.listener != nil {
			_ = f.listener.Close()
			<-f.acceptDone
		}
		done := make(chan struct{})
		go func() { f.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gateway ServeConn workers did not exit")
		}
		for id := range f.keys {
			if _, err := f.manager.CurrentForDevice(context.Background(), id); !errors.Is(err, session.ErrNoCurrentSession) {
				t.Error("gateway cleanup retained current device session")
			}
		}
	})
	if err := f.store.CreateUser(ctx, domain.User{ID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < devices; i++ {
		id := domain.DeviceID(fmt.Sprintf("device-%d", i))
		if err := f.store.CreateDevice(ctx, domain.Device{ID: id, ProjectID: "project", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		credential, err := f.store.IssueLegacyCredential(ctx, id, []byte("4B isolated test server secret"))
		if err != nil {
			t.Fatal(err)
		}
		f.keys[id] = credential.VKey
	}
	gw, err := legacy.New(legacy.Config{ServerSecret: []byte("4B isolated test server secret"), Store: f.store, Sessions: f.manager, MuxConfig: legacy.LegacyMuxConfig{PingInterval: 100 * time.Millisecond, PingTimeout: 3 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	f.gateway = gw
	f.route = router.New(f.store, f.manager)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.listener = l
	go func() {
		defer close(f.acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.workers.Add(1)
			go func() { defer f.workers.Done(); _ = gw.ServeConn(ctx, c) }()
		}
	}()
	for i := 0; i < devices; i++ {
		id := domain.DeviceID(fmt.Sprintf("device-%d", i))
		f.start(t, id)
		f.manager.wait(t, ctx, id, "", true)
	}
	return f
}
func (f *realMatrixFixture) start(t *testing.T, id domain.DeviceID) *realMatrixProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	cmd := exec.CommandContext(ctx, f.bin, "-server="+f.listener.Addr().String(), "-vkey="+f.keys[id])
	cmd.Dir = t.TempDir()
	p := &realMatrixProcess{cancel: cancel, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal("start pinned NPC:", err)
	}
	f.processes = append(f.processes, p)
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p
}
func (f *realMatrixFixture) target(t *testing.T, id domain.DeviceID, e *realMatrixTarget) domain.Tunnel {
	t.Helper()
	tunnel := domain.Tunnel{ID: domain.TunnelID("tunnel-" + string(id)), DeviceID: id, Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef("public-" + string(id)), TargetAddr: e.listener.Addr().String(), Enabled: true}
	if err := f.store.CreateTunnel(f.ctx, tunnel); err != nil {
		t.Fatal(err)
	}
	f.tunnels[id] = tunnel
	return tunnel
}

type realMatrixRoute struct {
	client net.Conn
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	result error
}

func (f *realMatrixFixture) open(tunnel domain.Tunnel) (*realMatrixRoute, error) {
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		defer l.Close()
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		done <- f.route.RouteTCP(ctx, tunnel, c)
	}()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	if err != nil {
		cancel()
		_ = l.Close()
		<-done
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(7 * time.Second))
	return &realMatrixRoute{client: c, cancel: cancel, done: done}, nil
}
func (r *realMatrixRoute) finish() error {
	r.once.Do(func() { _ = r.client.Close(); r.cancel(); r.result = <-r.done })
	return r.result
}
func (r *realMatrixRoute) echo(payload []byte) error {
	written := make(chan error, 1)
	go func() { written <- writeAllIntegration(r.client, payload) }()
	got := make([]byte, len(payload))
	_, readErr := io.ReadFull(r.client, got)
	if readErr != nil {
		_ = r.client.Close()
	}
	writeErr := <-written
	if readErr != nil {
		return readErr
	}
	if writeErr != nil {
		return writeErr
	}
	if !bytes.Equal(got, payload) {
		return errors.New("payload byte mismatch")
	}
	return nil
}
func (f *realMatrixFixture) echo(tunnel domain.Tunnel, payload []byte) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		r, err := f.open(tunnel)
		if err != nil {
			return err
		}
		echoErr := r.echo(payload)
		routeErr := r.finish()
		if echoErr == nil {
			if routeErr != nil && !errors.Is(routeErr, context.Canceled) && !errors.Is(routeErr, legacy.ErrLegacyStreamClosed) {
				return fmt.Errorf("successful echo had unexpected route completion: %w", routeErr)
			}
			return nil
		}
		if !errors.Is(routeErr, legacy.ErrLegacyDataChannelUnavailable) {
			return fmt.Errorf("echo failed: %v; route: %v", echoErr, routeErr)
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline.C:
			return errors.New("bounded fresh-route readiness retry exhausted")
		case <-f.ctx.Done():
			return f.ctx.Err()
		}
	}
}
func matrixPayload(size int, seed byte) []byte {
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(i*31) ^ seed
	}
	return p
}

func TestLegacyNPCPayloadMatrix(t *testing.T) {
	f := newRealMatrixFixture(t, 1)
	e := newRealMatrixTarget(t, 0)
	tunnel := f.target(t, "device-0", e)
	for _, n := range []int{1, 5, 19, 257, 4085, 4086, 8192, 65536, 122549, 122550, 122551, 131072, 262144} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			if err := f.echo(tunnel, matrixPayload(n, byte(n))); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestLegacyNPCSequential129(t *testing.T) {
	f := newRealMatrixFixture(t, 1)
	e := newRealMatrixTarget(t, 0)
	tunnel := f.target(t, "device-0", e)
	for i := 1; i <= 129; i++ {
		if err := f.echo(tunnel, matrixPayload(257, byte(i))); err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
	}
	if e.count() != 129 {
		t.Fatalf("target accepted %d, want 129", e.count())
	}
}
func TestLegacyNPCConcurrentMatrix(t *testing.T) {
	for _, n := range []int{2, 8, 16} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := newRealMatrixFixture(t, 1)
			e := newRealMatrixTarget(t, 0)
			tunnel := f.target(t, "device-0", e)
			if err := f.echo(tunnel, []byte("ready")); err != nil {
				t.Fatal(err)
			}
			e.barrier(n)
			start := make(chan struct{})
			done := make(chan error, n)
			for i := 0; i < n; i++ {
				go func(seed byte) { <-start; done <- f.echo(tunnel, matrixPayload(262144, seed)) }(byte(i))
			}
			close(start)
			for i := 0; i < n; i++ {
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
			if e.count() != n+1 {
				t.Fatalf("target accepted %d, want %d", e.count(), n+1)
			}
		})
	}
}
func TestLegacyNPCProcessRestartLifecycle(t *testing.T) {
	f := newRealMatrixFixture(t, 1)
	e := newRealMatrixTarget(t, 0)
	tunnel := f.target(t, "device-0", e)
	if err := f.echo(tunnel, []byte("before-stop")); err != nil {
		t.Fatal(err)
	}
	first, _ := f.manager.CurrentForDevice(f.ctx, "device-0")
	f.processes[0].stop(t)
	f.manager.wait(t, f.ctx, "device-0", "", false)
	f.start(t, "device-0")
	next := f.manager.wait(t, f.ctx, "device-0", first.ID(), true)
	if next.ID() == first.ID() {
		t.Fatal("restarted process reused session")
	}
	if err := f.echo(tunnel, []byte("after-restart")); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyNPCMultiDeviceIsolation(t *testing.T) {
	f := newRealMatrixFixture(t, 2)
	a := newRealMatrixTarget(t, 0)
	b := newRealMatrixTarget(t, 0)
	ta := f.target(t, "device-0", a)
	tb := f.target(t, "device-1", b)
	ta.TargetAddr = b.listener.Addr().String() // caller-supplied target must not override stored A target
	if err := f.echo(ta, []byte("A-target payload mentions "+b.listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	if err := f.echo(tb, []byte("B-target")); err != nil {
		t.Fatal(err)
	}
	before, _ := f.manager.CurrentForDevice(f.ctx, "device-1")
	release := b.hold()
	defer release()
	done := make(chan error, 1)
	go func() { done <- f.echo(tb, matrixPayload(262144, 2)) }()
	joined := false
	defer func() {
		release()
		if !joined {
			f.cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("device B echo worker did not exit")
			}
		}
	}()
	if err := b.waitAccepted(f.ctx, 2); err != nil {
		release()
		<-done
		joined = true
		t.Fatal(err)
	}
	f.processes[0].stop(t)
	f.manager.wait(t, f.ctx, "device-0", "", false)
	after, err := f.manager.CurrentForDevice(f.ctx, "device-1")
	if err != nil || before.ID() != after.ID() {
		t.Fatal("device A stop disturbed device B")
	}
	release()
	err = <-done
	joined = true
	if err != nil {
		t.Fatal(err)
	}
	if a.count() != 1 || b.count() != 2 {
		t.Fatal("target/device isolation failed")
	}
}
func TestLegacyNPCClosePaths(t *testing.T) {
	for _, mode := range []string{"target-close", "public-close", "route-cancel", "close-before-payload", "npc-stop-active", "half-close-record"} {
		t.Run(mode, func(t *testing.T) {
			f := newRealMatrixFixture(t, 1)
			closeAfter := 0
			if mode == "target-close" {
				closeAfter = 19
			} else if mode == "half-close-record" {
				closeAfter = -1
			}
			e := newRealMatrixTarget(t, closeAfter)
			tunnel := f.target(t, "device-0", e)
			if err := f.echo(tunnel, matrixPayload(19, 3)); err != nil {
				t.Fatal(err)
			}
			r, err := f.open(tunnel)
			if err != nil {
				t.Fatal(err)
			}
			defer r.finish()
			if mode == "close-before-payload" {
				_ = r.client.Close()
				if err := r.finish(); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, legacy.ErrLegacyStreamClosed) {
					t.Fatal(err)
				}
				return
			}
			if err := r.echo(matrixPayload(19, 4)); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "target-close":
				buf := make([]byte, 1)
				_, err := r.client.Read(buf)
				if !errors.Is(err, io.EOF) {
					t.Fatalf("target close read: %v", err)
				}
			case "public-close":
				_ = r.client.Close()
			case "npc-stop-active":
				f.processes[0].stop(t)
				f.manager.wait(t, f.ctx, "device-0", "", false)
				r.cancel()
			case "route-cancel":
				r.cancel()
				buf := make([]byte, 1)
				_, err := r.client.Read(buf)
				if err == nil {
					t.Fatal("canceled route still readable")
				}
			case "half-close-record":
				if err := r.client.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				for {
					select {
					case result := <-e.probes:
						if result.ordinal != 2 {
							continue
						}
						if errors.Is(result.err, io.EOF) {
							t.Log("target observed EOF in this bounded CloseWrite probe; no universal half-close compatibility claim")
						} else if netErr, ok := result.err.(net.Error); ok && netErr.Timeout() {
							t.Log("target did not receive write-half EOF within its 150ms read deadline after public CloseWrite; independent legacy half-close is unsupported")
						} else {
							t.Fatalf("unexpected target EOF probe result: %v", result.err)
						}
						return
					case <-f.ctx.Done():
						t.Fatal("target EOF probe worker did not finish")
					}
				}
			}
		})
	}
}

func TestLegacyNPCIdleRecovery(t *testing.T) {
	f := newRealMatrixFixture(t, 1)
	e := newRealMatrixTarget(t, 0)
	tunnel := f.target(t, "device-0", e)
	if err := f.echo(tunnel, []byte("before-idle")); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(350 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("idle interval canceled")
	}
	if err := f.echo(tunnel, matrixPayload(262144, 5)); err != nil {
		t.Fatal(err)
	}
	t.Log("Router echo before and after intentional 350ms idle; configured ping interval 100ms; companion separately verifies actual matching pings")
}
