package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"github.com/geniucker-dev/kavern/internal/testutil"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func listenerOwner(t *testing.T, address string) *store.ConfigOwner {
	t.Helper()
	s := store.NewMemoryStore()
	ctx := context.Background()
	_ = s.CreateUser(ctx, domain.User{ID: "u"})
	_ = s.CreateProject(ctx, domain.Project{ID: "p", UserID: "u"})
	for _, id := range []domain.DeviceID{"a", "b"} {
		_ = s.CreateDevice(ctx, domain.Device{ID: id, ProjectID: "p", Enabled: true})
		ref := address
		if id == "b" {
			ref = "127.0.0.1:0"
		}
		if err := s.CreateTunnel(ctx, domain.Tunnel{ID: domain.TunnelID(id), DeviceID: id, Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(ref), TargetAddr: "127.0.0.1:2001", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	key := bytes.Repeat([]byte{0x61}, 32)
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if err := s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	owner, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner
}

type admittedEcho struct{ owner *store.ConfigOwner }

func (e admittedEcho) RouteListenerTCP(ctx context.Context, id domain.TunnelID, generation uint64, conn net.Conn) error {
	_, lease, err := e.owner.AdmitListener(ctx, id, generation)
	if err != nil {
		return err
	}
	defer lease.Finish()
	done := make(chan struct{})
	stop := context.AfterFunc(lease.Context, func() { defer close(done); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	_, err = io.Copy(conn, conn)
	return err
}
func listenerAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("listener barrier timed out")
	}
}
func listenerStatus(t *testing.T, s *ListenerService, id domain.TunnelID, predicate func(ListenerStatus) bool) ListenerStatus {
	t.Helper()
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	for {
		changed := s.Changed()
		for _, v := range s.Status() {
			if v.TunnelID == id && predicate(v) {
				return v
			}
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("listener status did not converge", s.Status())
		}
	}
}
func runListeners(t *testing.T, o *store.ConfigOwner) *ListenerService {
	t.Helper()
	s, err := NewListenerService(o, admittedEcho{o}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.retryBase = 10 * time.Millisecond
	s.retryMax = 40 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		bound := s.Status()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("listener service did not join")
		}
		if len(s.Status()) != 0 {
			t.Error("runtime listener status retained")
		}
		for _, v := range bound {
			if v.State != "bound" {
				continue
			}
			if o.ListenerCurrent(context.Background(), v.TunnelID, v.Generation) {
				t.Error("generation survived shutdown")
			}
			socket, err := net.Listen("tcp", v.BoundAddress)
			if err != nil {
				t.Error("bound socket survived shutdown", err)
			} else {
				_ = socket.Close()
			}
		}
		if len(s.slots) != 0 {
			t.Error("accepted handler slots retained")
		}
	})
	return s
}
func echoConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	echoByte(t, c)
	return c
}
func echoByte(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[0] != 'x' {
		t.Fatal("unaffected listener traffic failed", err)
	}
}
func listenerCommit(t *testing.T, o *store.ConfigOwner, id domain.DeviceID, edit func(*domain.DeviceConfiguration)) {
	t.Helper()
	c, err := o.DeviceConfiguration(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	edit(&c)
	if _, err = o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err != nil {
		t.Fatal(err)
	}
}
func TestDynamicListenersOccupiedRecoveryPortZeroAndChangedAddressFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	o := listenerOwner(t, occupied.Addr().String())
	s := runListeners(t, o)
	failed := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bind_failed" })
	if failed.BoundAddress != "" || failed.RetryAt.IsZero() {
		t.Fatal("bind failure reported bound")
	}
	b := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" })
	if b.BoundAddress == "127.0.0.1:0" || b.Generation == 0 {
		t.Fatal("ephemeral actual address missing")
	}
	continuing := echoConnection(t, b.BoundAddress)
	_ = occupied.Close()
	a := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" })
	old := echoConnection(t, a.BoundAddress)
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	newAddress := blocked.Addr().String()
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = domain.ListenerRef(newAddress) })
	if o.ListenerCurrent(context.Background(), "a", a.Generation) {
		t.Fatal("superseded generation still admitted")
	}
	changed := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bind_failed" && string(v.DesiredAddress) == newAddress })
	if changed.BoundAddress != "" {
		t.Fatal("old changed socket reported serving")
	}
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	var byte [1]byte
	if _, err = old.Read(byte[:]); err == nil {
		t.Fatal("old changed address still serves")
	}
	echoByte(t, continuing)
	stable := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" })
	if stable.Generation != b.Generation || stable.BoundAddress != b.BoundAddress {
		t.Fatal("unaffected listener replaced")
	}
	view, err := o.RouteView(context.Background(), "a")
	if err != nil || string(view.Tunnel.Listener) != newAddress {
		t.Fatal("failed bind rolled back desired address", err)
	}
	_ = blocked.Close()
	recovered := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" })
	if recovered.Generation <= a.Generation || recovered.BoundAddress != newAddress {
		t.Fatal("replacement listener not bound")
	}
	_ = echoConnection(t, recovered.BoundAddress)
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels = nil })
	for {
		changed := s.Changed()
		found := false
		for _, v := range s.Status() {
			if v.TunnelID == "a" {
				found = true
			}
		}
		if !found {
			break
		}
		listenerAwait(t, changed)
	}
	if o.ListenerCurrent(context.Background(), "a", recovered.Generation) {
		t.Fatal("deleted listener generation survived")
	}
	echoByte(t, continuing)
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) {
		c.Tunnels = []domain.Tunnel{{ID: "a", DeviceID: "a", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.2:0", TargetAddr: "127.0.0.1:2001", Enabled: true}}
	})
	created := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" })
	if created.Generation <= recovered.Generation {
		t.Fatal("created listener reused obsolete generation")
	}
	createdClient := echoConnection(t, created.BoundAddress)
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Enabled = false })
	disabled := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "disabled" })
	if disabled.BoundAddress != "" {
		t.Fatal("disabled tunnel still bound")
	}
	_ = createdClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = createdClient.Read(byte[:]); err == nil {
		t.Fatal("disabled tunnel still serves")
	}
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Enabled = true })
	enabled := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" && v.Generation > created.Generation })
	_ = echoConnection(t, enabled.BoundAddress)
	echoByte(t, continuing)

}
func TestListenerGenerationRejectsBeforeRoutingAndReenableRequiresNewGeneration(t *testing.T) {
	o := listenerOwner(t, "127.0.0.2:0")
	ctx := context.Background()
	manager := session.NewManager()
	fake := testutil.NewFakeSession("session", "a")
	_ = manager.Attach(ctx, fake)
	routes := New(o, manager)
	generation, err := o.ReserveListener(ctx, "a", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = "127.0.0.3:0" })
	if err = routes.RouteListenerTCP(ctx, "a", generation, nil); !errors.Is(err, domain.ErrStaleAdmission) {
		t.Fatal("stale handler admitted", err)
	}
	fresh, err := o.ReserveListener(ctx, "a", "127.0.0.3:0")
	if err != nil || fresh <= generation {
		t.Fatal("generation not replaced", err)
	}
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Device.Enabled = false })
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Device.Enabled = true })
	if err = routes.RouteListenerTCP(ctx, "a", fresh, nil); !errors.Is(err, domain.ErrStaleAdmission) {
		t.Fatal("reenable resurrected old handler", err)
	}
	if fake.OpenCount() != 0 {
		t.Fatal("stale admission opened remote stream")
	}
}
func TestDynamicListenerAcceptFailureIsolatedAndRetried(t *testing.T) {
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := port.Addr().String()
	_ = port.Close()
	o := listenerOwner(t, address)
	s, err := NewListenerService(o, admittedEcho{o}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.retryBase = 50 * time.Millisecond
	s.retryMax = 100 * time.Millisecond
	captured := make(chan net.Listener, 4)
	listen := s.listen
	s.listen = func(ctx context.Context, address string) (net.Listener, error) {
		l, err := listen(ctx, address)
		if err == nil {
			select {
			case captured <- l:
			default:
			}
		}
		return l, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("service did not join")
		}
	})
	a := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" })
	b := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" })
	continuing := echoConnection(t, b.BoundAddress)
	var failed net.Listener
	for failed == nil {
		select {
		case l := <-captured:
			if l.Addr().String() == a.BoundAddress {
				failed = l
			}
		case <-time.After(time.Second):
			t.Fatal("socket not captured")
		}
	}
	_ = failed.Close()
	status := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "accept_failed" })
	if status.BoundAddress != "" {
		t.Fatal("failed accept still bound")
	}
	echoByte(t, continuing)
	recovered := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" && v.Generation > a.Generation })
	_ = echoConnection(t, recovered.BoundAddress)
	if current := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" }); current.Generation != b.Generation {
		t.Fatal("public accept failure disrupted unaffected listener")
	}
}

type excessiveListenerSource struct{ *store.ConfigOwner }

func (s excessiveListenerSource) DesiredRoutes(context.Context) ([]domain.RouteView, error) {
	views := make([]domain.RouteView, MaxListeners+1)
	for i := range views {
		views[i] = domain.RouteView{Device: domain.Device{ID: "a", Enabled: true}, Tunnel: domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("t%d", i)), DeviceID: "a", Enabled: true}}
	}
	return views, nil
}
func TestListenerCapacityAndSharedHandlerCeiling(t *testing.T) {
	o := listenerOwner(t, "127.0.0.2:0")
	s, err := NewListenerService(excessiveListenerSource{o}, admittedEcho{o}, nil)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	s.listen = func(context.Context, string) (net.Listener, error) {
		called = true
		return nil, errors.New("unexpected")
	}
	if err = s.Run(context.Background()); err == nil || called {
		t.Fatal("listener capacity not enforced before binding")
	}
	s = runListeners(t, o)
	b := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" })
	for i := 0; i < MaxAcceptedHandlers; i++ {
		s.slots <- struct{}{}
	}
	c, err := net.DialTimeout("tcp", b.BoundAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var byte [1]byte
	if _, err = c.Read(byte[:]); err == nil {
		t.Fatal("saturated handler admitted")
	}
	_ = c.Close()
	if len(s.slots) != MaxAcceptedHandlers {
		t.Fatal("handler cap changed")
	}
	for i := 0; i < MaxAcceptedHandlers; i++ {
		<-s.slots
	}
	_ = echoConnection(t, b.BoundAddress)
}

func TestListenerBindSupersessionCoalescesAndKeepsOtherTraffic(t *testing.T) {
	o := listenerOwner(t, "127.0.0.2:0")
	s, err := NewListenerService(o, admittedEcho{o}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan net.Listener, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	listen := s.listen
	s.listen = func(ctx context.Context, address string) (net.Listener, error) {
		socket, err := listen(ctx, address)
		if err != nil {
			return nil, err
		}
		if address == "127.0.0.3:0" {
			entered <- socket
			select {
			case <-release:
			case <-ctx.Done():
				_ = socket.Close()
				return nil, ctx.Err()
			}
		}
		return socket, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("superseded bind did not join")
		}
	})
	_ = listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" })
	b := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" })
	continuing := echoConnection(t, b.BoundAddress)
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = "127.0.0.3:0" })
	var obsolete net.Listener
	select {
	case obsolete = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("pending bind not reached")
	}
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = "127.0.0.4:0" })
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = "127.0.0.5:0" })
	echoByte(t, continuing)
	releaseOnce.Do(func() { close(release) })
	latest := listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" && v.DesiredAddress == "127.0.0.5:0" })
	_ = echoConnection(t, latest.BoundAddress)
	rebound, err := net.Listen("tcp", obsolete.Addr().String())
	if err != nil {
		t.Fatal("superseded pending bind socket retained", err)
	}
	_ = rebound.Close()
	if stable := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" }); stable.Generation != b.Generation {
		t.Fatal("pending bind supersession replaced unaffected listener")
	}
	echoByte(t, continuing)
}

// Hold the coordinator in another listener's bind while its failure queue is
// saturated. The failed generation's handler must retire without a queue drain.
type queueCancellationProbe struct {
	owner             *store.ConfigOwner
	first             atomic.Bool
	started, canceled chan struct{}
}

func (p *queueCancellationProbe) RouteListenerTCP(ctx context.Context, id domain.TunnelID, generation uint64, conn net.Conn) error {
	if id != "b" || !p.first.CompareAndSwap(false, true) {
		return admittedEcho{p.owner}.RouteListenerTCP(ctx, id, generation, conn)
	}
	_, lease, err := p.owner.AdmitListener(ctx, id, generation)
	if err != nil {
		return err
	}
	defer lease.Finish()
	close(p.started)
	<-lease.Context.Done()
	close(p.canceled)
	return lease.Context.Err()
}
func TestListenerSaturatedFailureQueueCancelsReleasesRetriesAndJoins(t *testing.T) {
	o := listenerOwner(t, "127.0.0.2:0")
	probe := &queueCancellationProbe{owner: o, started: make(chan struct{}), canceled: make(chan struct{})}
	s, err := NewListenerService(o, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.retryBase = 50 * time.Millisecond
	s.retryMax = 100 * time.Millisecond
	captured := make(chan net.Listener, 4)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	listen := s.listen
	s.listen = func(ctx context.Context, address string) (net.Listener, error) {
		socket, err := listen(ctx, address)
		if err != nil {
			return nil, err
		}
		if address == "127.0.0.1:0" {
			captured <- socket
		}
		if address == "127.0.0.3:0" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				_ = socket.Close()
				return nil, ctx.Err()
			}
		}
		return socket, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("saturated failure service did not join")
		}
		if len(s.slots) != 0 || len(s.Status()) != 0 {
			t.Error("saturated failure shutdown retained resources")
		}
	})
	_ = listenerStatus(t, s, "a", func(v ListenerStatus) bool { return v.State == "bound" })
	initial := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" })
	socket := <-captured
	client, err := net.DialTimeout("tcp", initial.BoundAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	listenerAwait(t, probe.started)
	listenerCommit(t, o, "a", func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = "127.0.0.3:0" })
	listenerAwait(t, entered)
	for i := 0; i < MaxListeners; i++ {
		s.failures <- listenerFailure{id: "stale", generation: uint64(i + 1)}
	}
	_ = socket.Close()
	listenerAwait(t, probe.canceled)
	if o.ListenerCurrent(context.Background(), "b", initial.Generation) {
		t.Fatal("failed generation still admitted")
	}
	// Observe actual slot release, not merely the handler cancellation signal.
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for len(s.slots) != 0 {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("failure backpressure retained handler slot")
		}
	}
	if len(s.failures) != MaxListeners || len(s.failureWake) != 1 {
		t.Fatal("saturation did not retain a reliable coalesced failure wakeup")
	}
	select {
	case <-release:
		t.Fatal("coordinator released before cancellation assertions")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	failed := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "accept_failed" })
	if failed.BoundAddress != "" {
		t.Fatal("failed generation still reported bound")
	}
	recovered := listenerStatus(t, s, "b", func(v ListenerStatus) bool { return v.State == "bound" && v.Generation > initial.Generation })
	_ = echoConnection(t, recovered.BoundAddress)
	if recovered.BoundAddress != initial.BoundAddress {
		stale, err := net.DialTimeout("tcp", initial.BoundAddress, 50*time.Millisecond)
		if err == nil {
			_ = stale.Close()
			t.Fatal("obsolete socket still accepts")
		}
	}
}
