package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"github.com/geniucker-dev/kavern/internal/testutil"
)

type runtimeTestManager struct {
	*session.Manager
	mu      sync.Mutex
	changed chan struct{}
}

func (m *runtimeTestManager) notify() {
	m.mu.Lock()
	close(m.changed)
	m.changed = make(chan struct{})
	m.mu.Unlock()
}
func (m *runtimeTestManager) Attach(ctx context.Context, s session.AgentSession) error {
	err := m.Manager.Attach(ctx, s)
	m.notify()
	return err
}
func (m *runtimeTestManager) Detach(ctx context.Context, id domain.SessionID) error {
	err := m.Manager.Detach(ctx, id)
	m.notify()
	return err
}

type runtimePipe struct {
	peer net.Conn
	done chan struct{}
	err  error
}

func startRuntimePipe(t *testing.T, gateway *Gateway, token, role string) *runtimePipe {
	t.Helper()
	server, client := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	p := &runtimePipe{peer: client, done: make(chan struct{})}
	go func() { defer close(p.done); p.err = gateway.ServeConn(ctx, server) }()
	t.Cleanup(func() { cancel(); _ = client.Close(); awaitRobustness(t, p.done) })
	_ = client.SetDeadline(time.Now().Add(robustnessWait))
	writeStockPreface(t, client)
	readStockServerAuthField(t, client)
	if sendStockTokenAndReadOutcome(t, client, token) != "sucs" {
		t.Fatal("test device authentication failed")
	}
	if err := writeAll(client, []byte(role)); err != nil {
		t.Fatal("test role delivery failed")
	}
	_ = client.SetDeadline(time.Time{})
	return p
}

func waitRuntimeAttached(t *testing.T, g *Gateway, m *runtimeTestManager, id domain.DeviceID) *LegacyNpcSession {
	t.Helper()
	timer := time.NewTimer(robustnessWait)
	defer timer.Stop()
	for {
		m.mu.Lock()
		notify := m.changed
		m.mu.Unlock()
		current, err := m.CurrentForDevice(context.Background(), id)
		if err == nil {
			if main, ok := current.(*LegacyNpcSession); ok {
				r := main.runtime
				r.mu.Lock()
				ready := r.attachedMain == main
				notify = r.mainNotify
				r.mu.Unlock()
				if ready {
					return main
				}
			}
		}
		select {
		case <-notify:
		case <-timer.C:
			t.Fatal("legacy main did not become attached")
		}
	}
}

func newRuntimeRobustnessGateway(t *testing.T) (*Gateway, *runtimeTestManager, []string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemoryStore()
	tokens := make([]string, 2)
	for i := range tokens {
		id := domain.DeviceID(fmt.Sprintf("device-%d", i+1))
		if err := st.CreateDevice(ctx, domain.Device{ID: id, ProjectID: "project", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateTunnel(ctx, domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("tunnel-%d", i+1)), DeviceID: id, Protocol: domain.TunnelProtocolTCP, TargetAddr: "localhost:8080", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		issued, err := st.IssueLegacyCredential(ctx, id, []byte("test-server-secret"))
		if err != nil {
			t.Fatal(err)
		}
		tokens[i], err = security.LegacyWireTokenFromVKey(issued.VKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	m := &runtimeTestManager{Manager: session.NewManager(), changed: make(chan struct{})}
	g, err := New(Config{Store: st, Sessions: m, ServerSecret: []byte("test-server-secret")})
	if err != nil {
		t.Fatal(err)
	}
	return g, m, tokens
}

func runtimeRoundTrip(t *testing.T, main *LegacyNpcSession, peer *robustnessPeer, tunnel domain.TunnelID) *LegacyStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), robustnessWait)
	defer cancel()
	opened, err := main.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: tunnel, Protocol: domain.TunnelProtocolTCP, RemoteAddr: "public-metadata"})
	if err != nil {
		t.Fatal("runtime open:", err)
	}
	stream := opened.(*LegacyStream)
	payload := deterministicPayload(19, int(stream.id))
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	frames := peer.wait(t, func(frames []Frame) bool { return len(dataFrames(frames, stream.id)) >= 2 })
	data := dataFrames(frames, stream.id)
	if !bytes.Equal(data[len(data)-1].Content, payload) {
		t.Fatal("runtime payload was corrupted")
	}
	peer.send(t, Frame{Flag: FrameFlagDataFinal, StreamID: stream.id, Content: payload})
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("runtime response was corrupted")
	}
	return stream
}

func TestDeviceRuntimeTwoDeviceProtocolIsolationAndRecovery(t *testing.T) {
	g, manager, tokens := newRuntimeRobustnessGateway(t)
	mainPipe1 := startRuntimePipe(t, g, tokens[0], connTypeMain)
	main1 := waitRuntimeAttached(t, g, manager, "device-1")
	mainPipe2 := startRuntimePipe(t, g, tokens[1], connTypeMain)
	main2 := waitRuntimeAttached(t, g, manager, "device-2")
	chan1 := startRuntimePipe(t, g, tokens[0], connTypeChan)
	peer1 := newRobustnessPeer(t, chan1.peer, true, false)
	chan2 := startRuntimePipe(t, g, tokens[1], connTypeChan)
	peer2 := newRobustnessPeer(t, chan2.peer, true, false)
	peer1.wait(t, peerHasPing)
	peer2.wait(t, peerHasPing)
	// Wait for installation using runtime state, not the main generation.
	waitRuntimeMux(t, main1)
	waitRuntimeMux(t, main2)
	stream1 := runtimeRoundTrip(t, main1, peer1, "tunnel-1")
	stream2 := runtimeRoundTrip(t, main2, peer2, "tunnel-2")
	peer1.sendCommand(t, peerWrite{raw: []byte{0xff, 1, 0, 0, 0}})
	awaitRobustness(t, chan1.done)
	if !errors.Is(chan1.err, ErrLegacyProtocol) {
		t.Fatal("device protocol error lost its sentinel")
	}
	if got, err := manager.CurrentForDevice(context.Background(), "device-1"); err != nil || got != main1 {
		t.Fatal("chan protocol failure offlined its main")
	}
	if _, _, err := main1.snapshotMux(); !errors.Is(err, ErrLegacyDataChannelUnavailable) {
		t.Fatal("failed mux remained current")
	}
	if _, err := stream1.Write([]byte("x")); !errors.Is(err, ErrLegacyProtocol) {
		t.Fatal("returned stream lost protocol cause")
	}
	if _, err := stream2.Write([]byte("survives")); err != nil {
		t.Fatal("protocol failure escaped its device")
	}
	_ = stream2.Close()
	newChan := startRuntimePipe(t, g, tokens[0], connTypeChan)
	newPeer := newRobustnessPeer(t, newChan.peer, true, false)
	newPeer.wait(t, peerHasPing)
	waitRuntimeMux(t, main1)
	_ = runtimeRoundTrip(t, main1, newPeer, "tunnel-1").Close()
	_ = runtimeRoundTrip(t, main2, peer2, "tunnel-2").Close()
	_ = mainPipe1.peer.Close()
	_ = mainPipe2.peer.Close()
	for _, p := range []*runtimePipe{mainPipe1, mainPipe2, newChan, chan2} {
		awaitRobustness(t, p.done)
	}
	for _, id := range []domain.DeviceID{"device-1", "device-2"} {
		if _, err := manager.CurrentForDevice(context.Background(), id); !errors.Is(err, session.ErrNoCurrentSession) {
			t.Fatal("disconnected device remained online")
		}
	}
	assertRuntimeMapEmpty(t, g)
}

func peerHasPing(frames []Frame) bool {
	for _, f := range frames {
		if f.Flag == FrameFlagPing {
			return true
		}
	}
	return false
}

func waitRuntimeMux(t *testing.T, main *LegacyNpcSession) {
	t.Helper()
	r := main.runtime
	timer := time.NewTimer(robustnessWait)
	defer timer.Stop()
	expired := false
	for {
		r.mu.Lock()
		ready := r.mux != nil
		notify := r.mainNotify
		r.mu.Unlock()
		if ready {
			return
		}
		if expired {
			t.Fatal("device mux was not installed")
		}
		select {
		case <-notify:
		case <-timer.C:
			expired = true
		}
	}
}

func TestDeviceRuntimeMainAndChanReplacementPolicies(t *testing.T) {
	g, manager, tokens := newRuntimeRobustnessGateway(t)
	a := startRuntimePipe(t, g, tokens[0], connTypeMain)
	mainA := waitRuntimeAttached(t, g, manager, "device-1")
	chanA := startRuntimePipe(t, g, tokens[0], connTypeChan)
	peerA := newRobustnessPeer(t, chanA.peer, true, false)
	peerA.wait(t, peerHasPing)
	waitRuntimeMux(t, mainA)
	returned := runtimeRoundTrip(t, mainA, peerA, "tunnel-1")
	oldMux, generation, _ := mainA.snapshotMux()
	b := startRuntimePipe(t, g, tokens[0], connTypeMain)
	awaitRobustness(t, a.done)
	mainB := waitRuntimeAttached(t, g, manager, "device-1")
	currentMux, currentGeneration, err := mainB.snapshotMux()
	if err != nil || currentMux != oldMux || currentGeneration != generation {
		t.Fatal("main replacement changed the device mux")
	}
	if _, err := returned.Write([]byte("survives-main")); err != nil {
		t.Fatal("returned stream did not survive main replacement")
	}
	if _, err := mainA.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrLegacySessionClosed) {
		t.Fatal("old main admitted a new operation")
	}
	chanB := startRuntimePipe(t, g, tokens[0], connTypeChan)
	peerB := newRobustnessPeer(t, chanB.peer, true, false)
	peerB.wait(t, peerHasPing)
	awaitRobustness(t, chanA.done)
	if mainB.clearMuxIfCurrent(oldMux, generation) {
		t.Fatal("stale chan cleared replacement")
	}
	if _, err := returned.Write([]byte("closed")); !errors.Is(err, ErrLegacyMuxClosed) {
		t.Fatal("chan replacement left old stream usable")
	}
	_ = runtimeRoundTrip(t, mainB, peerB, "tunnel-1").Close()
	fake := testutil.NewFakeSession("other-protocol", "device-1")
	if err := manager.Attach(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	awaitRobustness(t, b.done)
	awaitRobustness(t, chanB.done)
	assertRuntimeMapEmpty(t, g)
	if current, err := manager.CurrentForDevice(context.Background(), "device-1"); err != nil || current != fake {
		t.Fatal("legacy cleanup detached the other protocol")
	}
	_ = fake.Close(context.Background())
	_ = manager.Detach(context.Background(), fake.ID())
}

func TestDeviceRuntimeConcurrentLeaseCategoriesReturnToZero(t *testing.T) {
	g := &Gateway{runtimes: make(map[domain.DeviceID]*legacyRuntimeEntry)}
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				id := domain.DeviceID(fmt.Sprintf("temporary-%d-%d", worker, i))
				transition, main := g.acquireMainRuntime(id)
				ch := g.acquireRuntime(id, legacyRuntimeLeaseChan)
				if transition.Runtime() != ch.Runtime() {
					results <- ErrLegacyRuntimeInvariant
					return
				}
				if _, err := transition.Runtime().finishUnpublishedMainTransition(); err != nil {
					results <- err
					return
				}
				for _, lease := range []*legacyRuntimeLease{main, transition, ch, ch} {
					if err := lease.Release(); err != nil {
						results <- err
						return
					}
				}
			}
			results <- nil
		}(worker)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	awaitRobustness(t, done)
	for i := 0; i < 16; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	assertRuntimeMapEmpty(t, g)
}
