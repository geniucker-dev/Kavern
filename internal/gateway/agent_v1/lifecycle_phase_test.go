package agent_v1

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"net"
	"testing"
)

func readyLifecyclePhaseServer(t *testing.T, backend mux.Session) (*AuthService, *agentSession, syncTuple, *fakeLifecycleClock) {
	owner, svc, server, _, clock := lifecycleControlFixture(t)
	snapshot, e := owner.NativeSnapshot(context.Background(), server.auth.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	tuple := syncTuple{server.auth.DeviceID, server.auth.SessionID, snapshot.Revision, 1}
	entry, _ := svc.registry.lookup(server.auth.SessionID)
	data := entry.session.syncController()
	data.install(tuple, snapshot)
	if e = data.ack(tuple); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < snapshot.Policy.Carriers; i++ {
		b := backend
		if i > 0 {
			b = &fakeMuxSession{}
		}
		c, e := carrier.New(b, policyCarrier(snapshot.Policy))
		if e != nil {
			t.Fatal(e)
		}
		if e = entry.session.pool.Add(c); e != nil {
			t.Fatal(e)
		}
	}
	if e = svc.markSyncReady(context.Background(), server.auth, tuple, snapshot.Policy.Carriers); e != nil {
		t.Fatal(e)
	}
	return svc, entry.session, tuple, clock
}
func TestLifecycleNativeOpenPhaseClosesLateMuxResult(t *testing.T) {
	backend := &lateOwnedMux{started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), stream: &syncRecordedStream{}}
	svc, agent, tuple, clock := readyLifecyclePhaseServer(t, backend)
	done := make(chan error, 1)
	go func() {
		stream, e := agent.OpenStream(context.Background(), domain.StreamOpenRequest{Revision: tuple.Revision, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			stream.Close()
			e = errors.New("late native stream escaped")
		}
		done <- e
	}()
	revocationBarrier(t, backend.started)
	clock.Advance(session.NativeOpenTimeout)
	revocationBarrier(t, backend.canceled)
	close(backend.release)
	if e := awaitSync(t, done); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("late native open error", e)
	}
	if backend.stream.closes.Load() != 1 || backend.stream.writes.Load() != 0 {
		t.Fatal("late stream leaked or emitted metadata")
	}
	entry, _ := svc.registry.lookup(agent.ID())
	if e := entry.session.serverLease().Valid(context.Background()); e != nil {
		t.Fatal("opening phase retired unrelated session authority", e)
	}
	if clock.active() != 2 {
		t.Fatal("opening phase retained a timer")
	}
}

type phasePipeBackend struct{ stream mux.Stream }

func (b *phasePipeBackend) OpenStream(context.Context) (mux.Stream, error) { return b.stream, nil }
func (b *phasePipeBackend) AcceptStream(context.Context) (mux.Stream, error) {
	return nil, errors.New("unused")
}
func (b *phasePipeBackend) Close() error            { return nil }
func (b *phasePipeBackend) ReceiveBufferLimit() int { return 0 }
func TestLifecycleNativeMetadataWritePhaseInterruptsStalledPeer(t *testing.T) {
	stream, peer := net.Pipe()
	defer peer.Close()
	_, agent, tuple, clock := readyLifecyclePhaseServer(t, &phasePipeBackend{stream})
	done := make(chan error, 1)
	go func() {
		s, e := agent.OpenStream(context.Background(), domain.StreamOpenRequest{Revision: tuple.Revision, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP})
		if s != nil {
			s.Close()
			e = errors.New("stalled metadata escaped")
		}
		done <- e
	}()
	awaitLifecycle(t, func() bool { return clock.active() == 3 })
	clock.Advance(session.NativeOpenTimeout)
	if e := awaitSync(t, done); e == nil {
		t.Fatal("stalled metadata survived phase timeout")
	}
	if clock.active() != 2 {
		t.Fatal("metadata phase retained a timer")
	}
}
func readyLifecyclePhaseReceiver(t *testing.T) (*ConfigReceiver, *fakeLifecycleClock, SyncStreamMetadata) {
	owner, _, _, r, clock := lifecycleControlFixture(t)
	snapshot, e := owner.NativeSnapshot(context.Background(), r.auth.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	r.applied = snapshot
	r.lastTransfer = 1
	r.ready = r.currentTupleLocked()
	tuple := r.ready
	for i := 0; i < snapshot.Policy.Carriers; i++ {
		r.carriers[&SyncClientCarrier{carrier: &carrier.Carrier{}}] = struct{}{}
	}
	r.mu.Unlock()
	t.Cleanup(func() { r.mu.Lock(); clear(r.carriers); r.mu.Unlock() })
	return r, clock, SyncStreamMetadata{Version: ProtocolVersion, SyncVersion: 1, Type: OpenStreamMessageType, DeviceID: tuple.DeviceID, SessionID: tuple.SessionID, Revision: tuple.Revision, TransferID: tuple.TransferID, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP}
}
func TestLifecycleNativeAgentMetadataPhaseBoundsQuietUntrustedStream(t *testing.T) {
	r, clock, _ := readyLifecyclePhaseReceiver(t)
	stream, peer := net.Pipe()
	defer peer.Close()
	done := make(chan error, 1)
	go func() { done <- HandleSyncAgentStream(context.Background(), stream, r, nil) }()
	awaitLifecycle(t, func() bool { return clock.active() == 3 })
	clock.Advance(session.NativeOpenTimeout)
	if e := awaitSync(t, done); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("metadata phase error", e)
	}
	if clock.active() != 2 {
		t.Fatal("agent metadata phase retained timer")
	}
}
func TestLifecycleNativeAgentDialPhaseClosesLateConnection(t *testing.T) {
	r, clock, metadata := readyLifecyclePhaseReceiver(t)
	stream, peer := net.Pipe()
	defer peer.Close()
	late, target := net.Pipe()
	defer target.Close()
	observed := &countedConn{Conn: late}
	dialer := &revocationDialer{started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), late: observed}
	done := make(chan error, 1)
	go func() { done <- HandleSyncAgentStream(context.Background(), stream, r, dialer) }()
	if e := WriteSyncStreamMetadata(peer, metadata); e != nil {
		t.Fatal(e)
	}
	revocationBarrier(t, dialer.started)
	clock.Advance(session.NativeOpenTimeout)
	revocationBarrier(t, dialer.canceled)
	close(dialer.release)
	if e := awaitSync(t, done); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("late dial phase error", e)
	}
	if observed.closes.Load() != 1 {
		t.Fatal("late dial connection leaked")
	}
	if clock.active() != 2 {
		t.Fatal("agent dial phase retained timer")
	}
}
