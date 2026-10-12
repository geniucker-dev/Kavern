package agent_v1

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func revocationBarrier(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("revocation barrier timed out")
	}
}

func TestOwnedFinalAuthPublicationSerializesDeviceDisable(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "disable-before-publish", false: "publish-before-disable"}[before], func(t *testing.T) {
			owner, svc, manager, secret := syncOwnedFixture(t)
			reached, release := make(chan struct{}), make(chan struct{})
			if before {
				svc.newSessionID = func() (domain.SessionID, error) { close(reached); <-release; return GenerateSessionID() }
			}
			nonce := mustNonce(t)
			challenge, err := svc.BeginSyncAuth(context.Background(), AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}, 1)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := SignSyncAuthResponse(secret, "device-1", nonce, challenge.ServerNonce, 1)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, err := svc.CompleteSyncAuth(context.Background(), AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: proof}, 1)
				result <- err
			}()
			if before {
				revocationBarrier(t, reached)
			} else {
				if err = awaitSync(t, result); err != nil {
					t.Fatal(err)
				}
			}
			desired, err := owner.DeviceConfiguration(context.Background(), "device-1")
			if err != nil {
				t.Fatal(err)
			}
			desired.Device.Enabled = false
			if _, err = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); err != nil {
				t.Fatal(err)
			}
			if before {
				close(release)
				if err = awaitSync(t, result); err == nil {
					t.Fatal("disabled device authenticated after proof verification")
				}
			}
			if _, err = manager.CurrentForDevice(context.Background(), "device-1"); !errors.Is(err, session.ErrNoCurrentSession) {
				t.Fatal("disabled session remains current", err)
			}
			svc.registry.mu.Lock()
			count := len(svc.registry.byID)
			svc.registry.mu.Unlock()
			if count != 0 {
				t.Fatal("disabled auth registry leaked")
			}
		})
	}
}

type lateOwnedMux struct {
	started, canceled, release chan struct{}
	stream                     *syncRecordedStream
	once                       sync.Once
}

func (b *lateOwnedMux) ReceiveBufferLimit() int { return 0 }
func (b *lateOwnedMux) OpenStream(ctx context.Context) (mux.Stream, error) {
	close(b.started)
	<-ctx.Done()
	close(b.canceled)
	<-b.release
	return b.stream, nil
}
func (b *lateOwnedMux) AcceptStream(ctx context.Context) (mux.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (b *lateOwnedMux) Close() error {
	b.once.Do(func() {
		select {
		case <-b.release:
		default:
			close(b.release)
		}
	})
	return nil
}
func ownedReady(t *testing.T, backend mux.Session) (*store.ConfigOwner, *agentSession, syncTuple) {
	t.Helper()
	owner, svc, _, secret := syncOwnedFixture(t)
	desired, err := owner.DeviceConfiguration(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	desired.Policy.Carriers = 1
	if _, err = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	auth := syncAuthFixture(t, svc, secret)
	t.Cleanup(func() { _ = svc.CloseSession(context.Background(), auth.SessionID) })
	if _, err = svc.NewConfigServer(context.Background(), auth, owner, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := owner.NativeSnapshot(context.Background(), auth.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := svc.registry.lookup(auth.SessionID)
	tuple := syncTuple{auth.DeviceID, auth.SessionID, snapshot.Revision, 1}
	entry.session.syncController().install(tuple, snapshot)
	if err = entry.session.syncController().ack(tuple); err != nil {
		t.Fatal(err)
	}
	if err = svc.BindAndAttachSyncCarrier(context.Background(), readinessCarrierRequest(t, auth, tuple, secret), backend); err != nil {
		t.Fatal(err)
	}
	if err = svc.markSyncReady(context.Background(), auth, tuple, 1); err != nil {
		t.Fatal(err)
	}
	return owner, entry.session, tuple
}
func TestOwnedPendingMuxOpenLateResultCannotEscapeRevocation(t *testing.T) {
	backend := &lateOwnedMux{started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), stream: &syncRecordedStream{}}
	owner, agent, tuple := ownedReady(t, backend)
	result := make(chan error, 1)
	go func() {
		stream, err := agent.OpenStream(context.Background(), domain.StreamOpenRequest{Revision: tuple.Revision, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
			result <- errors.New("obsolete stream escaped")
			return
		}
		result <- err
	}()
	revocationBarrier(t, backend.started)
	desired, err := owner.DeviceConfiguration(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].TargetAddr = "127.0.0.1:2222"
	committed := make(chan error, 1)
	go func() {
		_, err := owner.Commit(context.Background(), []domain.DeviceConfiguration{desired})
		committed <- err
	}()
	revocationBarrier(t, backend.canceled)
	// The desired generation is already published while cleanup waits outside its guard.
	view, err := owner.RouteView(context.Background(), "server-tunnel")
	if err != nil || view.Revision != tuple.Revision+1 {
		t.Fatal("publication guard held across cleanup", err)
	}
	select {
	case <-committed:
		t.Fatal("commit returned before pending work joined")
	default:
	}
	close(backend.release)
	if err = awaitSync(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal("late stream escaped", err)
	}
	if err = awaitSync(t, committed); err != nil {
		t.Fatal(err)
	}
	if backend.stream.writes.Load() != 0 || backend.stream.closes.Load() != 1 {
		t.Fatal("late mux stream leaked or emitted obsolete metadata")
	}
}

type revocationDialer struct {
	started, canceled, release chan struct{}
	late                       net.Conn
}

func (d *revocationDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	close(d.canceled)
	<-d.release
	return d.late, nil
}

type countedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }
func readyReceiverForRevocation(t *testing.T) (*ConfigReceiver, *syncPlan) {
	t.Helper()
	auth := codecAuth(t)
	r := receiverFixture(t, auth, nil)
	snapshot := codecSnapshot(1, "a", "b")
	snapshot.Policy.Carriers = 1
	plan, err := newSyncPlan(auth, snapshot, 1)
	if err != nil {
		t.Fatal(err)
	}
	installPlan(t, r, plan)
	backend := &fakeMuxSession{}
	c, err := carrier.New(backend, policyCarrier(snapshot.Policy))
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.ready = plan.tuple
	r.carriers[&SyncClientCarrier{receiver: r, backend: backend, carrier: c, tuple: plan.tuple, policy: snapshot.Policy}] = struct{}{}
	r.mu.Unlock()
	return r, plan
}
func metadataForPlan(p *syncPlan, id domain.TunnelID) SyncStreamMetadata {
	return SyncStreamMetadata{Version: ProtocolVersion, SyncVersion: 1, Type: OpenStreamMessageType, DeviceID: p.tuple.DeviceID, SessionID: p.tuple.SessionID, Revision: p.tuple.Revision, TransferID: p.tuple.TransferID, TunnelID: id, Protocol: domain.TunnelProtocolTCP}
}
func TestReceiverPendingDialRevokedBeforeACKAndLateConnClosed(t *testing.T) {
	for _, kind := range []string{"target", "omit", "policy", "close"} {
		t.Run(kind, func(t *testing.T) {
			receiver, plan := readyReceiverForRevocation(t)
			agent, server := net.Pipe()
			defer server.Close()
			connected, peer := net.Pipe()
			defer peer.Close()
			tracked := &countedConn{Conn: connected}
			dial := &revocationDialer{started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), late: tracked}
			result := make(chan error, 1)
			go func() { result <- HandleSyncAgentStream(context.Background(), agent, receiver, dial) }()
			if err := WriteSyncStreamMetadata(server, metadataForPlan(plan, "a")); err != nil {
				t.Fatal(err)
			}
			revocationBarrier(t, dial.started)
			completed := make(chan error, 1)
			if kind == "close" {
				go func() { receiver.Close(); completed <- nil }()
			} else {
				next := plan.snapshot
				next.Tunnels = append([]domain.NativeTunnel(nil), next.Tunnels...)
				next.Revision++
				switch kind {
				case "target":
					next.Tunnels[0].TargetAddr = "127.0.0.1:2222"
				case "omit":
					next.Tunnels = next.Tunnels[1:]
				case "policy":
					next.Policy.MaxStreams++
				}
				updated, err := newSyncPlan(receiver.auth, next, 2)
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					var ack *syncFrame
					for i := 0; i < updated.frames(); i++ {
						e := wireEvent(t, updated.frame(i))
						var err error
						ack, err = receiver.accept(e.frame, e.bytes)
						if err != nil {
							completed <- err
							return
						}
					}
					if ack == nil {
						completed <- errors.New("missing ACK")
					} else {
						completed <- nil
					}
				}()
			}
			revocationBarrier(t, dial.canceled)
			select {
			case <-completed:
				t.Fatal("ACK/close returned before pending dial joined")
			default:
			}
			close(dial.release)
			if err := awaitSync(t, result); !errors.Is(err, context.Canceled) {
				t.Fatal("late dial escaped", err)
			}
			if err := awaitSync(t, completed); err != nil {
				t.Fatal(err)
			}
			if tracked.closes.Load() != 1 || receiver.work.Count() != 0 {
				t.Fatal("late connection or pending registration retained")
			}
		})
	}
}

type immediateRevocationDialer struct {
	conn    net.Conn
	started chan struct{}
}

func (d *immediateRevocationDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(d.started)
	return d.conn, nil
}
func TestReceiverUnchangedActiveRouteSurvivesOtherTunnelPublication(t *testing.T) {
	r, p := readyReceiverForRevocation(t)
	agent, server := net.Pipe()
	defer server.Close()
	connected, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	dial := &immediateRevocationDialer{conn: connected, started: make(chan struct{})}
	go func() { result <- HandleSyncAgentStream(ctx, agent, r, dial) }()
	if err := WriteSyncStreamMetadata(server, metadataForPlan(p, "a")); err != nil {
		t.Fatal(err)
	}
	revocationBarrier(t, dial.started)
	transfer := func() {
		t.Helper()
		_ = server.SetWriteDeadline(time.Now().Add(time.Second))
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		sent := make(chan error, 1)
		go func() { _, err := server.Write([]byte("x")); sent <- err }()
		var byte [1]byte
		if _, err := peer.Read(byte[:]); err != nil || byte[0] != 'x' {
			t.Fatal("unaffected active route interrupted", err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
	}
	transfer()
	next := p.snapshot
	next.Revision++
	next.Tunnels = append([]domain.NativeTunnel(nil), next.Tunnels...)
	next.Tunnels[1].TargetAddr = "127.0.0.1:2222"
	updated, err := newSyncPlan(r.auth, next, 2)
	if err != nil {
		t.Fatal(err)
	}
	installPlan(t, r, updated)
	if r.work.Count() != 1 {
		t.Fatal("unaffected work registration changed")
	}
	transfer()
	cancel()
	if err = awaitSync(t, result); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.work.Count() != 0 {
		t.Fatal("active registration leaked")
	}
}

func TestOwnedActiveStreamSurvivesUnrelatedRevisionThenRevokesTarget(t *testing.T) {
	tracked := &syncRecordedStream{}
	backend := &fakeMuxSession{streams: []mux.Stream{tracked}}
	owner, agent, tuple := ownedReady(t, backend)
	stream, err := agent.OpenStream(context.Background(), domain.StreamOpenRequest{Revision: tuple.Revision, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	desired, err := owner.DeviceConfiguration(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	desired.Device.Name = "updated name"
	if _, err = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	if tracked.closes.Load() != 0 || backend.CloseCount() != 0 {
		t.Fatal("unrelated revision closed active stream or carrier")
	}
	if _, err = stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	desired, err = owner.DeviceConfiguration(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].TargetAddr = "127.0.0.1:2222"
	if _, err = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	if tracked.closes.Load() != 1 || backend.CloseCount() != 0 {
		t.Fatal("target change did not isolate stream revocation")
	}
}
func TestReceiverPublicationBeforeAdmissionRejectsOldMetadata(t *testing.T) {
	r, p := readyReceiverForRevocation(t)
	next := p.snapshot
	next.Revision++
	next.Tunnels = append([]domain.NativeTunnel(nil), next.Tunnels...)
	next.Tunnels[0].TargetAddr = "127.0.0.1:2222"
	updated, err := newSyncPlan(r.auth, next, 2)
	if err != nil {
		t.Fatal(err)
	}
	installPlan(t, r, updated)
	r.mu.Lock()
	r.ready = updated.tuple
	r.mu.Unlock()
	if _, lease, err := r.admitSyncTarget(context.Background(), metadataForPlan(p, "a")); !errors.Is(err, ErrSyncStale) || lease != nil {
		t.Fatal("obsolete target admitted", err)
	}
	target, lease, err := r.admitSyncTarget(context.Background(), metadataForPlan(updated, "a"))
	if err != nil {
		t.Fatal(err)
	}
	lease.Finish()
	if target != next.Tunnels[0].TargetAddr || r.work.Count() != 0 {
		t.Fatal("new target not captured coherently")
	}
}

func TestOwnedPublicationAutomaticallyWakesBoundedControlSource(t *testing.T) {
	owner, svc, _, secret := syncOwnedFixture(t)
	auth := syncAuthFixture(t, svc, secret)
	source := &watchedOwnedSource{source: owner, calls: make(chan domain.ConfigRevision, 32)}
	server, err := svc.NewConfigServer(context.Background(), auth, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiver := receiverFixture(t, auth, nil)
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone, receiverDone := make(chan error, 1), make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, left) }()
	go func() { receiverDone <- receiver.Run(ctx, right) }()
	t.Cleanup(func() {
		cancel()
		_ = left.Close()
		_ = right.Close()
		_ = awaitSync(t, serverDone)
		_ = awaitSync(t, receiverDone)
	})
	if awaitOwnedRead(t, source) != 1 || awaitOwnedRead(t, source) != 1 {
		t.Fatal("initial full resync missing")
	}
	desired, err := owner.DeviceConfiguration(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].TargetAddr = "127.0.0.1:2222"
	if _, err = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	if awaitOwnedRead(t, source) != 2 || awaitOwnedRead(t, source) != 2 {
		t.Fatal("publication did not automatically send newest full snapshot")
	}
	snapshot, ok := receiver.Snapshot()
	if !ok || snapshot.Revision != 2 || snapshot.Tunnels[0].TargetAddr != desired.Tunnels[0].TargetAddr {
		t.Fatal("automatic resync mismatch")
	}
}

// This backend deliberately holds predecessor cleanup after replacement has
// published. The replacement's lifecycle must already be independently owned.
type blockedPredecessorBackend struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *blockedPredecessorBackend) ReceiveBufferLimit() int { return 0 }
func (b *blockedPredecessorBackend) OpenStream(context.Context) (mux.Stream, error) {
	return nil, errors.New("unused")
}
func (b *blockedPredecessorBackend) AcceptStream(context.Context) (mux.Stream, error) {
	return nil, errors.New("unused")
}
func (b *blockedPredecessorBackend) Close() error {
	b.once.Do(func() { close(b.entered); <-b.release })
	return nil
}

type observedDetachManager struct {
	*session.Manager
	detached chan domain.SessionID
}

func (m *observedDetachManager) Detach(ctx context.Context, id domain.SessionID) error {
	err := m.Manager.Detach(ctx, id)
	if err == nil {
		m.detached <- id
	}
	return err
}
func TestOwnedReplacementBlockedPredecessorCannotDelayNewDisable(t *testing.T) {
	backend := &blockedPredecessorBackend{entered: make(chan struct{}), release: make(chan struct{})}
	owner, old, _ := ownedReady(t, backend)
	svc := old.syncController().service
	observed := &observedDetachManager{Manager: svc.sessions.(*session.Manager), detached: make(chan domain.SessionID, 4)}
	svc.sessions = observed
	_, secret, err := owner.ResolveKAPv1DeviceForAuth(context.Background(), old.DeviceID())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	nonce := mustNonce(t)
	challenge, err := svc.BeginSyncAuth(context.Background(), AuthStartRequest{DeviceID: old.DeviceID(), ClientNonce: nonce}, 1)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignSyncAuthResponse(secret, old.DeviceID(), nonce, challenge.ServerNonce, 1)
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	var committed chan error
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(backend.release) }) }
	t.Cleanup(func() {
		release()
		if err := awaitSync(t, completed); err != nil {
			t.Error(err)
		}
		if committed != nil {
			if err := awaitSync(t, committed); err != nil {
				t.Error(err)
			}
		}
	})
	go func() {
		_, err := svc.CompleteSyncAuth(context.Background(), AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: proof}, 1)
		completed <- err
	}()
	revocationBarrier(t, backend.entered)
	current, err := svc.sessions.CurrentForDevice(context.Background(), old.DeviceID())
	if err != nil || current.ID() == old.ID() {
		t.Fatal("replacement not published", err)
	}
	changed := owner.ChangeSignal()
	desired, err := owner.DeviceConfiguration(context.Background(), old.DeviceID())
	if err != nil {
		t.Fatal(err)
	}
	desired.Device.Enabled = false
	committed = make(chan error, 1)
	go func() {
		_, err := owner.Commit(context.Background(), []domain.DeviceConfiguration{desired})
		committed <- err
	}()
	revocationBarrier(t, changed)
	// Assert actual retirement AND detachment while the old pool is still held.
	revocationBarrier(t, current.Done())
	select {
	case id := <-observed.detached:
		if id != current.ID() {
			t.Fatal("wrong session detached")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new disabled session not detached while predecessor cleanup blocked")
	}
	if _, err := svc.sessions.CurrentForDevice(context.Background(), old.DeviceID()); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatal("disabled replacement still current", err)
	}
	if _, ok := svc.registry.lookup(current.ID()); ok {
		t.Fatal("disabled replacement retained in auth registry")
	}
	select {
	case <-backend.release:
		t.Fatal("predecessor released before lifecycle assertions")
	default:
	}
	select {
	case <-completed:
		t.Fatal("authentication completion escaped blocked predecessor cleanup")
	default:
	}
	release()
}
