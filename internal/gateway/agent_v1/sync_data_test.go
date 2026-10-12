package agent_v1

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
)

type syncDataFixture struct {
	ctx      context.Context
	cancel   context.CancelFunc
	receiver *ConfigReceiver
	session  *agentSession
	source   *watchedOwnedSource
	secret   []byte
	trust    *tls.Config
	address  string
	shutdown func()
	carriers []*SyncClientCarrier
}

func newSyncDataFixture(t *testing.T, target string) *syncDataFixture {
	t.Helper()
	owner, svc, manager, secret := syncOwnedFixture(t)
	desired, err := owner.DeviceConfiguration(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].TargetAddr = target
	if _, err = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	serverTrust, clientTrust, _ := syncTLSFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	source := &watchedOwnedSource{source: owner, calls: make(chan domain.ConfigRevision, 32)}
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				_ = svc.ServeSyncTransport(ctx, tls.Server(raw, serverTrust), source, nil)
			}()
		}
	}()
	var once sync.Once
	cleanup := func() { once.Do(func() { cancel(); _ = listener.Close(); <-acceptDone; workers.Wait() }) }
	t.Cleanup(cleanup)
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: clientTrust}
	connected, err := dial.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	receiver, control, err := AuthenticateSyncControl(ctx, connected.(*tls.Conn), "device-1", secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	controlDone := make(chan error, 1)
	go func() { controlDone <- receiver.Run(ctx, control) }()
	t.Cleanup(func() { cancel(); _ = control.Close(); _ = awaitSync(t, controlDone) })
	_ = awaitOwnedRead(t, source)
	_ = awaitOwnedRead(t, source)
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	f := &syncDataFixture{ctx: ctx, cancel: cancel, receiver: receiver, session: current.(*agentSession), source: source, secret: secret, trust: clientTrust, address: listener.Addr().String(), shutdown: cleanup}
	if err = receiver.RequestReady(ctx); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("carrierless receiver ready", err)
	}
	snapshot, _ := receiver.Snapshot()
	for i := 0; i < snapshot.Policy.Carriers; i++ {
		connection, err := dial.DialContext(ctx, "tcp", f.address)
		if err != nil {
			t.Fatal(err)
		}
		c, err := receiver.BindSyncCarrierTLS(ctx, connection.(*tls.Conn), secret)
		if err != nil {
			t.Fatal(err)
		}
		f.carriers = append(f.carriers, c)
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx, nil) }()
		t.Cleanup(func() { cancel(); _ = c.Close(); _ = awaitSync(t, done) })
	}
	if err = receiver.RequestReady(ctx); err != nil {
		t.Fatal("scoped ready rejected actual attached carriers", err)
	}
	return f
}

func TestSyncDataAuthenticatedPolicyReadyAndTCPEcho(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-targetDone:
		case <-time.After(3 * time.Second):
			t.Error("target did not join")
		}
	})
	f := newSyncDataFixture(t, listener.Addr().String())
	snapshot, _ := f.receiver.Snapshot()
	if f.session.pool.LiveCount() != snapshot.Policy.Carriers {
		t.Fatal("actual carrier count differs from policy")
	}
	stream, err := f.session.OpenStream(f.ctx, domain.StreamOpenRequest{Revision: snapshot.Revision, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP, TargetAddr: "untrusted.invalid:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload := bytes.Repeat([]byte("scoped native echo"), 4096)
	writeDone := make(chan error, 1)
	go func() {
		_, err := stream.Write(payload)
		if err == nil {
			err = stream.(interface{ CloseWrite() error }).CloseWrite()
		}
		writeDone <- err
	}()
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("fixture echo bytes differ")
	}
	if err = awaitSync(t, writeDone); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	f.shutdown()
	if f.session.pool.LiveCount() != 0 {
		t.Fatal("shutdown retained server carriers")
	}
}

type zeroDial struct{ calls atomic.Int32 }

func (d *zeroDial) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("unexpected target dial")
}
func TestSyncDataStaleCrossDeviceMetadataNeverDials(t *testing.T) {
	f := newSyncDataFixture(t, "127.0.0.1:2001")
	snapshot, _ := f.receiver.Snapshot()
	f.receiver.mu.Lock()
	tuple := f.receiver.ready
	f.receiver.mu.Unlock()
	base := SyncStreamMetadata{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, Type: OpenStreamMessageType, DeviceID: tuple.DeviceID, SessionID: tuple.SessionID, Revision: snapshot.Revision, TransferID: tuple.TransferID, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP}
	for name, mutate := range map[string]func(*SyncStreamMetadata){"device": func(m *SyncStreamMetadata) { m.DeviceID = "other-device" }, "session": func(m *SyncStreamMetadata) { m.SessionID = domain.SessionID(mustNonce(t)) }, "revision": func(m *SyncStreamMetadata) { m.Revision++ }, "transfer": func(m *SyncStreamMetadata) { m.TransferID++ }, "tunnel": func(m *SyncStreamMetadata) { m.TunnelID = "other-tunnel" }, "protocol": func(m *SyncStreamMetadata) { m.Protocol = domain.TunnelProtocolHTTP }} {
		t.Run(name, func(t *testing.T) {
			metadata := base
			mutate(&metadata)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			dialer := &zeroDial{}
			done := make(chan error, 1)
			go func() { done <- HandleSyncAgentStream(f.ctx, left, f.receiver, dialer) }()
			if name == "protocol" {
				data := metadata
				data.Protocol = domain.TunnelProtocolTCP
				var wire bytes.Buffer
				if err := WriteSyncStreamMetadata(&wire, data); err != nil {
					t.Fatal(err)
				}
				raw := bytes.Replace(wire.Bytes(), []byte(`"protocol":"tcp"`), []byte(`"protocol":"bad"`), 1)
				_, _ = right.Write(raw)
			} else {
				if err := WriteSyncStreamMetadata(right, metadata); err != nil {
					t.Fatal(err)
				}
			}
			if err := awaitSync(t, done); err == nil {
				t.Fatal("invalid metadata accepted")
			}
			if dialer.calls.Load() != 0 {
				t.Fatal("stale/cross-device metadata dialed target")
			}
		})
	}
	_ = f.carriers[0].Close()
	if _, err := f.session.OpenStream(f.ctx, domain.StreamOpenRequest{Revision: snapshot.Revision, TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP}); err == nil {
		t.Fatal("lost carrier kept stream readiness")
	}
}

type delayedSyncBackend struct {
	started, release, done chan struct{}
	once                   sync.Once
	stream                 *syncRecordedStream
}

func (b *delayedSyncBackend) ReceiveBufferLimit() int { return 0 }
func (b *delayedSyncBackend) OpenStream(ctx context.Context) (mux.Stream, error) {
	close(b.started)
	select {
	case <-b.release:
		return b.stream, nil
	case <-b.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (b *delayedSyncBackend) AcceptStream(ctx context.Context) (mux.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (b *delayedSyncBackend) Close() error { b.once.Do(func() { close(b.done) }); return nil }

type syncRecordedStream struct{ writes, closes atomic.Int32 }

func (s *syncRecordedStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (s *syncRecordedStream) Write(p []byte) (int, error) { s.writes.Add(1); return len(p), nil }
func (s *syncRecordedStream) Close() error                { s.closes.Add(1); return nil }
func readySyncUnit(t *testing.T, backend mux.Session) (*AuthService, SyncAuthResult, *agentSession, *syncSource, syncTuple, []byte) {
	t.Helper()
	svc, _, secret := newAuthFixture(t, true)
	auth := syncAuthFixture(t, svc, secret)
	snapshot := codecSnapshot(1, "a")
	snapshot.Policy.Carriers = 1
	source := &syncSource{snapshot: snapshot, calls: make(chan domain.ConfigRevision, 32)}
	if _, err := svc.NewConfigServer(context.Background(), auth, source, &SyncStagingBudget{}); err != nil {
		t.Fatal(err)
	}
	entry, _ := svc.registry.lookup(auth.SessionID)
	tuple := syncTuple{auth.DeviceID, auth.SessionID, 1, 1}
	entry.session.syncController().install(tuple, snapshot)
	if err := entry.session.syncController().ack(tuple); err != nil {
		t.Fatal(err)
	}
	nonce := mustNonce(t)
	proof, err := SignSyncCarrierBind(secret, auth.SessionID, auth.DeviceID, nonce, ConfigSyncVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.BindAndAttachSyncCarrier(context.Background(), SyncCarrierRequest{Binding: CarrierBindRequest{SessionID: auth.SessionID, CarrierNonce: nonce, ResponseHMAC: proof}, DeviceID: auth.DeviceID, Revision: 1, TransferID: 1}, backend); err != nil {
		t.Fatal(err)
	}
	if err = svc.markSyncReady(context.Background(), auth, tuple, 1); err != nil {
		t.Fatal(err)
	}
	return svc, auth, entry.session, source, tuple, secret
}
func TestSyncDataRechecksAfterMuxPoolWait(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "revision", true: "session"}[replace], func(t *testing.T) {
			backend := &delayedSyncBackend{started: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{}), stream: &syncRecordedStream{}}
			svc, _, session, source, _, secret := readySyncUnit(t, backend)
			done := make(chan error, 1)
			go func() {
				stream, err := session.OpenStream(context.Background(), domain.StreamOpenRequest{Revision: 1, TunnelID: "a", Protocol: domain.TunnelProtocolTCP})
				if stream != nil {
					_ = stream.Close()
				}
				done <- err
			}()
			select {
			case <-backend.started:
			case <-time.After(time.Second):
				t.Fatal("mux open not reached")
			}
			if replace {
				_ = syncAuthFixture(t, svc, secret)
			} else {
				next := source.snapshot
				next.Revision = 2
				source.set(next)
				close(backend.release)
			}
			if err := awaitSync(t, done); err == nil {
				t.Fatal("stale post-wait stream opened")
			}
			if backend.stream.writes.Load() != 0 {
				t.Fatal("stale metadata emitted after wait")
			}
			if !replace && backend.stream.closes.Load() == 0 {
				t.Fatal("post-wait rejected lease not closed")
			}
		})
	}
}
