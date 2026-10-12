package agent_v1

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

type syncSource struct {
	mu       sync.Mutex
	snapshot domain.NativeSnapshot
	calls    chan domain.ConfigRevision
}

func (s *syncSource) NativeSnapshot(ctx context.Context, id domain.DeviceID) (domain.NativeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.NativeSnapshot{}, err
	}
	s.mu.Lock()
	snapshot := s.snapshot
	snapshot.Tunnels = append([]domain.NativeTunnel(nil), snapshot.Tunnels...)
	s.mu.Unlock()
	select {
	case s.calls <- snapshot.Revision:
	default:
	}
	return snapshot, nil
}
func (s *syncSource) set(snapshot domain.NativeSnapshot) {
	s.mu.Lock()
	s.snapshot = snapshot
	s.mu.Unlock()
}
func awaitSync(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("control worker did not join")
		return nil
	}
}
func awaitSource(t *testing.T, source *syncSource) domain.ConfigRevision {
	t.Helper()
	select {
	case revision := <-source.calls:
		return revision
	case <-time.After(3 * time.Second):
		t.Fatal("source was not re-read")
		return 0
	}
}
func readPeerFrame(t *testing.T, conn net.Conn) syncRead {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	f, size, err := readSyncFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return syncRead{frame: f, bytes: size}
}
func writePeerFrame(t *testing.T, conn net.Conn, f syncFrame) {
	t.Helper()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := writeSyncFrame(conn, f); err != nil {
		t.Fatal(err)
	}
}
func serverFixture(t *testing.T, snapshot domain.NativeSnapshot) (*AuthService, []byte, SyncAuthResult, *ConfigServer, *syncSource, *SyncStagingBudget) {
	t.Helper()
	svc, _, secret := newAuthFixture(t, true)
	auth := syncAuthFixture(t, svc, secret)
	source := &syncSource{snapshot: snapshot, calls: make(chan domain.ConfigRevision, 16)}
	budget := &SyncStagingBudget{}
	server, err := svc.NewConfigServer(context.Background(), auth, source, budget)
	if err != nil {
		t.Fatal(err)
	}
	return svc, secret, auth, server, source, budget
}
func readTransfer(t *testing.T, conn net.Conn, receiver *ConfigReceiver) syncFrame {
	t.Helper()
	for i := 0; i < 1026; i++ {
		e := readPeerFrame(t, conn)
		if e.frame.Type == "pong" {
			continue
		}
		ack, err := receiver.accept(e.frame, e.bytes)
		if err != nil {
			t.Fatal(err)
		}
		if ack != nil {
			return *ack
		}
	}
	t.Fatal("transfer exceeded frame limit")
	return syncFrame{}
}

func TestSyncControlPeerAtomicInstallACKEmptyAndCleanShutdown(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "tunnels", true: "empty"}[empty], func(t *testing.T) {
			snapshot := codecSnapshot(1, "a", "b")
			if empty {
				snapshot.Tunnels = nil
			}
			_, _, auth, server, source, budget := serverFixture(t, snapshot)
			receiver := receiverFixture(t, auth, budget)
			left, right := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer left.Close()
			defer right.Close()
			serverDone, clientDone := make(chan error, 1), make(chan error, 1)
			go func() { serverDone <- server.Run(ctx, left) }()
			go func() { clientDone <- receiver.Run(ctx, right) }()
			if awaitSource(t, source) != 1 || awaitSource(t, source) != 1 {
				t.Fatal("ACK did not trigger authoritative re-read")
			}
			if revision, err := server.AppliedRevision(ctx); err != nil || revision != 1 {
				t.Fatal("exact ACK did not apply", err)
			}
			got, ok := receiver.Snapshot()
			if !ok || !sameSnapshot(got, snapshot) {
				t.Fatal("peer did not atomically install snapshot")
			}
			cancel()
			_ = awaitSync(t, serverDone)
			_ = awaitSync(t, clientDone)
			if budget.Used() != 0 {
				t.Fatal("control shutdown leaked payload reservation")
			}
			if _, ok = receiver.Snapshot(); ok {
				t.Fatal("disconnect retained map")
			}
		})
	}
}

func TestSyncControlCoalescesSupersededRevisionAndDuplicateACK(t *testing.T) {
	_, _, auth, server, source, budget := serverFixture(t, codecSnapshot(1, "a"))
	receiver := receiverFixture(t, auth, budget)
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, left) }()
	ack1 := readTransfer(t, right, receiver)
	_ = awaitSource(t, source)
	source.set(codecSnapshot(2, "b"))
	server.NotifyDesired()
	source.set(codecSnapshot(3, "c"))
	for i := 0; i < 100; i++ {
		server.NotifyDesired()
	}
	if len(server.updates) > 1 {
		t.Fatal("unbounded desired wakeups")
	}
	writePeerFrame(t, right, ack1)
	receiver.ackSent()
	if awaitSource(t, source) != 3 {
		t.Fatal("supersession did not read latest state")
	}
	begin := readPeerFrame(t, right)
	if begin.frame.Type != "config_begin" || *begin.frame.Revision != 3 {
		t.Fatal("superseded revision was sent")
	}
	if _, err := receiver.accept(begin.frame, begin.bytes); err != nil {
		t.Fatal(err)
	}
	writePeerFrame(t, right, ack1) // exact old ACK is harmless during R3 transfer
	if revision, err := server.AppliedRevision(ctx); err != nil || revision != 1 {
		t.Fatal("duplicate ACK advanced application", err)
	}
	ack3 := readTransfer(t, right, receiver)
	if ack3.tuple().Revision != 3 {
		t.Fatal("latest transfer not received")
	}
	writePeerFrame(t, right, ack3)
	receiver.ackSent()
	if awaitSource(t, source) != 3 {
		t.Fatal("latest ACK not accepted")
	}
	if revision, err := server.AppliedRevision(ctx); err != nil || revision != 3 {
		t.Fatal("wrong applied revision", err)
	}
	cancel()
	_ = awaitSync(t, done)
	receiver.Close()
	if budget.Used() != 0 {
		t.Fatal("supersession leaked reservation")
	}
}

func TestSyncControlACKRejectsWrongDeviceSessionRevisionTransfer(t *testing.T) {
	for name, mutate := range map[string]func(*syncFrame){"device": func(f *syncFrame) { f.DeviceID = "other" }, "session": func(f *syncFrame) { f.SessionID = domain.SessionID(mustNonce(t)) }, "revision": func(f *syncFrame) { r := domain.ConfigRevision(2); f.Revision = &r }, "transfer": func(f *syncFrame) { id := domain.ConfigRevision(2); f.TransferID = &id }} {
		t.Run(name, func(t *testing.T) {
			_, _, auth, server, _, budget := serverFixture(t, codecSnapshot(1, "a"))
			receiver := receiverFixture(t, auth, budget)
			left, right := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer left.Close()
			defer right.Close()
			done := make(chan error, 1)
			go func() { done <- server.Run(ctx, left) }()
			ack := readTransfer(t, right, receiver)
			mutate(&ack)
			writePeerFrame(t, right, ack)
			if err := awaitSync(t, done); !errors.Is(err, ErrSyncStale) {
				t.Fatal("wrong ACK accepted", err)
			}
			server.mu.Lock()
			applied := server.applied
			server.mu.Unlock()
			if applied != 0 {
				t.Fatal("wrong ACK retained application")
			}
			receiver.Close()
			if budget.Used() != 0 {
				t.Fatal("wrong ACK leaked reservation")
			}
		})
	}
}

func TestSyncControlReplacementReleasesOldScopeAndReconnectResyncs(t *testing.T) {
	svc, secret, auth, server, source, budget := serverFixture(t, codecSnapshot(1, "a"))
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, left) }()
	begin := readPeerFrame(t, right)
	if begin.frame.Type != "config_begin" {
		t.Fatal("missing old begin")
	}
	newAuth := syncAuthFixture(t, svc, secret)
	if newAuth.SessionID == auth.SessionID {
		t.Fatal("reconnect reused session")
	}
	_ = awaitSync(t, done)
	if budget.Used() != 0 {
		t.Fatal("replacement retained old plan")
	}
	fresh, err := svc.NewConfigServer(ctx, newAuth, source, budget)
	if err != nil {
		t.Fatal(err)
	}
	receiver := receiverFixture(t, newAuth, budget)
	left2, right2 := net.Pipe()
	defer left2.Close()
	defer right2.Close()
	done2 := make(chan error, 1)
	go func() { done2 <- fresh.Run(ctx, left2) }()
	ack := readTransfer(t, right2, receiver)
	if ack.tuple().Revision != 1 || ack.SessionID != newAuth.SessionID || ack.tuple().TransferID != 1 {
		t.Fatal("same revision did not transfer on reconnect")
	}
	writePeerFrame(t, right2, ack)
	receiver.ackSent()
	cancel()
	_ = awaitSync(t, done2)
	receiver.Close()
	if budget.Used() != 0 {
		t.Fatal("reconnect retained staging")
	}
}

func TestSyncControlHeartbeatsDoNotExtendACKDeadline(t *testing.T) {
	_, _, auth, server, _, budget := serverFixture(t, codecSnapshot(1))
	server.timing = syncTiming{transfer: 150 * time.Millisecond, write: 50 * time.Millisecond, idle: time.Second, heartbeat: 10 * time.Millisecond}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, left) }()
	receiver := receiverFixture(t, auth, budget)
	_ = readTransfer(t, right, receiver)
	start := time.Now()
	pings := 0
	for {
		_ = right.SetWriteDeadline(time.Now().Add(time.Second))
		if err := writeSyncFrame(right, heartbeatFrame("ping", auth)); err != nil {
			break
		}
		_ = right.SetReadDeadline(time.Now().Add(time.Second))
		f, _, err := readSyncFrame(right)
		if err != nil {
			break
		}
		if f.Type != "pong" {
			t.Fatal("heartbeat not serviced")
		}
		pings++
	}
	if err := awaitSync(t, done); !errors.Is(err, ErrSyncDeadline) {
		t.Fatal("missing ACK did not expire", err)
	}
	if pings == 0 || time.Since(start) > time.Second {
		t.Fatal("heartbeat service/deadline unbounded")
	}
	receiver.Close()
	if budget.Used() != 0 {
		t.Fatal("ACK timeout retained budget")
	}
}

func TestSyncControlMalformedPartialFrameAndQueuedCleanup(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "oversized", true: "partial"}[partial], func(t *testing.T) {
			auth := codecAuth(t)
			budget := &SyncStagingBudget{}
			receiver := receiverFixture(t, auth, budget)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			timing := syncTiming{transfer: time.Second, write: 30 * time.Millisecond, idle: time.Second, heartbeat: time.Second}
			go func() { done <- runConfigControl(ctx, left, nil, receiver, nil, timing) }()
			var prefix [4]byte
			n := uint32(MaxControlFrameBytes + 1)
			if partial {
				n = 100
			}
			binary.BigEndian.PutUint32(prefix[:], n)
			_ = right.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := right.Write(prefix[:]); err != nil {
				t.Fatal(err)
			}
			if partial {
				if _, err := right.Write([]byte(`{"version":`)); err != nil {
					t.Fatal(err)
				}
			}
			if err := awaitSync(t, done); err == nil {
				t.Fatal("invalid partial frame accepted")
			}
			if _, ok := receiver.Snapshot(); ok {
				t.Fatal("invalid frame installed map")
			}
			if budget.Used() != 0 {
				t.Fatal("partial frame leaked payload")
			}
		})
	}
}

func TestSyncControlSingleWriterInterleavesPingBetweenEntries(t *testing.T) {
	_, _, auth, server, _, budget := serverFixture(t, codecSnapshot(1, "a", "b"))
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, left) }()
	receiver := receiverFixture(t, auth, budget)
	begin := readPeerFrame(t, right)
	if _, err := receiver.accept(begin.frame, begin.bytes); err != nil {
		t.Fatal(err)
	}
	pingDone := make(chan error, 1)
	go func() { pingDone <- writeSyncFrame(right, heartbeatFrame("ping", auth)) }()
	var ack *syncFrame
	sawPong := false
	for i := 0; i < 4; i++ {
		event := readPeerFrame(t, right)
		if event.frame.Type == "pong" {
			sawPong = true
			continue
		}
		var err error
		ack, err = receiver.accept(event.frame, event.bytes)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := awaitSync(t, pingDone); err != nil {
		t.Fatal(err)
	}
	if !sawPong || ack == nil {
		t.Fatal("control event lost/interleaved frame bytes")
	}
	writePeerFrame(t, right, *ack)
	receiver.ackSent()
	cancel()
	_ = awaitSync(t, done)
	receiver.Close()
	if budget.Used() != 0 {
		t.Fatal("interleaved control leaked budget")
	}
}

func TestSyncReaderQueueCapacityClosesAndJoinsOnBackpressure(t *testing.T) {
	auth := codecAuth(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inbox := make(chan syncRead, syncControlQueue)
	done := make(chan struct{})
	timing := syncTiming{transfer: time.Second, write: 30 * time.Millisecond, idle: time.Second, heartbeat: time.Second}
	go syncReader(ctx, left, inbox, done, timing)
	for i := 0; i < syncControlQueue+1; i++ {
		_ = right.SetWriteDeadline(time.Now().Add(time.Second))
		if err := writeSyncFrame(right, heartbeatFrame("ping", auth)); err != nil {
			t.Fatal("reader did not reach queue bound", err)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full queue did not retire reader")
	}
	if len(inbox) != syncControlQueue {
		t.Fatal("queue exceeded declared bound")
	}
	_ = right.SetReadDeadline(time.Now().Add(time.Second))
	var byte [1]byte
	if _, err := right.Read(byte[:]); err == nil {
		t.Fatal("full queue did not close transport")
	}
}
