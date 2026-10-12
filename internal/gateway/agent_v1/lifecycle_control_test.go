package agent_v1

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func lifecycleControlFixture(t *testing.T) (*store.ConfigOwner, *AuthService, *ConfigServer, *ConfigReceiver, *fakeLifecycleClock) {
	t.Helper()
	owner, svc, _, secret := syncOwnedFixture(t)
	clock := newLifecycleFakeClock()
	svc.lifecycleClock = clock
	start := lifecycleFrame("auth_start", "device-1", "")
	start.ClientNonce = mustNonce(t)
	challenge, e := svc.beginLifecycleAuth(context.Background(), start)
	if e != nil {
		t.Fatal(e)
	}
	finish := challenge
	finish.Type = "auth_finish"
	finish, e = SignLifecycleFrame(secret, finish)
	if e != nil {
		t.Fatal(e)
	}
	auth, grant, e := svc.completeLifecycleAuth(context.Background(), finish)
	if e != nil {
		t.Fatal(e)
	}
	server, e := svc.NewConfigServer(context.Background(), auth, owner, &SyncStagingBudget{})
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := NewConfigReceiver(auth, &SyncStagingBudget{})
	if e != nil {
		t.Fatal(e)
	}
	receiver.lifecycle, e = NewClientLease(context.Background(), finish, grant, clock.Now(), secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { receiver.Close(); _ = svc.CloseSession(context.Background(), auth.SessionID) })
	return owner, svc, server, receiver, clock
}
func awaitLifecycle(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("lifecycle dispatcher did not reach expected state")
		}
		time.Sleep(time.Millisecond)
	}
}
func lifecycleGeneration(s *ServerLease, c *ClientLease) (domain.ConfigRevision, domain.ConfigRevision) {
	s.mu.Lock()
	sg := s.generation
	s.mu.Unlock()
	c.mu.Lock()
	cg := c.generation
	c.mu.Unlock()
	return sg, cg
}
func startLifecyclePair(t *testing.T, s *ConfigServer, r *ConfigReceiver, left, right net.Conn) (context.CancelFunc, chan error, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sd, rd := make(chan error, 1), make(chan error, 1)
	go func() { sd <- s.Run(ctx, left) }()
	go func() { rd <- r.Run(ctx, right) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-sd:
		case <-time.After(2 * time.Second):
			t.Error("server dispatcher not joined")
		}
		select {
		case <-rd:
		case <-time.After(2 * time.Second):
			t.Error("client dispatcher not joined")
		}
	})
	wait, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if _, e := r.WaitApplied(wait, 0); e != nil {
		t.Fatal(e)
	}
	return cancel, sd, rd
}
func TestLifecycleControlMultipleRenewalsCrossHourWithoutRevisionChange(t *testing.T) {
	_, svc, s, r, clock := lifecycleControlFixture(t)
	left, right := net.Pipe()
	startLifecyclePair(t, s, r, left, right)
	entry, _ := svc.registry.lookup(s.auth.SessionID)
	lease := entry.session.serverLease()
	initial, _ := r.Snapshot()
	for i := 0; i < 125; i++ {
		clock.Advance(30 * time.Second)
		want := domain.ConfigRevision(i + 2)
		awaitLifecycle(t, func() bool { a, b := lifecycleGeneration(lease, r.lifecycle); return a == want && b == want })
	}
	snapshot, ok := r.Snapshot()
	if !ok || !sameSnapshot(initial, snapshot) {
		t.Fatal("renewal changed desired configuration")
	}
	if clock.active() != 2 {
		t.Fatal("renewal timer state is not bounded", clock.active())
	}
	// An ordinary operation cancellation is isolated from live session authority.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if e := svc.withSyncSession(canceled, s.auth, func() error { return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := svc.withSyncSession(context.Background(), s.auth, func() error { return ErrSyncStale }); !errors.Is(e, ErrSyncStale) {
		t.Fatal(e)
	}
	if e := lease.Valid(context.Background()); e != nil {
		t.Fatal("ordinary failure retired live lease", e)
	}
	// The historical timestamp is irrelevant only for this negotiated session.
	entry.session.expiresAt = svc.now().Add(-time.Hour)
	if e := svc.withSyncSession(context.Background(), s.auth, func() error { return nil }); e != nil {
		t.Fatal("fixed session timestamp still active", e)
	}
	old := s.auth
	old.LifecycleVersion = 0
	if e := svc.withSyncSession(context.Background(), old, func() error { return nil }); !errors.Is(e, ErrSyncSchema) {
		t.Fatal("downgraded session admitted", e)
	}
}

// The coordinator writes one framed payload at a time. This peer drops exactly
// one selected payload while preserving subsequent frame boundaries.
type lifecycleDropConn struct {
	net.Conn
	mu      sync.Mutex
	prefix  []byte
	kind    string
	dropped bool
}

func (c *lifecycleDropConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prefix == nil {
		if len(p) != 4 {
			return 0, io.ErrShortWrite
		}
		c.prefix = append([]byte(nil), p...)
		return len(p), nil
	}
	prefix := c.prefix
	c.prefix = nil
	var f struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(p, &f)
	if f.Type == c.kind && !c.dropped {
		c.dropped = true
		return len(p), nil
	}
	if _, e := c.Conn.Write(prefix); e != nil {
		return 0, e
	}
	return c.Conn.Write(p)
}
func TestLifecycleControlLostChallengeProofAndGrant(t *testing.T) {
	for _, kind := range []string{"renew_challenge", "renew_response", "renew_ok"} {
		t.Run(kind, func(t *testing.T) {
			_, svc, s, r, clock := lifecycleControlFixture(t)
			left, right := net.Pipe()
			drop := &lifecycleDropConn{Conn: left, kind: kind}
			serverConn, clientConn := net.Conn(drop), right
			if kind == "renew_response" {
				drop.Conn = right
				serverConn = left
				clientConn = drop
			}
			startLifecyclePair(t, s, r, serverConn, clientConn)
			entry, _ := svc.registry.lookup(s.auth.SessionID)
			lease := entry.session.serverLease()
			clock.Advance(30 * time.Second)
			awaitLifecycle(t, func() bool { drop.mu.Lock(); defer drop.mu.Unlock(); return drop.dropped })
			clock.Advance(2 * time.Second)
			awaitLifecycle(t, func() bool { a, b := lifecycleGeneration(lease, r.lifecycle); return a == 2 && b == 2 })
			lease.mu.Lock()
			expiry := lease.expiry
			lease.mu.Unlock()
			if expiry.After(clock.Now().Add(lifecycleDuration)) {
				t.Fatal("duplicate extended lease more than once")
			}
		})
	}
}
func TestLifecycleControlStoppedPeerExpiresAndJoins(t *testing.T) {
	_, svc, s, _, clock := lifecycleControlFixture(t)
	left, right := net.Pipe()
	defer right.Close()
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background(), left) }()
	// The first snapshot write is blocked on this stopped peer. Expiry must abort
	// that writer without waiting for its real-time write deadline.
	clock.Advance(90 * time.Second)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lease expiry failed to abort blocked control writer")
	}
	awaitLifecycle(t, func() bool { _, ok := svc.registry.lookup(s.auth.SessionID); return !ok })
}
func TestLifecycleControlRevocationAndFreshSynchronization(t *testing.T) {
	for _, kind := range []string{"rotate", "delete", "disable", "replace"} {
		t.Run(kind, func(t *testing.T) {
			owner, svc, s, r, clock := lifecycleControlFixture(t)
			left, right := net.Pipe()
			startLifecyclePair(t, s, r, left, right)
			entry, _ := svc.registry.lookup(s.auth.SessionID)
			lease := entry.session.serverLease()
			clock.Advance(30 * time.Second)
			awaitLifecycle(t, func() bool { a, b := lifecycleGeneration(lease, r.lifecycle); return a == 2 && b == 2 })
			cfg, e := owner.DeviceConfiguration(context.Background(), "device-1")
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "rotate", "delete":
				w, e := owner.ManagementWindow(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				mutation := store.Mutation{Window: w, OperationID: kind, Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: cfg.Revision, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}
				if kind == "delete" {
					mutation.Kind = "delete_device"
					mutation.CredentialKind = ""
					mutation.Cascade = true
				}
				_, e = owner.ApplyMutation(context.Background(), mutation, nil)
				if e != nil {
					t.Fatal(e)
				}
			case "disable":
				cfg.Device.Enabled = false
				if _, e = owner.Commit(context.Background(), []domain.DeviceConfiguration{cfg}); e != nil {
					t.Fatal(e)
				}
			case "replace":
				start := lifecycleFrame("auth_start", "device-1", "")
				start.ClientNonce = mustNonce(t)
				challenge, e := svc.beginLifecycleAuth(context.Background(), start)
				if e != nil {
					t.Fatal(e)
				}
				_, secret, e := owner.ResolveKAPv1DeviceForAuth(context.Background(), "device-1")
				if e != nil {
					t.Fatal(e)
				}
				finish := challenge
				finish.Type = "auth_finish"
				finish, e = SignLifecycleFrame(secret, finish)
				clear(secret)
				if e != nil {
					t.Fatal(e)
				}
				fresh, _, e := svc.completeLifecycleAuth(context.Background(), finish)
				if e != nil {
					t.Fatal(e)
				}
				defer svc.CloseSession(context.Background(), fresh.SessionID)
				if fresh.SessionID == s.auth.SessionID {
					t.Fatal("reconnect reused session")
				}
				if e = svc.withSyncSession(context.Background(), fresh, func() error { return nil }); e != nil {
					t.Fatal(e)
				}
			}
			awaitLifecycle(t, func() bool {
				select {
				case <-lease.Done():
					return true
				default:
					return false
				}
			})
			if e := lease.Valid(context.Background()); e == nil {
				t.Fatal("revoked lease remained live")
			}
		})
	}
}
func TestLifecycleCommandRejectsSchemaOnlyPeerBeforePublication(t *testing.T) {
	owner, svc, manager, _ := syncOwnedFixture(t)
	serverTrust, clientTrust, _ := syncTLSFixture(t)
	left, right := net.Pipe()
	server, client := tls.Server(left, serverTrust), tls.Client(right, clientTrust)
	done := make(chan error, 1)
	go func() { done <- svc.ServeSyncTransport(context.Background(), server, owner, nil) }()
	defer right.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if e := client.Handshake(); e != nil {
		t.Fatal(e)
	}
	start := authFrame("auth_start")
	start.DeviceID = "device-1"
	start.ClientNonce = mustNonce(t)
	if e := writeSyncAuth(client, start); e != nil {
		t.Fatal(e)
	}
	reject, e := ReadLifecycleFrame(client)
	if e != nil || reject.Type != "auth_reject" {
		t.Fatal(reject.Type, e)
	}
	if e := <-done; !errors.Is(e, ErrSyncSchema) {
		t.Fatal(e)
	}
	if _, e := manager.CurrentForDevice(context.Background(), "device-1"); e == nil {
		t.Fatal("unsupported peer published session")
	}
}

func TestLifecycleControlRenewalDispatchRejectsWrongScopeFutureAndPendingNonce(t *testing.T) {
	for _, kind := range []string{"device", "session", "future", "nonce"} {
		t.Run(kind, func(t *testing.T) {
			_, svc, s, r, clock := lifecycleControlFixture(t)
			left, right := net.Pipe()
			defer right.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx, left) }()
			_ = right.SetDeadline(time.Now().Add(2 * time.Second))
			var tuple syncTuple
			for {
				data, e := readSyncTransportPayload(right)
				if e != nil {
					t.Fatal(e)
				}
				f, e := decodeLifecycleSyncPayload(data)
				if e != nil {
					t.Fatal(e)
				}
				tuple = f.tuple()
				if f.Type == "config_end" {
					break
				}
			}
			ack, e := encodeLifecycleSyncPayload(scopedFrame("config_ack", tuple))
			if e != nil {
				t.Fatal(e)
			}
			if e = writeControlPayload(right, ack); e != nil {
				t.Fatal(e)
			}
			clock.Advance(30 * time.Second)
			challenge, e := ReadLifecycleFrame(right)
			if e != nil {
				t.Fatal(e)
			}
			r.lifecycle.mu.Lock()
			secret := append([]byte(nil), r.lifecycle.secret...)
			r.lifecycle.mu.Unlock()
			proof := challenge
			proof.Type = "renew_response"
			switch kind {
			case "device":
				proof.DeviceID = "other"
			case "session":
				proof.SessionID = domain.SessionID(mustNonce(t))
			case "future":
				proof.Generation++
			case "nonce":
				proof.Nonce = mustNonce(t)
			}
			proof, e = SignLifecycleFrame(secret, proof)
			clear(secret)
			if e != nil {
				t.Fatal(e)
			}
			if e = WriteLifecycleFrame(right, proof); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("invalid renewal advanced dispatcher")
				}
			case <-time.After(time.Second):
				t.Fatal("invalid renewal did not retire session")
			}
			if _, ok := svc.registry.lookup(s.auth.SessionID); ok {
				t.Fatal("retired renewal retained registry")
			}
		})
	}
}
func TestLifecycleAuthenticationRotationRejectsOldProofAndReconnectResyncs(t *testing.T) {
	owner, svc, _, oldReceiver, clock := lifecycleControlFixture(t)
	start := lifecycleFrame("auth_start", "device-1", "")
	start.ClientNonce = mustNonce(t)
	challenge, e := svc.beginLifecycleAuth(context.Background(), start)
	if e != nil {
		t.Fatal(e)
	}
	oldReceiver.lifecycle.mu.Lock()
	secret := append([]byte(nil), oldReceiver.lifecycle.secret...)
	oldReceiver.lifecycle.mu.Unlock()
	finish := challenge
	finish.Type = "auth_finish"
	finish, e = SignLifecycleFrame(secret, finish)
	clear(secret)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := owner.DeviceConfiguration(context.Background(), "device-1")
	if e != nil {
		t.Fatal(e)
	}
	window, e := owner.ManagementWindow(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.ApplyMutation(context.Background(), store.Mutation{Window: window, OperationID: "rotation-auth", Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: cfg.Revision, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}, nil); e != nil {
		t.Fatal(e)
	}
	if _, _, e = svc.completeLifecycleAuth(context.Background(), finish); e == nil {
		t.Fatal("rotated credential accepted old finish")
	}
	_, secret, e = owner.ResolveKAPv1DeviceForAuth(context.Background(), "device-1")
	if e != nil {
		t.Fatal(e)
	}
	defer clear(secret)
	start.ClientNonce = mustNonce(t)
	challenge, e = svc.beginLifecycleAuth(context.Background(), start)
	if e != nil {
		t.Fatal(e)
	}
	finish = challenge
	finish.Type = "auth_finish"
	finish, e = SignLifecycleFrame(secret, finish)
	if e != nil {
		t.Fatal(e)
	}
	auth, grant, e := svc.completeLifecycleAuth(context.Background(), finish)
	if e != nil {
		t.Fatal(e)
	}
	defer svc.CloseSession(context.Background(), auth.SessionID)
	if auth.SessionID == oldReceiver.auth.SessionID {
		t.Fatal("reconnect reused old session")
	}
	server, e := svc.NewConfigServer(context.Background(), auth, owner, &SyncStagingBudget{})
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := NewConfigReceiver(auth, &SyncStagingBudget{})
	if e != nil {
		t.Fatal(e)
	}
	receiver.lifecycle, e = NewClientLease(context.Background(), finish, grant, clock.Now(), secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	left, right := net.Pipe()
	startLifecyclePair(t, server, receiver, left, right)
	snapshot, ok := receiver.Snapshot()
	if !ok || snapshot.DeviceID != "device-1" {
		t.Fatal("fresh reconnect did not receive complete snapshot")
	}
	if e = svc.withSyncSession(context.Background(), oldReceiver.auth, func() error { return nil }); e == nil {
		t.Fatal("old reconnect scope remained admissible")
	}
}

func TestLifecycleAuthenticationBlockedPredecessorCannotDelayNewExpiry(t *testing.T) {
	backend := &blockedPredecessorBackend{entered: make(chan struct{}), release: make(chan struct{})}
	owner, old, _ := ownedReady(t, backend)
	svc := old.syncController().service
	clock := newLifecycleFakeClock()
	svc.lifecycleClock = clock
	observed := &observedDetachManager{Manager: svc.sessions.(*session.Manager), detached: make(chan domain.SessionID, 4)}
	svc.sessions = observed
	_, secret, e := owner.ResolveKAPv1DeviceForAuth(context.Background(), old.DeviceID())
	if e != nil {
		t.Fatal(e)
	}
	defer clear(secret)
	start := lifecycleFrame("auth_start", old.DeviceID(), "")
	start.ClientNonce = mustNonce(t)
	challenge, e := svc.beginLifecycleAuth(context.Background(), start)
	if e != nil {
		t.Fatal(e)
	}
	finish := challenge
	finish.Type = "auth_finish"
	finish, e = SignLifecycleFrame(secret, finish)
	if e != nil {
		t.Fatal(e)
	}
	completed := make(chan error, 1)
	var once sync.Once
	release := func() { once.Do(func() { close(backend.release) }) }
	t.Cleanup(func() {
		release()
		select {
		case <-completed:
		case <-time.After(time.Second):
			t.Error("blocked authentication did not join")
		}
	})
	go func() { _, _, e := svc.completeLifecycleAuth(context.Background(), finish); completed <- e }()
	revocationBarrier(t, backend.entered)
	current, e := svc.sessions.CurrentForDevice(context.Background(), old.DeviceID())
	if e != nil || current.ID() == old.ID() {
		t.Fatal("replacement not published", e)
	}
	clock.Advance(90 * time.Second)
	revocationBarrier(t, current.Done())
	select {
	case id := <-observed.detached:
		if id != current.ID() {
			t.Fatal("wrong session detached")
		}
	case <-time.After(time.Second):
		t.Fatal("replacement expiry waited for predecessor cleanup")
	}
	if clock.active() != 0 {
		t.Fatal("expired session retained lease timer")
	}
	select {
	case <-completed:
		t.Fatal("authentication escaped blocked predecessor")
	default:
	}
}
