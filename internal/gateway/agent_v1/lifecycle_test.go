package agent_v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLifecycleTimer struct {
	clock    *fakeLifecycleClock
	at       time.Time
	callback func()
	active   bool
}

func (t *fakeLifecycleTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	old := t.active
	t.active = false
	return old
}

type fakeLifecycleClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeLifecycleTimer
}

func newLifecycleFakeClock() *fakeLifecycleClock { return &fakeLifecycleClock{now: time.Unix(1000, 0)} }
func (c *fakeLifecycleClock) Now() time.Time     { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeLifecycleClock) AfterFunc(d time.Duration, f func()) LifecycleTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeLifecycleTimer{c, c.now.Add(d), f, true}
	c.timers = append(c.timers, t)
	return t
}
func (c *fakeLifecycleClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	for _, t := range c.timers {
		if t.active && !c.now.Before(t.at) {
			t.active = false
			due = append(due, t.callback)
		}
	}
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}
func (c *fakeLifecycleClock) active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.active {
			n++
		}
	}
	return n
}

type fakeLifecycleAuthority struct {
	mu     sync.Mutex
	scope  LifecycleScope
	secret []byte
	ctx    context.Context
	cancel context.CancelFunc
	valid  bool
}

func (a *fakeLifecycleAuthority) Context() context.Context { return a.ctx }
func (a *fakeLifecycleAuthority) WithCurrent(ctx context.Context, s LifecycleScope, f func([]byte) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.valid || a.ctx.Err() != nil || ctx.Err() != nil || s != a.scope {
		return ErrLifecycleExpired
	}
	return f(a.secret)
}
func lifecycleFixture(t *testing.T) (*fakeLifecycleClock, *fakeLifecycleAuthority, LifecycleFrame) {
	t.Helper()
	clock := newLifecycleFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	secret := bytes.Repeat([]byte{0x31}, 32)
	scope := LifecycleScope{"device-1", domain.SessionID(mustNonce(t))}
	authority := &fakeLifecycleAuthority{scope: scope, secret: secret, ctx: ctx, cancel: cancel, valid: true}
	t.Cleanup(cancel)
	f := lifecycleFrame("auth_finish", scope.DeviceID, "")
	f.ClientNonce = mustNonce(t)
	f.ServerNonce = mustNonce(t)
	f.ChallengeID = mustNonce(t)
	f.LeaseMillis = LifecycleLeaseMillis
	f.ProofMillis = LifecycleAuthMillis
	f, e := SignLifecycleFrame(secret, f)
	if e != nil {
		t.Fatal(e)
	}
	return clock, authority, f
}
func serverLifecycleFixture(t *testing.T) (*ServerLease, *fakeLifecycleClock, *fakeLifecycleAuthority, LifecycleFrame, LifecycleFrame) {
	t.Helper()
	clock, a, finish := lifecycleFixture(t)
	lease, grant, e := NewServerLease(context.Background(), a.scope, finish, a, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { lease.Revoke(ErrLifecycleExpired) })
	return lease, clock, a, finish, grant
}
func lifecycleProof(t *testing.T, f LifecycleFrame, secret []byte) LifecycleFrame {
	t.Helper()
	f.Type = "renew_response"
	signed, e := SignLifecycleFrame(secret, f)
	if e != nil {
		t.Fatal(e)
	}
	return signed
}
func TestLifecycleCodecsExactTypesBoundsAndAuthenticatedFields(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	challenge := finish
	challenge.Type = "auth_challenge"
	challenge.HMAC = ""
	start := lifecycleFrame("auth_start", a.scope.DeviceID, "")
	start.ClientNonce = finish.ClientNonce
	carrier := lifecycleFrame("carrier_bind", a.scope.DeviceID, a.scope.SessionID)
	carrier.Role = TransportRoleDataCarrier
	carrier.CarrierNonce = mustNonce(t)
	carrier, e := SignLifecycleFrame(a.secret, carrier)
	if e != nil {
		t.Fatal(e)
	}
	carrierOK := carrier
	carrierOK.Type = "carrier_ok"
	carrierOK, e = SignLifecycleFrame(a.secret, carrierOK)
	if e != nil {
		t.Fatal(e)
	}
	clock.Advance(30 * time.Second)
	renew, e := lease.Poll(context.Background())
	if e != nil || renew == nil {
		t.Fatal(e)
	}
	proof := lifecycleProof(t, *renew, a.secret)
	grant, e := lease.AcceptProof(context.Background(), proof)
	if e != nil {
		t.Fatal(e)
	}
	for _, frame := range []LifecycleFrame{start, challenge, finish, initial, carrier, carrierOK, *renew, proof, *grant} {
		t.Run(frame.Type, func(t *testing.T) {
			data, e := EncodeLifecycleFrame(frame)
			if e != nil {
				t.Fatal(e)
			}
			got, e := DecodeLifecycleFrame(data)
			if e != nil || got != frame {
				t.Fatal("roundtrip")
			}
			var wire bytes.Buffer
			if e = WriteLifecycleFrame(&wire, frame); e != nil {
				t.Fatal(e)
			}
			if got, e = ReadLifecycleFrame(&wire); e != nil || got != frame {
				t.Fatal("framing")
			}
			for _, bad := range [][]byte{append(data, []byte(" {}")...), append(data[:len(data)-1], []byte(`,"unknown":1}`)...), append(data[:len(data)-1], []byte(`,"Version":"1"}`)...), bytes.Repeat([]byte{' '}, MaxLifecycleFrameBytes+1)} {
				if _, e = DecodeLifecycleFrame(bad); e == nil {
					t.Fatal("nonexact frame accepted")
				}
			}
			for _, mutate := range []func(*LifecycleFrame){func(f *LifecycleFrame) { f.LifecycleVersion = 0 }, func(f *LifecycleFrame) { f.SyncVersion = 2 }, func(f *LifecycleFrame) { f.Role = "unknown" }} {
				bad := frame
				mutate(&bad)
				if _, e = EncodeLifecycleFrame(bad); e == nil {
					t.Fatal("negotiation downgrade accepted")
				}
			}
		})
	}
	for _, frame := range []LifecycleFrame{finish, initial, carrier, carrierOK, proof, *grant} {
		if e = VerifyLifecycleFrame(a.secret, frame); e != nil {
			t.Fatal(e)
		}
		for _, mutate := range []func(*LifecycleFrame){func(f *LifecycleFrame) { f.DeviceID = "another-device" }, func(f *LifecycleFrame) {
			if f.SessionID != "" {
				f.SessionID = domain.SessionID(mustNonce(t))
			} else {
				f.ClientNonce = mustNonce(t)
			}
		}, func(f *LifecycleFrame) {
			if f.RemainingMillis != 0 {
				f.RemainingMillis--
			} else if f.Nonce != "" {
				f.Nonce = mustNonce(t)
			} else if f.CarrierNonce != "" {
				f.CarrierNonce = mustNonce(t)
			} else {
				f.ChallengeID = mustNonce(t)
			}
		}} {
			bad := frame
			mutate(&bad)
			if e = VerifyLifecycleFrame(a.secret, bad); e == nil {
				t.Fatal("authenticated field tamper accepted")
			}
		}
	}
	for _, n := range []uint32{0, MaxLifecycleFrameBytes + 1, math.MaxUint32} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		if _, e = ReadLifecycleFrame(bytes.NewReader(b[:])); e == nil {
			t.Fatal("length accepted")
		}
	}
	// Selected lifecycle fields cannot bypass schema-1 exact key/frame bounds.
	auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: a.scope.DeviceID, SessionID: a.scope.SessionID, ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: 1}
	f := heartbeatFrame("ping", auth)
	data, e := encodeLifecycleSyncPayload(f)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := decodeLifecycleSyncPayload(data); e != nil || got.Type != "ping" {
		t.Fatal("schema envelope")
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(data, &fields)
	delete(fields, "lifecycle_version")
	data, _ = json.Marshal(fields)
	if _, e = decodeLifecycleSyncPayload(data); e == nil {
		t.Fatal("missing lifecycle envelope accepted")
	}
}
func TestLifecycleInitialGrantFrozenAgainstWrongExchangeAndClock(t *testing.T) {
	_, clock, a, finish, grant := serverLifecycleFixture(t)
	sent := clock.Now()
	var cleanup atomic.Int32
	client, e := NewClientLease(context.Background(), finish, grant, sent, a.secret, clock, func() { cleanup.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Revoke(nil) })
	for _, mutate := range []func(*LifecycleFrame){func(f *LifecycleFrame) { f.ClientNonce = mustNonce(t) }, func(f *LifecycleFrame) { f.ServerNonce = mustNonce(t) }, func(f *LifecycleFrame) { f.ChallengeID = mustNonce(t) }, func(f *LifecycleFrame) { f.SessionID = domain.SessionID(mustNonce(t)) }, func(f *LifecycleFrame) { f.Generation = 2 }, func(f *LifecycleFrame) { f.LeaseMillis++ }, func(f *LifecycleFrame) { f.RemainingMillis-- }} {
		bad := grant
		mutate(&bad)
		if _, e = NewClientLease(context.Background(), finish, bad, sent, a.secret, clock, func() {}); e == nil {
			t.Fatal("initial grant tamper")
		}
	}
	// Even a correctly re-signed grant for another authenticated exchange fails.
	wrong := grant
	wrong.ServerNonce = mustNonce(t)
	wrong, e = SignLifecycleFrame(a.secret, wrong)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = NewClientLease(context.Background(), finish, wrong, sent, a.secret, clock, func() {}); e == nil {
		t.Fatal("other initial exchange accepted")
	}
	clock.Advance(90 * time.Second)
	if client.Valid() == nil || cleanup.Load() != 1 {
		t.Fatal("initial local equality expiry")
	}
	if _, e = NewClientLease(context.Background(), finish, grant, sent, a.secret, clock, func() {}); e == nil {
		t.Fatal("expired delayed initial grant resurrected")
	}
}
func TestLifecycleDuplicateLostGrantRemainingNeverExtends(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), a.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	clock.Advance(30 * time.Second)
	challenge, e := lease.Poll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	proof, e := client.Challenge(*challenge)
	if e != nil {
		t.Fatal(e)
	}
	first, e := lease.AcceptProof(context.Background(), *proof)
	if e != nil {
		t.Fatal(e)
	}
	expiry := lease.expiry
	// Drop original grant; retry recovers decreasing remaining time at fixed expiry.
	clock.Advance(2 * time.Second)
	retry, e := client.Poll()
	if e != nil || retry == nil || *retry != *proof {
		t.Fatal("bounded identical retry")
	}
	second, e := lease.AcceptProof(context.Background(), *retry)
	if e != nil || second.RemainingMillis != 88000 || !lease.expiry.Equal(expiry) {
		t.Fatal("duplicate extended lease", e)
	}
	if e = client.Grant(*second); e != nil {
		t.Fatal(e)
	}
	deadline := client.expiry
	clock.Advance(time.Second)
	if e = client.Grant(*first); e != nil || !client.expiry.Equal(deadline) {
		t.Fatal("duplicate grant reset local deadline", e)
	}
	if client.pending != nil || lease.pending != nil || lease.receipt == nil || clock.active() != 2 {
		t.Fatal("retained state/timer bound")
	}
}
func TestLifecycleForgottenFramesSyntaxScopeThenBoundedDrop(t *testing.T) {
	lease, clock, a, _, _ := serverLifecycleFixture(t)
	var forgotten LifecycleFrame
	for i := 0; i < 2; i++ {
		clock.Advance(30 * time.Second)
		f, e := lease.Poll(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		proof := lifecycleProof(t, *f, a.secret)
		if i == 0 {
			forgotten = proof
		}
		if _, e = lease.AcceptProof(context.Background(), proof); e != nil {
			t.Fatal(e)
		}
	}
	// Forgotten nonce/MAC has valid syntax but is not matched against retained history.
	forgotten.Nonce = mustNonce(t)
	forgotten.HMAC = strings.Repeat("0", 64)
	for i := 0; i < 2; i++ {
		if _, e := lease.AcceptProof(context.Background(), forgotten); !errors.Is(e, ErrLifecycleStale) {
			t.Fatal("forgotten message was verified or granted", e)
		}
	}
	if _, e := lease.AcceptProof(context.Background(), forgotten); !errors.Is(e, ErrLifecycleQuota) {
		t.Fatal("stale quota unbounded", e)
	}
	select {
	case <-lease.Done():
	default:
		t.Fatal("quota failed closed")
	}
}
func TestLifecycleStaleTimerCannotExpireNewGrantAndExpiryIsTerminal(t *testing.T) {
	lease, clock, a, _, _ := serverLifecycleFixture(t)
	clock.mu.Lock()
	oldCallback := clock.timers[len(clock.timers)-1].callback
	clock.mu.Unlock()
	clock.Advance(30 * time.Second)
	f, _ := lease.Poll(context.Background())
	proof := lifecycleProof(t, *f, a.secret)
	if _, e := lease.AcceptProof(context.Background(), proof); e != nil {
		t.Fatal(e)
	}
	oldCallback()
	if e := lease.Valid(context.Background()); e != nil {
		t.Fatal("stale callback expired new grant")
	}
	// No control dispatcher polls the next challenge: lease equality still expires.
	clock.Advance(90 * time.Second)
	if e := lease.Valid(context.Background()); e == nil {
		t.Fatal("lease equality survived")
	}
	if _, e := lease.AcceptProof(context.Background(), proof); e == nil {
		t.Fatal("expired duplicate resurrected")
	}
	if clock.active() != 0 {
		t.Fatal("terminal timer retained")
	}
}
func TestLifecycleChallengeRetriesProofDeadlineAndClientNoResurrection(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), a.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	clock.Advance(30 * time.Second)
	first, _ := lease.Poll(context.Background())
	clock.Advance(2 * time.Second)
	second, _ := lease.Poll(context.Background())
	clock.Advance(3 * time.Second)
	third, _ := lease.Poll(context.Background())
	if first == nil || second == nil || third == nil || *first != *second || *first != *third {
		t.Fatal("challenge changed on retry")
	}
	if f, e := lease.Poll(context.Background()); e != nil || f != nil {
		t.Fatal("challenge sends unbounded")
	}
	proof, e := client.Challenge(*first)
	if e != nil {
		t.Fatal(e)
	}
	clock.Advance(10 * time.Second)
	if _, e = lease.AcceptProof(context.Background(), *proof); e == nil {
		t.Fatal("proof accepted at deadline equality")
	}
	clock.Advance(5 * time.Second)
	if client.Valid() == nil {
		t.Fatal("lost grant confirmation stayed alive")
	}
}
func TestLifecycleHourOfVirtualRenewalsAndConcurrentRevoke(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), a.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	for i := 0; i < 125; i++ {
		clock.Advance(30 * time.Second)
		f, e := lease.Poll(context.Background())
		if e != nil || f == nil {
			t.Fatal("renewal unavailable", e)
		}
		proof, e := client.Challenge(*f)
		if e != nil {
			t.Fatal(e)
		}
		grant, e := lease.AcceptProof(context.Background(), *proof)
		if e != nil {
			t.Fatal(e)
		}
		if e = client.Grant(*grant); e != nil {
			t.Fatal(e)
		}
	}
	if lease.Generation() != 126 || clock.active() != 2 {
		t.Fatal("counter or timer retention")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = lease.Valid(context.Background()); lease.Revoke(ErrLifecycleExpired) }()
	}
	wg.Wait()
	if lease.Valid(context.Background()) == nil {
		t.Fatal("revocation revived")
	}
}
func TestLifecyclePendingRetainedMismatchFutureAndOverflowFailClosed(t *testing.T) {
	for _, kind := range []string{"nonce", "mac", "session", "device", "future", "replay-mismatch", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			lease, clock, a, _, _ := serverLifecycleFixture(t)
			clock.Advance(30 * time.Second)
			if kind == "overflow" {
				lease.mu.Lock()
				lease.generation = domain.ConfigRevision(math.MaxUint64)
				lease.mu.Unlock()
				if _, e := lease.Poll(context.Background()); e == nil {
					t.Fatal("counter wrapped")
				}
				return
			}
			challenge, e := lease.Poll(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			proof := lifecycleProof(t, *challenge, a.secret)
			switch kind {
			case "nonce":
				proof.Nonce = mustNonce(t)
				proof, e = SignLifecycleFrame(a.secret, proof)
			case "mac":
				proof.HMAC = strings.Repeat("0", 64)
			case "session":
				proof.SessionID = domain.SessionID(mustNonce(t))
				proof, e = SignLifecycleFrame(a.secret, proof)
			case "device":
				proof.DeviceID = "other"
				proof, e = SignLifecycleFrame(a.secret, proof)
			case "future":
				proof.Generation++
				proof, e = SignLifecycleFrame(a.secret, proof)
			case "replay-mismatch":
				if _, e = lease.AcceptProof(context.Background(), proof); e != nil {
					t.Fatal(e)
				}
				proof.Nonce = mustNonce(t)
				proof, e = SignLifecycleFrame(a.secret, proof)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = lease.AcceptProof(context.Background(), proof); e == nil {
				t.Fatal("mismatch extended")
			}
			if lease.Valid(context.Background()) == nil {
				t.Fatal("mismatch not terminal")
			}
		})
	}
}
func TestLifecycleClientRetriesScopeStaleAndQuota(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), a.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	clock.Advance(30 * time.Second)
	challenge, _ := lease.Poll(context.Background())
	proof, e := client.Challenge(*challenge)
	if e != nil {
		t.Fatal(e)
	}
	// Duplicate challenges consume the same bounded proof-send budget.
	for i := 0; i < 2; i++ {
		again, e := client.Challenge(*challenge)
		if e != nil || again == nil || *again != *proof {
			t.Fatal("duplicate allocated new proof")
		}
	}
	if f, e := client.Poll(); e != nil || f != nil {
		t.Fatal("unbounded extra proof")
	}
	grant, e := lease.AcceptProof(context.Background(), *proof)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Grant(*grant); e != nil {
		t.Fatal(e)
	}
	expiry := client.expiry
	for i := 0; i < 3; i++ {
		if e = client.Grant(*grant); e != nil || !client.expiry.Equal(expiry) {
			t.Fatal("duplicate grant deadline or budget")
		}
	}
	if e = client.Grant(*grant); !errors.Is(e, ErrLifecycleQuota) {
		t.Fatal("retained grant spam unlimited", e)
	}
}
func TestLifecycleClientForgottenGrantDropsWithoutHistory(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), a.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	var forgotten LifecycleFrame
	for i := 0; i < 2; i++ {
		clock.Advance(30 * time.Second)
		challenge, _ := lease.Poll(context.Background())
		proof, e := client.Challenge(*challenge)
		if e != nil {
			t.Fatal(e)
		}
		grant, e := lease.AcceptProof(context.Background(), *proof)
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			forgotten = *grant
		}
		if e = client.Grant(*grant); e != nil {
			t.Fatal(e)
		}
	}
	forgotten.Nonce = mustNonce(t)
	forgotten.HMAC = strings.Repeat("0", 64)
	if e = client.Grant(forgotten); !errors.Is(e, ErrLifecycleStale) {
		t.Fatal("forgotten grant matched against growing history", e)
	}
	if e = client.Valid(); e != nil {
		t.Fatal(e)
	}
}
func TestLifecycleEnvelopeBoundsAndNoOldMACDowngrade(t *testing.T) {
	_, _, a, finish, _ := serverLifecycleFixture(t)
	old, e := SignSyncAuthResponse(a.secret, finish.DeviceID, finish.ClientNonce, finish.ServerNonce, ConfigSyncVersion)
	if e != nil {
		t.Fatal(e)
	}
	finish.HMAC = old
	if VerifyLifecycleFrame(a.secret, finish) == nil {
		t.Fatal("old sync MAC accepted for lifecycle auth")
	}
	f := heartbeatFrame("ping", SyncAuthResult{AuthResult: AuthResult{DeviceID: a.scope.DeviceID, SessionID: a.scope.SessionID, ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: 1})
	data, e := encodeLifecycleSyncPayload(f)
	if e != nil {
		t.Fatal(e)
	}
	padded := append(append([]byte(nil), data...), bytes.Repeat([]byte{' '}, MaxControlFrameBytes-len(data))...)
	if _, e = decodeLifecycleSyncPayload(padded); e != nil {
		t.Fatal("exact envelope bound", e)
	}
	if _, e = decodeLifecycleSyncPayload(append(padded, ' ')); e == nil {
		t.Fatal("envelope bound widened")
	}
	for _, bad := range []string{`{"lifecycle_version":1,"Lifecycle_Version":1}`, `{"lifecycle_version":null}`, `{"lifecycle_version":2}`} {
		if _, e = decodeLifecycleSyncPayload([]byte(bad)); e == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}
func TestLifecycleClientStaleTimerAndCanceledConstruction(t *testing.T) {
	lease, clock, a, finish, initial := serverLifecycleFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := NewClientLease(ctx, finish, initial, clock.Now(), a.secret, clock, func() {}); e == nil {
		t.Fatal("canceled client constructed")
	}
	client, e := NewClientLease(context.Background(), finish, initial, clock.Now(), a.secret, clock, func() {})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Revoke(nil)
	clock.mu.Lock()
	callback := clock.timers[len(clock.timers)-1].callback
	clock.mu.Unlock()
	clock.Advance(30 * time.Second)
	challenge, _ := lease.Poll(context.Background())
	proof, e := client.Challenge(*challenge)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := lease.AcceptProof(context.Background(), *proof)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Grant(*grant); e != nil {
		t.Fatal(e)
	}
	callback()
	if e = client.Valid(); e != nil {
		t.Fatal("stale client timer canceled new generation")
	}
}
