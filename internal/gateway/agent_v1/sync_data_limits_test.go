package agent_v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
)

type oversizedSyncBackend struct{ fakeMuxSession }

func (b *oversizedSyncBackend) ReceiveBufferLimit() int { return 64 << 20 }
func TestSyncDataCarrierPolicyReplayCapacityAndFailureCleanup(t *testing.T) {
	first := &fakeMuxSession{}
	svc, auth, session, source, tuple, secret := readySyncUnit(t, first)
	makeRequest := func() SyncCarrierRequest {
		nonce := mustNonce(t)
		proof, err := SignSyncCarrierBind(secret, auth.SessionID, auth.DeviceID, nonce, ConfigSyncVersion)
		if err != nil {
			t.Fatal(err)
		}
		return SyncCarrierRequest{Binding: CarrierBindRequest{SessionID: auth.SessionID, CarrierNonce: nonce, ResponseHMAC: proof}, DeviceID: auth.DeviceID, Revision: tuple.Revision, TransferID: tuple.TransferID}
	}
	extra := &fakeMuxSession{}
	if err := svc.BindAndAttachSyncCarrier(context.Background(), makeRequest(), extra); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("snapshot carrier cap bypassed", err)
	}
	if extra.CloseCount() == 0 || session.pool.LiveCount() != 1 {
		t.Fatal("over-cap carrier leaked or changed pool")
	}
	request := makeRequest()
	stale := &fakeMuxSession{}
	request.Revision++
	if err := svc.BindAndAttachSyncCarrier(context.Background(), request, stale); !errors.Is(err, ErrSyncStale) {
		t.Fatal("stale carrier scope accepted", err)
	}
	if stale.CloseCount() == 0 {
		t.Fatal("failed bind retained backend")
	}
	request.Revision--
	replay := &fakeMuxSession{}
	if err := svc.BindAndAttachSyncCarrier(context.Background(), request, replay); !errors.Is(err, ErrCarrierNonceReplay) {
		t.Fatal("carrier nonce replay accepted", err)
	}
	if replay.CloseCount() == 0 {
		t.Fatal("replay retained backend")
	}
	oversized := &oversizedSyncBackend{}
	if err := svc.BindAndAttachSyncCarrier(context.Background(), makeRequest(), oversized); err == nil {
		t.Fatal("receive buffer exceeds authenticated policy")
	}
	if oversized.CloseCount() == 0 {
		t.Fatal("bad backend retained")
	}
	if err := svc.markSyncReady(context.Background(), auth, tuple, 2); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("wrong count produced readiness", err)
	}
	next := source.snapshot
	next.Revision++
	source.set(next)
	if err := svc.markSyncReady(context.Background(), auth, tuple, 1); err == nil {
		t.Fatal("stale desired revision produced readiness")
	}
}

func TestSyncReadinessRequiresExactACKAndActualCarriers(t *testing.T) {
	svc, _, secret := newAuthFixture(t, true)
	auth := syncAuthFixture(t, svc, secret)
	snapshot := codecSnapshot(1, "a")
	snapshot.Policy.Carriers = 1
	source := &syncSource{snapshot: snapshot, calls: make(chan domain.ConfigRevision, 8)}
	if _, err := svc.NewConfigServer(context.Background(), auth, source, nil); err != nil {
		t.Fatal(err)
	}
	entry, _ := svc.registry.lookup(auth.SessionID)
	tuple := syncTuple{auth.DeviceID, auth.SessionID, 1, 1}
	data := entry.session.syncController()
	data.install(tuple, snapshot)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := svc.markSyncReady(ctx, auth, tuple, 1); err == nil {
		t.Fatal("missing ACK produced readiness")
	}
	if err := data.ack(tuple); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel2()
	if err := svc.markSyncReady(ctx2, auth, tuple, 1); err == nil {
		t.Fatal("missing actual carriers produced readiness")
	}
	if _, err := entry.session.OpenStream(context.Background(), domain.StreamOpenRequest{Revision: 1, TunnelID: "a", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("unready stream admission opened", err)
	}
}

func TestSyncStreamMetadataStrictNoCallerTargetAndBounds(t *testing.T) {
	auth := codecAuth(t)
	metadata := SyncStreamMetadata{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, Type: OpenStreamMessageType, DeviceID: auth.DeviceID, SessionID: auth.SessionID, Revision: 1, TransferID: 1, TunnelID: "a", Protocol: domain.TunnelProtocolTCP}
	var wire bytes.Buffer
	if err := WriteSyncStreamMetadata(&wire, metadata); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSyncStreamMetadata(fragmentReader{bytes.NewReader(wire.Bytes())}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{append(append([]byte(nil), data[:len(data)-1]...), []byte(`,"target_addr":"attacker.invalid:1"}`)...), bytes.Replace(data, []byte(`"revision":"1"`), []byte(`"revision":1`), 1), bytes.Replace(data, []byte(`"transfer_id":"1"`), []byte(`"transfer_id":"01"`), 1), bytes.Replace(data, []byte(`"device_id"`), []byte(`"DEVICE_ID"`), 1)} {
		if _, err := decodeSyncMetadata(body); err == nil {
			t.Fatal("untrusted metadata field accepted")
		}
	}
	if err := WriteSyncStreamMetadata(syncShortWriter{}, metadata); err == nil {
		t.Fatal("short metadata write ignored")
	}
	if _, err := ReadSyncStreamMetadata(bytes.NewReader(wire.Bytes()[:wire.Len()-1])); err == nil {
		t.Fatal("truncated metadata accepted")
	}
}

type readinessLiveBackend struct {
	fakeMuxSession
	done chan struct{}
	once sync.Once
}

func (b *readinessLiveBackend) Done() <-chan struct{} { return b.done }
func (b *readinessLiveBackend) Close() error {
	b.once.Do(func() { close(b.done) })
	return b.fakeMuxSession.Close()
}
func readinessCarrierRequest(t *testing.T, auth SyncAuthResult, tuple syncTuple, secret []byte) SyncCarrierRequest {
	t.Helper()
	nonce := mustNonce(t)
	proof, err := SignSyncCarrierBind(secret, auth.SessionID, auth.DeviceID, nonce, ConfigSyncVersion)
	if err != nil {
		t.Fatal(err)
	}
	return SyncCarrierRequest{Binding: CarrierBindRequest{SessionID: auth.SessionID, CarrierNonce: nonce, ResponseHMAC: proof}, DeviceID: auth.DeviceID, Revision: tuple.Revision, TransferID: tuple.TransferID}
}
func TestSyncCarrierReplacementRequiresFreshScopedReady(t *testing.T) {
	original := &readinessLiveBackend{done: make(chan struct{})}
	svc, auth, session, _, tuple, secret := readySyncUnit(t, original)
	ctx := context.Background()
	req := domain.StreamOpenRequest{Revision: tuple.Revision, TunnelID: "a", Protocol: domain.TunnelProtocolTCP}
	_ = original.Close()
	if session.pool.LiveCount() != 0 {
		t.Fatal("lost carrier still counted")
	}
	if stream, err := session.OpenStream(ctx, req); err == nil || stream != nil {
		t.Fatal("carrier loss retained admission")
	}
	recorded := &syncRecordedStream{}
	replacement := &readinessLiveBackend{fakeMuxSession: fakeMuxSession{streams: []mux.Stream{recorded}}, done: make(chan struct{})}
	if err := svc.BindAndAttachSyncCarrier(ctx, readinessCarrierRequest(t, auth, tuple, secret), replacement); err != nil {
		t.Fatal(err)
	}
	if session.pool.LiveCount() != 1 {
		t.Fatal("replacement not attached")
	}
	stream, err := session.OpenStream(ctx, req)
	if stream != nil {
		_ = stream.Close()
	}
	if !errors.Is(err, ErrSyncNotReady) || recorded.writes.Load() != 0 {
		t.Fatalf("replacement reused old readiness: error=%v metadata writes=%d", err, recorded.writes.Load())
	}
	wrong := tuple
	wrong.TransferID++
	if err = svc.markSyncReady(ctx, auth, wrong, 1); err == nil {
		t.Fatal("wrong-scope refresh restored readiness")
	}
	if stream, err = session.OpenStream(ctx, req); stream != nil || !errors.Is(err, ErrSyncNotReady) || recorded.writes.Load() != 0 {
		t.Fatal("wrong-scope refresh admitted metadata", err)
	}
	if err = svc.markSyncReady(ctx, auth, tuple, 1); err != nil {
		t.Fatal("fresh scoped ready validation failed", err)
	}
	stream, err = session.OpenStream(ctx, req)
	if err != nil || stream == nil {
		t.Fatal("fresh readiness did not admit stream", err)
	}
	_ = stream.Close()
	if recorded.writes.Load() == 0 {
		t.Fatal("fresh readiness emitted no metadata")
	}
}
func TestFailedSyncCarrierAttachmentPreservesExistingReady(t *testing.T) {
	recorded := &syncRecordedStream{}
	original := &readinessLiveBackend{fakeMuxSession: fakeMuxSession{streams: []mux.Stream{recorded}}, done: make(chan struct{})}
	svc, auth, session, _, tuple, secret := readySyncUnit(t, original)
	ctx := context.Background()
	rejected := &readinessLiveBackend{done: make(chan struct{})}
	if err := svc.BindAndAttachSyncCarrier(ctx, readinessCarrierRequest(t, auth, tuple, secret), rejected); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("over-cap attachment accepted", err)
	}
	data := session.syncController()
	data.mu.Lock()
	ready := data.ready
	data.mu.Unlock()
	if ready != tuple || session.pool.LiveCount() != 1 || rejected.CloseCount() == 0 {
		t.Fatal("failed attachment changed readiness/carrier set or leaked backend")
	}
	stream, err := session.OpenStream(ctx, domain.StreamOpenRequest{Revision: tuple.Revision, TunnelID: "a", Protocol: domain.TunnelProtocolTCP})
	if err != nil || stream == nil {
		t.Fatal("failed attachment closed existing admission", err)
	}
	_ = stream.Close()
	if recorded.writes.Load() == 0 {
		t.Fatal("preserved readiness did not emit metadata")
	}
}
