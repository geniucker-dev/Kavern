package agent_v1

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

func codecAuth(t *testing.T) SyncAuthResult {
	return SyncAuthResult{AuthResult: AuthResult{DeviceID: "device-1", SessionID: domain.SessionID(mustNonce(t)), ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: ConfigSyncVersion}
}
func codecSnapshot(revision domain.ConfigRevision, ids ...domain.TunnelID) domain.NativeSnapshot {
	s := domain.NativeSnapshot{DeviceID: "device-1", Revision: revision, Policy: domain.DefaultNativePolicy()}
	for _, id := range ids {
		s.Tunnels = append(s.Tunnels, domain.NativeTunnel{ID: id, Protocol: domain.TunnelProtocolTCP, TargetAddr: "127.0.0.1:2001"})
	}
	return s
}
func planFixture(t *testing.T, auth SyncAuthResult, revision, transfer domain.ConfigRevision, ids ...domain.TunnelID) *syncPlan {
	t.Helper()
	p, err := newSyncPlan(auth, codecSnapshot(revision, ids...), transfer)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func wireEvent(t *testing.T, f syncFrame) syncRead {
	t.Helper()
	data, err := encodeSyncPayload(f)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSyncPayload(data)
	if err != nil {
		t.Fatal(err)
	}
	return syncRead{frame: decoded, bytes: len(data)}
}

type fragmentReader struct{ io.Reader }

func (r fragmentReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestSyncCodecStrictMalformedTruncatedAndFrameLimits(t *testing.T) {
	auth := codecAuth(t)
	plan := planFixture(t, auth, 1, 1, "a")
	for i := 0; i < plan.frames(); i++ {
		var wire bytes.Buffer
		if err := writeSyncFrame(&wire, plan.frame(i)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readSyncFrame(fragmentReader{bytes.NewReader(wire.Bytes())}); err != nil {
			t.Fatal("fragmented frame", err)
		}
		for _, n := range []int{1, 3, wire.Len() - 1} {
			if _, _, err := readSyncFrame(bytes.NewReader(wire.Bytes()[:n])); err == nil {
				t.Fatal("truncated frame accepted")
			}
		}
	}
	begin, _ := encodeSyncPayload(plan.frame(0))
	entry, _ := encodeSyncPayload(plan.frame(1))
	ack, _ := encodeSyncPayload(scopedFrame("config_ack", plan.tuple))
	bad := [][]byte{
		bytes.Replace(begin, []byte(`"version":"kapv1"`), []byte(`"version":"kapv1","VERSION":"kapv1"`), 1),
		bytes.Replace(begin, []byte(`"config_sync_version":1`), []byte(`"config_sync_version":0`), 1),
		bytes.Replace(begin, []byte(`"revision":"1"`), []byte(`"revision":1`), 1),
		bytes.Replace(begin, []byte(`"revision":"1"`), []byte(`"revision":"01"`), 1),
		bytes.Replace(begin, []byte(`"count":1`), []byte(`"count":1025`), 1),
		bytes.Replace(begin, []byte(`"count":1`), []byte(`"count":null`), 1),
		bytes.Replace(begin, []byte(`"carriers":2`), []byte(`"Carriers":2`), 1),
		bytes.Replace(entry, []byte(`"index":0`), []byte(`"index":-1`), 1),
		bytes.Replace(entry, []byte(`"index":0`), []byte(`"index":1024`), 1),
		bytes.Replace(entry, []byte(`"protocol":"tcp"`), []byte(`"protocol":"http"`), 1),
		bytes.Replace(ack, []byte(`"type":"config_ack"`), []byte(`"type":"config_ack","count":0`), 1),
		bytes.Replace(ack, []byte(`"type":"config_ack"`), []byte(`"type":"config_ack","policy":null`), 1),
		append(append([]byte(nil), begin...), []byte(` {}`)...), []byte{0xff},
	}
	for i, data := range bad {
		if _, err := decodeSyncPayload(data); err == nil {
			t.Fatalf("malformed case %d accepted", i)
		}
	}
	padded := append(append([]byte(nil), ack...), bytes.Repeat([]byte(" "), MaxControlFrameBytes-len(ack))...)
	var wire bytes.Buffer
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(padded)))
	wire.Write(prefix[:])
	wire.Write(padded)
	if _, n, err := readSyncFrame(&wire); err != nil || n != MaxControlFrameBytes {
		t.Fatal("exact frame bound", err)
	}
	for _, n := range []uint32{0, MaxControlFrameBytes + 1, 1 << 31} {
		binary.BigEndian.PutUint32(prefix[:], n)
		if _, _, err := readSyncFrame(bytes.NewReader(prefix[:])); !errors.Is(err, ErrSyncTransfer) {
			t.Fatal("invalid prefix accepted", err)
		}
	}
}

func TestSyncPlanCountsCompletePayloadAndRejectsOversizedTransfer(t *testing.T) {
	auth := codecAuth(t)
	plan := planFixture(t, auth, 1, 1, "a", "b")
	total := 0
	for i := 0; i < plan.frames(); i++ {
		data, err := encodeSyncPayload(plan.frame(i))
		if err != nil {
			t.Fatal(err)
		}
		total += len(data)
	}
	if total != int(plan.total) || plan.frames() != 4 {
		t.Fatal("declared total excludes transfer envelopes")
	}
	auth.DeviceID = domain.DeviceID(strings.Repeat("d", 128))
	auth.SessionID = domain.SessionID(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 384)))
	snapshot := domain.NativeSnapshot{DeviceID: auth.DeviceID, Revision: 1, Policy: domain.DefaultNativePolicy()}
	for i := 0; i < config.MaxNativeTunnels; i++ {
		snapshot.Tunnels = append(snapshot.Tunnels, domain.NativeTunnel{ID: domain.TunnelID(strings.Repeat("x", 124) + string([]byte{byte('0' + i/1000), byte('0' + i/100%10), byte('0' + i/10%10), byte('0' + i%10)})), Protocol: domain.TunnelProtocolTCP, TargetAddr: strings.Repeat("x", 510) + ":1"})
	}
	if err := config.ValidateNativeSnapshot(snapshot); err != nil {
		t.Fatal("domain fixture invalid", err)
	}
	if _, err := newSyncPlan(auth, snapshot, 1); !errors.Is(err, ErrSyncCapacity) {
		t.Fatal("wire envelope budget bypassed", err)
	}
}

func TestSyncCodecRejectsShortWrites(t *testing.T) {
	auth := codecAuth(t)
	plan := planFixture(t, auth, 1, 1)
	if err := writeSyncFrame(syncShortWriter{}, plan.frame(0)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write ignored", err)
	}
}

type syncShortWriter struct{}

func (syncShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
