package agent_v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
	"testing"
	"time"
)

func prefixed(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}
func TestMetadataAmbiguityAndIDBounds(t *testing.T) {
	for _, payload := range []string{`{"version":"kapv1","type":"open_stream","tunnel_id":"safe","tunnel_id":"other","protocol":"tcp"}`, `{"version":"kapv1","type":"open_stream","tunnel_id":"safe","TUNNEL_ID":"other","protocol":"tcp"}`, `{"version":"kapv1","type":"open_stream","tunnel_id":"bad\nvalue","protocol":"tcp"}`, `{"version":"kapv1","type":"open_stream","tunnel_id":"safe","protocol":"tcp","target_addr":"127.0.0.1:1"}`} {
		if _, err := ReadOpenStreamMetadata(bytes.NewReader(prefixed([]byte(payload)))); err == nil {
			t.Fatal("ambiguous metadata accepted")
		}
	}
}
func TestAuthRoleVersionSeparationAndRotation(t *testing.T) {
	svc, st, secret := newAuthFixture(t, true)
	ctx := context.Background()
	nonce := mustNonce(t)
	ch, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{ProtocolVersion, TransportRoleDataCarrier}, {"kapv2", TransportRoleControl}} {
		if _, err := SignAuthResponse(secret, "device-1", nonce, ch.ServerNonce, pair[0], pair[1]); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("auth role/version accepted")
		}
	}
	result, _ := authenticate(t, svc)
	if _, err := SignCarrierBind(secret, result.SessionID, result.DeviceID, nonce, ProtocolVersion, TransportRoleControl); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("carrier control role accepted")
	}
	response := mustAuthResponse(t, secret, "device-1", nonce, ch.ServerNonce)
	rotated := bytes.Repeat([]byte{7}, 32)
	if err := st.SetKAPv1DeviceSecret(ctx, "device-1", rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: ch.AuthChallengeID, ResponseHMAC: response}); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("old auth survived rotation")
	}
	if _, err := svc.BindCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)}); !errors.Is(err, ErrAuthFailed) {
		t.Fatal("old carrier credential survived rotation")
	}
	fresh, _ := authenticateWithExistingSecret(t, svc, rotated)
	if fresh.SessionID == result.SessionID {
		t.Fatal("rotation reused session")
	}
	if _, ok := svc.registry.lookup(result.SessionID); ok {
		t.Fatal("replaced registry retained")
	}
	_ = svc.CloseSession(ctx, fresh.SessionID)
}
func TestAuthChallengeReplayAndRegistryCapacities(t *testing.T) {
	now := time.Now()
	svc, st, _ := newAuthFixture(t, true, WithNow(func() time.Time { return now }))
	ctx := context.Background()
	nonce := mustNonce(t)
	for i := 0; i < 4096; i++ {
		if _, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("challenge cap not enforced")
	}
	if len(svc.challenges) != 4096 {
		t.Fatal("challenge cap grew")
	}
	now = now.Add(3 * time.Minute)
	if _, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce}); err != nil {
		t.Fatal(err)
	}
	if len(svc.challenges) != 1 {
		t.Fatal("expired challenge records retained")
	}
	result, _ := authenticate(t, svc)
	for i := 0; i < 4096; i++ {
		if err := svc.registry.markNonceUsed(result.SessionID, fmt.Sprintf("nonce-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.registry.markNonceUsed(result.SessionID, "extra"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("replay capacity not enforced")
	}
	if err := svc.registry.markNonceUsed(result.SessionID, "nonce-0"); !errors.Is(err, ErrCarrierNonceReplay) {
		t.Fatal("replay forgotten at cap")
	}
	if err := svc.CloseSession(ctx, result.SessionID); err != nil {
		t.Fatal(err)
	}
	if len(svc.registry.byID) != 0 || len(svc.registry.byDevice) != 0 {
		t.Fatal("registry not cleaned")
	}
	// Disabled device must fail between challenge issuance and completion.
	challenge, err := svc.BeginAuth(ctx, AuthStartRequest{DeviceID: "device-1", ClientNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := st.ResolveKAPv1DeviceForAuth(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: challenge.AuthChallengeID, ResponseHMAC: mustAuthResponse(t, secret, "device-1", nonce, challenge.ServerNonce)}); !errors.Is(err, store.ErrDisabledDevice) {
		t.Fatal("disabled device completed auth")
	}
}
func FuzzNativeFrames(f *testing.F) {
	f.Add(prefixed([]byte(`{"version":"kapv1","type":"ping"}`)))
	f.Add([]byte{255, 255, 255, 255})
	f.Add(prefixed([]byte(`{"version":"kapv1","type":"open_stream","tunnel_id":"tunnel","protocol":"tcp"}`)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		_, _ = readControl(bytes.NewReader(data))
		_, _ = ReadOpenStreamMetadata(bytes.NewReader(data))
	})
}

func TestRegistryCapacityAndRemoval(t *testing.T) {
	r := newSessionRegistry()
	for i := 0; i < 4096; i++ {
		id := domain.SessionID(fmt.Sprintf("session-%d", i))
		s := newAgentSession(id, domain.DeviceID(fmt.Sprintf("device-%d", i)))
		if err := r.reserve(id, s); err != nil {
			t.Fatal(err)
		}
		if err := r.activate(id); err != nil {
			t.Fatal(err)
		}
	}
	extra := newAgentSession("extra", "extra")
	defer extra.Close(context.Background())
	if err := r.reserve("extra", extra); !errors.Is(err, ErrRegistryReserve) {
		t.Fatal("registry capacity not enforced")
	}
	for id, e := range r.byID {
		_ = e.session.Close(context.Background())
		r.remove(id)
	}
	if len(r.byID) != 0 || len(r.byDevice) != 0 {
		t.Fatal("registry entries retained after close")
	}
	if err := r.reserve("extra", extra); err != nil {
		t.Fatal("capacity not reusable")
	}
	r.remove("extra")
}
