package agent_v1

import (
	"bytes"
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"io"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

type shortMetadataWriter struct{}

func (shortMetadataWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestMetadataRejectsShortWrite(t *testing.T) {
	err := WriteOpenStreamMetadata(shortMetadataWriter{}, OpenStreamMetadata{Version: ProtocolVersion, Type: OpenStreamMessageType, TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short metadata write=%v", err)
	}
}
func TestCanonicalRejectsFieldInjection(t *testing.T) {
	nonce := mustNonce(t)
	for _, value := range []string{"device\nclient_nonce=injected", "device\r", "device\x00"} {
		if _, err := CanonicalAuthMessage(domain.DeviceID(value), nonce, nonce, ProtocolVersion, TransportRoleControl); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("injection accepted: %v", err)
		}
		if _, err := CanonicalCarrierBindMessage(domain.SessionID(value), "device", nonce, ProtocolVersion, TransportRoleDataCarrier); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("bind injection accepted: %v", err)
		}
	}
}
func TestCloseSessionWithCanceledContextStillDetaches(t *testing.T) {
	svc, _, _ := newAuthFixture(t, true)
	result, _ := authenticate(t, svc)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.CloseSession(ctx, result.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.registry.lookup(result.SessionID); ok {
		t.Fatal("canceled cleanup retained session")
	}
}

// The peer produces its response only after EOF. A full Close masquerading as
// CloseWrite cannot pass this test because the response must still be readable.
func TestLeasedKAPStreamHalfClosePreservesResponse(t *testing.T) {
	server, agent := newMuxPair(t)
	defer server.Close()
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := carrier.New(server, carrier.Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	sess := newAgentSession("session", "device")
	defer sess.Close(context.Background())
	if err := sess.attachCarrier(c); err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan error, 1)
	go func() {
		peer, err := agent.AcceptStream(ctx)
		if err != nil {
			peerDone <- err
			return
		}
		defer peer.Close()
		if _, err := ReadOpenStreamMetadata(peer); err != nil {
			peerDone <- err
			return
		}
		payload, err := io.ReadAll(peer)
		if err != nil {
			peerDone <- err
			return
		}
		_, err = peer.Write(append([]byte("after-eof:"), bytes.Repeat(payload, 40000)...))
		if err == nil {
			err = peer.(interface{ CloseWrite() error }).CloseWrite()
		}
		_ = peer.Close()
		peerDone <- err
	}()
	stream, err := sess.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, append([]byte("after-eof:"), bytes.Repeat([]byte("payload"), 40000)...)) {
		t.Fatalf("response length=%d", len(response))
	}
}

func TestExpiredSessionRejectsCarrierAndDetaches(t *testing.T) {
	now := time.Now()
	svc, _, _ := newAuthFixture(t, true, WithNow(func() time.Time { return now }))
	result, secret := authenticate(t, svc)
	now = now.Add(time.Hour)
	nonce := mustNonce(t)
	signature := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	if _, err := svc.BindCarrier(context.Background(), CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: signature}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("expired bind=%v", err)
	}
	if _, ok := svc.registry.lookup(result.SessionID); ok {
		t.Fatal("expired session retained")
	}
	if _, err := svc.sessions.CurrentForDevice(context.Background(), result.DeviceID); err == nil {
		t.Fatal("expired session still routed")
	}
}

type failingCloseMux struct{ fakeMuxSession }

var errBackendCleanup = errors.New("test backend cleanup failure")

func (s *failingCloseMux) Close() error { return errBackendCleanup }
func TestCloseSessionDetachesDespiteBackendCleanupFailure(t *testing.T) {
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)
	nonce := mustNonce(t)
	if err := svc.BindAndAttachCarrier(context.Background(), CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)}, &failingCloseMux{}, carrier.Config{MaxStreamsPerCarrier: 1}); err != nil {
		t.Fatal(err)
	}
	if err := svc.CloseSession(context.Background(), result.SessionID); !errors.Is(err, errBackendCleanup) {
		t.Fatalf("cleanup error=%v", err)
	}
	if _, ok := svc.registry.lookup(result.SessionID); ok {
		t.Fatal("cleanup failure retained registry")
	}
	if _, err := svc.sessions.CurrentForDevice(context.Background(), result.DeviceID); err == nil {
		t.Fatal("cleanup failure retained route")
	}
}
