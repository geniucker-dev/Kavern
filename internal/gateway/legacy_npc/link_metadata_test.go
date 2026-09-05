package legacy_npc

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestEncodeLegacyLinkMetadataExactWireContract(t *testing.T) {
	payload, err := encodeLegacyLinkMetadata("[::1]:43123", "127.0.0.1:51234")
	if err != nil {
		t.Fatalf("encodeLegacyLinkMetadata() error = %v", err)
	}
	if len(payload) < 4 {
		t.Fatalf("metadata payload is too short: %d", len(payload))
	}
	length := int(int32(binary.LittleEndian.Uint32(payload[:4])))
	if length != len(payload)-4 {
		t.Fatalf("metadata prefix = %d, payload body = %d", length, len(payload)-4)
	}
	want := `{"ConnType":"tcp","Host":"[::1]:43123","Crypt":false,"Compress":false,"LocalProxy":false,"RemoteAddr":"127.0.0.1:51234","ProtoVersion":"","Option":{"Timeout":5000000000}}`
	if got := string(payload[4:]); got != want {
		t.Fatalf("metadata JSON = %q, want %q", got, want)
	}
}

func TestLegacyLinkAddressValidation(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:80",
		"[::1]:443",
		"localhost:8080",
		"intranet-host:1234",
		"edge.example.test:65535",
	} {
		if _, err := encodeLegacyLinkMetadata(address, ""); err != nil {
			t.Fatalf("valid target %q error = %v", address, err)
		}
	}
	for _, address := range []string{
		"",
		":80",
		"host:0",
		"host:65536",
		"host:http",
		"https://host:443",
		"host/path:80",
		"bad host:80",
		"127.0.0.999:80",
		"::1:80",
	} {
		if _, err := encodeLegacyLinkMetadata(address, ""); !errors.Is(err, ErrLegacyInvalidTargetAddress) {
			t.Fatalf("invalid target %q error = %v, want ErrLegacyInvalidTargetAddress", address, err)
		}
	}
	for _, address := range []string{"", "127.0.0.1:4321", "[::1]:4321"} {
		if _, err := encodeLegacyLinkMetadata("localhost:8080", address); err != nil {
			t.Fatalf("valid remote address %q error = %v", address, err)
		}
	}
	for _, address := range []string{"bad remote", "https://remote", "remote/path", "remote\x00"} {
		if _, err := encodeLegacyLinkMetadata("localhost:8080", address); !errors.Is(err, ErrLegacyInvalidRemoteAddress) {
			t.Fatalf("invalid remote address %q error = %v, want ErrLegacyInvalidRemoteAddress", address, err)
		}
	}
}

func TestEncodeLegacyLinkMetadataBounds(t *testing.T) {
	oversized := make([]byte, maxLegacyAddressBytes+1)
	for index := range oversized {
		oversized[index] = 'a'
	}
	if _, err := encodeLegacyLinkMetadata(string(oversized)+":80", ""); !errors.Is(err, ErrLegacyInvalidTargetAddress) {
		t.Fatalf("oversized target error = %v", err)
	}
	if _, err := encodeLegacyLinkMetadata("localhost:80", string(oversized)); !errors.Is(err, ErrLegacyInvalidRemoteAddress) {
		t.Fatalf("oversized remote error = %v", err)
	}
}
