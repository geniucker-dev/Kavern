package security_test

import (
	"encoding/base64"
	"testing"

	"github.com/zhuhaoyu/kavern/internal/security"
)

func TestGenerateVKeyUsesAtLeast32RandomBytesAndURLSafeEncoding(t *testing.T) {
	vkey, err := security.GenerateVKey()
	if err != nil {
		t.Fatalf("GenerateVKey() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(vkey)
	if err != nil {
		t.Fatalf("generated vkey is not raw base64url: %v", err)
	}
	if len(raw) < 32 {
		t.Fatalf("generated vkey has %d bytes, want at least 32", len(raw))
	}
}

func TestLegacyWireTokenFromVKey(t *testing.T) {
	if _, err := security.LegacyWireTokenFromVKey(""); err == nil {
		t.Fatalf("expected empty vkey to fail")
	}

	token, err := security.LegacyWireTokenFromVKey("abc")
	if err != nil {
		t.Fatalf("LegacyWireTokenFromVKey() error = %v", err)
	}
	if token != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("token = %q", token)
	}
}

func TestNormalizeLegacyWireToken(t *testing.T) {
	token, err := security.NormalizeLegacyWireToken("900150983CD24FB0D6963F7D28E17F72")
	if err != nil {
		t.Fatalf("NormalizeLegacyWireToken() error = %v", err)
	}
	if token != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("normalized token = %q", token)
	}

	for _, input := range []string{"", "abc", "900150983cd24fb0d6963f7d28e17f7z", "900150983cd24fb0d6963f7d28e17f7200"} {
		if _, err := security.NormalizeLegacyWireToken(input); err == nil {
			t.Fatalf("NormalizeLegacyWireToken(%q) succeeded, want error", input)
		}
	}
}

func TestLegacyLookupKey(t *testing.T) {
	if _, err := security.LegacyLookupKey(nil, "900150983cd24fb0d6963f7d28e17f72"); err == nil {
		t.Fatalf("expected empty secret to fail")
	}

	key, err := security.LegacyLookupKey([]byte("secret"), "900150983CD24FB0D6963F7D28E17F72")
	if err != nil {
		t.Fatalf("LegacyLookupKey() error = %v", err)
	}
	const want = "a6d8f05457f43ae9a98410996d4070c6f171e67abf47c9f57a8dbc2f025c9d21"
	if key != want {
		t.Fatalf("lookup key = %q, want %q", key, want)
	}
}
