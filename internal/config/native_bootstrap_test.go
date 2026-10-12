package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeBootstrapStrictIdentityAndTrustOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	valid := `{"server":"127.0.0.1:8024","device_id":"device","secret_env":"KAVERN_TEST_DEVICE","ca_file":"fixture-ca.pem"}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNativeBootstrap(path); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`,"targets":{"a":"127.0.0.1:2001"}`, `,"carriers":2`, `,"limits":{"max_streams":64}`, `,"insecure_skip_verify":true`, `,"DEVICE_ID":"other"`} {
		body := valid[:len(valid)-1] + extra + "}"
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadNativeBootstrap(path); err == nil {
			t.Fatal("local business/security override accepted")
		}
	}
}
