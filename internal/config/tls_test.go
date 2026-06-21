package config_test

import (
	"testing"

	"github.com/zhuhaoyu/kavern/internal/config"
)

func TestDefaultTLSConfigDoesNotSkipVerify(t *testing.T) {
	cfg := config.DefaultTLSConfig()
	if cfg.InsecureSkipVerify {
		t.Fatalf("default TLS config must not set InsecureSkipVerify")
	}
}

func TestDevOnlyInsecureSkipVerifyIsExplicit(t *testing.T) {
	cfg := config.DefaultTLSConfig(config.DevOnlyInsecureSkipVerifyForTests())
	if !cfg.InsecureSkipVerify {
		t.Fatalf("explicit dev-only insecure option did not set InsecureSkipVerify")
	}
}
