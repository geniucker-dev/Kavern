package config

import "crypto/tls"

type TLSOption func(*tls.Config)

func DefaultTLSConfig(opts ...TLSOption) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func DevOnlyInsecureSkipVerifyForTests() TLSOption {
	return func(cfg *tls.Config) {
		cfg.InsecureSkipVerify = true
	}
}
