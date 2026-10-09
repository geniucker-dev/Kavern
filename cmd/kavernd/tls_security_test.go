package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"net"
	"os"
	"testing"
	"time"
)

func TestTLSHandshakeRejectsUntrustedWrongNameExpiredAndOldVersion(t *testing.T) {
	cert, key := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("CA invalid")
	}
	for _, name := range []string{"valid", "untrusted", "wrong-name", "expired", "old-version"} {
		t.Run(name, func(t *testing.T) {
			serverCfg := config.DefaultTLSConfig()
			serverCfg.Certificates = []tls.Certificate{pair}
			clientCfg := config.DefaultTLSConfig()
			clientCfg.RootCAs = roots
			clientCfg.ServerName = "127.0.0.1"
			switch name {
			case "untrusted":
				clientCfg.RootCAs = x509.NewCertPool()
			case "wrong-name":
				clientCfg.ServerName = "untrusted.invalid"
			case "expired":
				clientCfg.Time = func() time.Time { return time.Now().Add(2 * time.Hour) }
			case "old-version":
				clientCfg.MinVersion = tls.VersionTLS10
				clientCfg.MaxVersion = tls.VersionTLS11
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			server := tls.Server(a, serverCfg)
			client := tls.Client(b, clientCfg)
			done := make(chan error, 1)
			go func() { done <- server.HandshakeContext(ctx) }()
			clientErr := client.HandshakeContext(ctx)
			a.Close()
			b.Close()
			serverErr := <-done
			if name == "valid" {
				if clientErr != nil || serverErr != nil {
					t.Fatalf("trusted handshake failed: %v / %v", clientErr, serverErr)
				}
				return
			}
			if clientErr == nil {
				t.Fatal("unsafe TLS handshake accepted")
			}
			if name != "old-version" {
				var verify *tls.CertificateVerificationError
				if !errors.As(clientErr, &verify) {
					t.Fatalf("not certificate rejection: %v", clientErr)
				}
			}
		})
	}
}
