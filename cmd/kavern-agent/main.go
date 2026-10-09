package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
)

func main() {
	path := flag.String("config", "", "strict agent JSON configuration")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("kavern-agent MVP KAPv1")
		return
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(path string) error {
	cfg, err := config.LoadAgent(path)
	if err != nil {
		return err
	}
	secret, err := base64.RawURLEncoding.DecodeString(os.Getenv(cfg.SecretEnv))
	if err != nil || len(secret) != 32 {
		return fmt.Errorf("device secret environment must contain 32 base64url bytes")
	}
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid CA file")
	}
	tlsConfig := config.DefaultTLSConfig()
	tlsConfig.RootCAs = roots
	tlsConfig.ServerName = cfg.ServerName
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = agent_v1.RunAgent(ctx, cfg, tlsConfig, secret, func() { fmt.Println(`{"event":"agent_ready"}`) })
	if ctx.Err() != nil {
		return nil
	}
	return err
}
