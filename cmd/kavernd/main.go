package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/store"
)

func main() {
	path := flag.String("config", "", "strict server JSON configuration")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("kavernd KAPv1 config-sync=1")
		return
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(path string) error {
	cfg, err := config.LoadNativeServer(path)
	if err != nil {
		return err
	}
	key, err := store.MasterKeyFromEnv(cfg.MasterKeyEnv)
	if err != nil {
		return err
	}
	defer clear(key)
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return err
	}
	trust := config.DefaultTLSConfig()
	trust.Certificates = []tls.Certificate{certificate}
	svc, err := newSyncService(cfg.StateFile, key, trust)
	if err != nil {
		return err
	}
	defer svc.Close()

	var legacyKey []byte
	if cfg.ServerSecretEnv != "" {
		legacyKey, err = base64.RawURLEncoding.DecodeString(os.Getenv(cfg.ServerSecretEnv))
		if err != nil || len(legacyKey) < 32 || len(legacyKey) > 4096 {
			return errors.New("legacy server secret must contain 32 to 4096 base64url bytes")
		}
		defer clear(legacyKey)
	}
	svc.adminSocket = cfg.AdminSocket
	svc.adminLegacyKey = legacyKey
	if cfg.LegacyListen != "" {
		svc.legacy, err = legacy_npc.New(legacy_npc.Config{ServerSecret: legacyKey, Store: svc.owner, Sessions: svc.manager})
		if err != nil {
			return err
		}
		svc.legacyListen = cfg.LegacyListen
	}

	svc.ready = func() error {
		public := map[domain.TunnelID]string{}
		status := svc.public.Status()
		for _, v := range status {
			if v.State == "bound" {
				public[v.TunnelID] = v.BoundAddress
			}
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			Event     string                     `json:"event"`
			Control   string                     `json:"control"`
			Legacy    string                     `json:"legacy,omitempty"`
			Public    map[domain.TunnelID]string `json:"public"`
			Listeners []router.ListenerStatus    `json:"listeners"`
		}{"server_ready", svc.ControlAddress(), svc.LegacyAddress(), public, status})
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return svc.Run(ctx, cfg.ControlListen)
}

// The route deadline governs opening the stream and both copy directions. A
// socket deadline alone cannot stop a copy waiting on a silent mux peer.
func servePublicRoute(ctx context.Context, routes router.TunnelRouter, tunnel domain.Tunnel, inbound net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	routeCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stopped := make(chan struct{})
	stop := context.AfterFunc(routeCtx, func() { defer close(stopped); _ = inbound.Close() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	if err := inbound.SetDeadline(deadline); err != nil {
		return err
	}
	err := routes.RouteTCP(routeCtx, tunnel, inbound)
	return errors.Join(err, routeCtx.Err())
}

// slots contains the reservation acquired by the listener loop. Release it only
// after routing and cancellation cleanup have finished.
func serveConnection(ctx context.Context, conn net.Conn, handler func(net.Conn), slots chan struct{}) {
	defer func() { <-slots }()
	defer conn.Close()
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(stopped); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	handler(conn)
}
