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
	"sync"
	"syscall"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
	"github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func main() {
	path := flag.String("config", "", "strict server JSON configuration")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("kavernd MVP KAPv1")
		return
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(path string) error {
	cfg, err := config.LoadServer(path)
	if err != nil {
		return err
	}
	key, err := store.MasterKeyFromEnv(cfg.MasterKeyEnv)
	if err != nil {
		return err
	}
	unlock, err := store.LockState(cfg.StateFile)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := store.LoadState(cfg.StateFile, key)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return err
	}
	tlsConfig := config.DefaultTLSConfig()
	tlsConfig.Certificates = []tls.Certificate{certificate}
	manager := session.NewManager()
	auth := agent_v1.NewAuthService(state, manager)
	routes := router.New(state, manager)
	var legacy *legacy_npc.Gateway
	if cfg.LegacyListen != "" {
		secret, err := base64.RawURLEncoding.DecodeString(os.Getenv(cfg.ServerSecretEnv))
		if err != nil || len(secret) < 32 {
			return errors.New("legacy server secret must contain at least 32 base64url bytes")
		}
		legacy, err = legacy_npc.New(legacy_npc.Config{ServerSecret: secret, Store: state, Sessions: manager})
		if err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	type service struct {
		listener net.Listener
		handler  func(net.Conn)
	}
	var services []service
	defer func() {
		for _, s := range services {
			s.listener.Close()
		}
	}()
	listen := func(address string, handler func(net.Conn)) (net.Listener, error) {
		l, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		services = append(services, service{l, handler})
		return l, nil
	}
	control, err := listen(cfg.ControlListen, func(raw net.Conn) {
		conn := tls.Server(raw, tlsConfig)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if conn.HandshakeContext(ctx) != nil {
			return
		}
		_ = auth.ServeTransport(ctx, conn, cfg.Limits)
	})
	if err != nil {
		return err
	}
	legacyAddr := ""
	if legacy != nil {
		l, err := listen(cfg.LegacyListen, func(c net.Conn) { _ = legacy.ServeConn(ctx, c) })
		if err != nil {
			return err
		}
		legacyAddr = l.Addr().String()
	}
	public := map[domain.TunnelID]string{}
	for _, tunnel := range state.Tunnels() {
		if !tunnel.Enabled {
			continue
		}
		device, err := state.GetDevice(ctx, tunnel.DeviceID)
		if err != nil {
			return err
		}
		if !device.Enabled {
			continue
		}
		l, err := listen(string(tunnel.Listener), func(c net.Conn) {
			_ = servePublicRoute(ctx, routes, tunnel, c, 5*time.Minute)
		})
		if err != nil {
			return err
		}
		public[tunnel.ID] = l.Addr().String()
	}
	var loops, workers sync.WaitGroup
	slots := make(chan struct{}, 256)
	failures := make(chan error, len(services))
	allClosed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			for _, s := range services {
				s.listener.Close()
			}
		case <-allClosed:
		}
	}()
	defer close(allClosed)
	for _, s := range services {
		loops.Add(1)
		go func() {
			defer loops.Done()
			for {
				c, err := s.listener.Accept()
				if err != nil {
					if ctx.Err() == nil {
						failures <- err
					}
					return
				}
				select {
				case slots <- struct{}{}:
				default:
					c.Close()
					continue
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					serveConnection(ctx, c, s.handler, slots)
				}()
			}
		}()
	}
	if err = json.NewEncoder(os.Stdout).Encode(struct {
		Event   string                     `json:"event"`
		Control string                     `json:"control"`
		Legacy  string                     `json:"legacy,omitempty"`
		Public  map[domain.TunnelID]string `json:"public"`
	}{"server_ready", control.Addr().String(), legacyAddr, public}); err != nil {
		cancel()
	}
	select {
	case <-ctx.Done():
	case err = <-failures:
		cancel()
	}
	cancel()
	loops.Wait()
	workers.Wait()
	return err
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
