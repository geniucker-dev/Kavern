package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/store"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func serviceFixture(t *testing.T, target string) (*syncService, *tls.Config, string, []byte, []byte) {
	t.Helper()
	ctx := context.Background()
	state := store.NewMemoryStore()
	_ = state.CreateUser(ctx, domain.User{ID: "user"})
	_ = state.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"})
	_ = state.CreateDevice(ctx, domain.Device{ID: "device", ProjectID: "project", Enabled: true})
	secret, key := bytes.Repeat([]byte{0x71}, 32), bytes.Repeat([]byte{0x72}, 32)
	_ = state.SetKAPv1DeviceSecret(ctx, "device", secret)
	_ = state.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel", DeviceID: "device", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:0", TargetAddr: target, Enabled: true})
	dir := t.TempDir()
	path := filepath.Join(dir, "private", "state.json")
	if err := state.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := testCertificate(t, dir)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	trust := config.DefaultTLSConfig()
	trust.Certificates = []tls.Certificate{pair}
	client := config.DefaultTLSConfig()
	client.RootCAs = x509.NewCertPool()
	pem, err := os.ReadFile(certPath)
	if err != nil || !client.RootCAs.AppendCertsFromPEM(pem) {
		t.Fatal("fixture root invalid", err)
	}
	client.ServerName = "127.0.0.1"
	service, err := newSyncService(path, key, trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service, client, path, key, secret
}
func serviceBound(t *testing.T, s *syncService, state string) router.ListenerStatus {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		changed := s.public.Changed()
		for _, v := range s.public.Status() {
			if v.TunnelID == "tunnel" && v.State == state {
				return v
			}
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("service public status not reached", s.public.Status())
		}
	}
}
func serviceWait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(4 * time.Second):
		t.Fatal("service worker not joined")
		return nil
	}
}
func TestOwnedSyncServiceAssemblyTLSRoutingMutationAndShutdown(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var echoes sync.WaitGroup
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			echoes.Add(1)
			go func() { defer echoes.Done(); defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { _ = target.Close(); <-targetDone; echoes.Wait() })
	svc, trust, path, key, secret := serviceFixture(t, target.Addr().String())
	if _, err = store.OpenConfigOwner(path, key, domain.DefaultNativePolicy()); err == nil {
		t.Fatal("assembly did not hold exclusive state lock")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- svc.Run(ctx, "127.0.0.1:0") }()
	initial := serviceBound(t, svc, "bound")
	controlAddress := svc.ControlAddress()
	if controlAddress == "" {
		t.Fatal("control actual address missing")
	}
	t.Cleanup(func() {
		cancel()
		if err := svc.Close(); err != nil {
			t.Error(err)
		}
		if err := serviceWait(t, serverDone); err != nil {
			t.Error(err)
		}
	})
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: trust}
	raw, err := dial.DialContext(ctx, "tcp", controlAddress)
	if err != nil {
		t.Fatal(err)
	}
	receiver, control, err := agent_v1.AuthenticateSyncControl(ctx, raw.(*tls.Conn), "device", secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverDone := make(chan error, 1)
	go func() { receiverDone <- receiver.Run(ctx, control) }()
	t.Cleanup(func() { cancel(); _ = control.Close(); _ = serviceWait(t, receiverDone) })
	carrierDone := make([]chan error, 0, 2)
	for i := 0; i < 2; i++ {
		var attached *agent_v1.SyncClientCarrier
		for attempt := 0; attempt < 64; attempt++ {
			conn, err := dial.DialContext(ctx, "tcp", controlAddress)
			if err != nil {
				t.Fatal(err)
			}
			attached, err = receiver.BindSyncCarrierTLS(ctx, conn.(*tls.Conn), secret)
			if err == nil {
				break
			}
			if !errors.Is(err, agent_v1.ErrSyncNotReady) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
		if attached == nil {
			t.Fatal("full snapshot never applied")
		}
		done := make(chan error, 1)
		carrierDone = append(carrierDone, done)
		go func(c *agent_v1.SyncClientCarrier) { done <- c.Run(ctx, nil) }(attached)
	}
	t.Cleanup(func() {
		cancel()
		for _, done := range carrierDone {
			_ = serviceWait(t, done)
		}
	})
	if err = receiver.RequestReady(ctx); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", initial.BoundAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("owned listener native echo")
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(client, response); err != nil || !bytes.Equal(payload, response) {
		t.Fatal("owned routing did not echo", err)
	}
	desired, err := svc.owner.DeviceConfiguration(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	desired.Tunnels[0].Listener = domain.ListenerRef(occupied.Addr().String())
	if _, err = svc.owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	failed := serviceBound(t, svc, "bind_failed")
	if failed.BoundAddress != "" || failed.DesiredAddress != desired.Tunnels[0].Listener {
		t.Fatal("saved public failure invisible")
	}
	if svc.owner.ListenerCurrent(ctx, "tunnel", initial.Generation) {
		t.Fatal("changed listener generation survived")
	}
	if _, err = svc.auth.BeginSyncAuth(ctx, agent_v1.AuthStartRequest{DeviceID: "device", ClientNonce: mustServiceNonce(t)}, 1); err != nil {
		t.Fatal("public bind failure killed control auth", err)
	}
	_ = occupied.Close()
	_ = serviceBound(t, svc, "bound")
	desired, err = svc.owner.DeviceConfiguration(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	desired.Device.Enabled = false
	if _, err = svc.owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	_ = serviceBound(t, svc, "disabled")
	if svc.owner.ListenerCurrent(ctx, "tunnel", initial.Generation) {
		t.Fatal("disabled listener still admitted")
	}
	if _, err = svc.auth.BeginSyncAuth(ctx, agent_v1.AuthStartRequest{DeviceID: "device", ClientNonce: mustServiceNonce(t)}, 1); err == nil {
		t.Fatal("assembly auth did not share disabled owner")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = client.Read(b[:]); err == nil {
		t.Fatal("disabled device route survived")
	}
	cancel()
	if err = svc.Close(); err != nil {
		t.Fatal(err)
	}
	if svc.ControlAddress() != "" || len(svc.slots) != 0 || len(svc.public.Status()) != 0 {
		t.Fatal("assembly resources retained")
	}
	for _, address := range []string{initial.BoundAddress, controlAddress} {
		l, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("assembly socket survived shutdown", err)
		}
		_ = l.Close()
	}
	reopened, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal("assembly state lock not released", err)
	}
	defer reopened.Close()
	stored, err := reopened.DeviceConfiguration(context.Background(), "device")
	if err != nil || stored.Device.Enabled {
		t.Fatal("durable disabled state lost", err)
	}
}
func mustServiceNonce(t *testing.T) string {
	t.Helper()
	nonce, err := agent_v1.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func TestOwnedSyncServiceStartupFailureAndCloseBeforeRunReleaseLock(t *testing.T) {
	for _, run := range []bool{false, true} {
		t.Run(map[bool]string{false: "close-before-run", true: "control-bind-failure"}[run], func(t *testing.T) {
			svc, _, path, key, _ := serviceFixture(t, "127.0.0.1:2001")
			if run {
				occupied, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
				if err = svc.Run(context.Background(), occupied.Addr().String()); err == nil {
					t.Fatal("occupied control listener unexpectedly started")
				}
			} else {
				if err := svc.Close(); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
			if err != nil {
				t.Fatal("failed service retained state lock", err)
			}
			_ = reopened.Close()
			if len(svc.public.Status()) != 0 || len(svc.slots) != 0 {
				t.Fatal("failed startup retained runtime resources")
			}
		})
	}
}
