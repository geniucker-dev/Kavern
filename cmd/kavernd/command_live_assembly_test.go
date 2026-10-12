package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The agent is an actual process. Live changes use the reviewed in-process
// ConfigOwner assembly; there is deliberately no production test admin socket.
func TestActualAgentProcessLiveOwnedTargetBindAndDisable(t *testing.T) {
	if testing.Short() {
		t.Skip("actual process disabled by -short")
	}
	bins := buildNativeCommands(t)
	var replayed atomic.Bool
	t.Cleanup(func() {
		if replayed.Load() {
			t.Error("revoked application bytes replayed at replacement target")
		}
	})
	oldReceipt := make(chan struct{})
	var receiptOnce sync.Once
	first := processObservedEchoTarget(t, "first:", nil, func(data []byte) {
		if bytes.Contains(data, []byte("do-not-replay")) {
			receiptOnce.Do(func() { close(oldReceipt) })
		}
	})
	second := processObservedEchoTarget(t, "second:", func(data []byte) {
		if bytes.Contains(data, []byte("do-not-replay")) {
			replayed.Store(true)
		}
	})
	svc, _, _, _, secret := serviceFixture(t, first.Addr().String())
	initialPolicy, err := svc.owner.DeviceConfiguration(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	initialPolicy.Policy.Carriers = 3
	initialPolicy.Policy.MaxStreams = 8
	if _, err = svc.owner.Commit(context.Background(), []domain.DeviceConfiguration{initialPolicy}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svc.trust.Certificates[0].Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx, "127.0.0.1:0") }()
	initial := serviceBound(t, svc, "bound")
	t.Cleanup(func() {
		cancel()
		if err := svc.Close(); err != nil {
			t.Error(err)
		}
		if err := serviceWait(t, done); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "agent.json")
	writeJSON(t, path, config.NativeBootstrap{Server: svc.ControlAddress(), DeviceID: "device", SecretEnv: "KAVERN_LIVE_DEVICE", CAFile: ca})
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	agent := observeCommand(t, bins["kavern-agent"], path, append(os.Environ(), "KAVERN_LIVE_DEVICE="+encoded))
	_ = agent.ready(t, "agent_ready")
	assertProcessEOF(t, initial.BoundAddress, "first:")
	// Keep an application stream open through revocation; its bytes must not be
	// reconnected/replayed at the replacement target by the native agent.
	old, err := net.DialTimeout("tcp", initial.BoundAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	_ = old.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = old.Write([]byte("do-not-replay")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldReceipt:
	case <-time.After(time.Second):
		t.Fatal("old target did not receive marker before mutation")
	}
	desired, err := svc.owner.DeviceConfiguration(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].TargetAddr = second.Addr().String()
	if _, err = svc.owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	if event := agent.ready(t, "agent_ready"); event.Revision != "3" {
		t.Fatal("live agent did not apply authoritative revision")
	}
	var b [1]byte
	if _, err = old.Read(b[:]); err == nil {
		t.Fatal("revoked application stream continued")
	}
	assertProcessEOF(t, initial.BoundAddress, "second:")
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	desired, err = svc.owner.DeviceConfiguration(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].Listener = domain.ListenerRef(occupied.Addr().String())
	if _, err = svc.owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	_ = serviceBound(t, svc, "bind_failed")
	_ = agent.ready(t, "agent_ready")
	_ = occupied.Close()
	recovered := serviceBound(t, svc, "bound")
	assertProcessEOF(t, recovered.BoundAddress, "second:")
	desired, err = svc.owner.DeviceConfiguration(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	desired.Policy.Carriers = 1
	if _, err = svc.owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	if event := agent.ready(t, "agent_ready"); event.Revision != "5" {
		t.Fatal("policy retirement did not reconnect with authoritative carrier count")
	}
	assertProcessEOF(t, recovered.BoundAddress, "second:")
	desired, err = svc.owner.DeviceConfiguration(ctx, "device")
	if err != nil {
		t.Fatal(err)
	}
	desired.Device.Enabled = false
	if _, err = svc.owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	_ = serviceBound(t, svc, "disabled")
	agent.stop(t)
	cancel()
	if err = svc.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(agent.stderr.Bytes(), []byte(encoded)) {
		t.Fatal("live agent leaked fixture secret")
	}
}
