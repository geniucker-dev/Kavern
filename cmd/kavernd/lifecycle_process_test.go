//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActualNativeLifecycleSameConnectionRenewalRevocationAndResync(t *testing.T) {
	if testing.Short() {
		t.Skip("actual approximately 100-second native lifecycle smoke disabled by -short")
	}
	bins := buildNativeCommands(t)
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "r")
	if e := os.Mkdir(runtimeDir, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(runtimeDir, "a.sock")
	master, secret := bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x32}, 32)
	env := append(os.Environ(), "KAVERN_LIFECYCLE_MASTER="+base64.RawURLEncoding.EncodeToString(master), "KAVERN_LIFECYCLE_DEVICE="+base64.RawURLEncoding.EncodeToString(secret))
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var ordinal atomic.Int64
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	firstClosed := make(chan struct{})
	receipts := make(chan string, 32)
	go func() {
		defer close(acceptDone)
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			id := ordinal.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				if id == 1 {
					defer close(firstClosed)
				}
				_, e := fmt.Fprintf(c, "connection-%d\n", id)
				if e != nil {
					return
				}
				reader := bufio.NewReader(c)
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					reply := fmt.Sprintf("connection-%d:%s", id, line)
					if _, e = io.WriteString(c, reply); e != nil {
						return
					}
					receipts <- reply
				}
			}()
		}
	}()
	var targetOnce sync.Once
	closeTarget := func() { targetOnce.Do(func() { _ = target.Close(); <-acceptDone; workers.Wait() }) }
	t.Cleanup(closeTarget)
	state := store.NewMemoryStore()
	ctx := context.Background()
	for _, e := range []error{state.CreateUser(ctx, domain.User{ID: "u"}), state.CreateProject(ctx, domain.Project{ID: "p", UserID: "u"}), state.CreateDevice(ctx, domain.Device{ID: "device", ProjectID: "p", Enabled: true}), state.SetKAPv1DeviceSecret(ctx, "device", secret), state.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel", DeviceID: "device", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:0", TargetAddr: target.Addr().String(), Enabled: true})} {
		if e != nil {
			t.Fatal(e)
		}
	}
	statePath := filepath.Join(dir, "state", "state.json")
	if e = state.SaveState(statePath, master); e != nil {
		t.Fatal(e)
	}
	cert, key := testCertificate(t, dir)
	serverPath := filepath.Join(dir, "server.json")
	writeJSON(t, serverPath, config.NativeServer{AdminSocket: socket, ControlListen: "127.0.0.1:0", CertFile: cert, KeyFile: key, StateFile: statePath, MasterKeyEnv: "KAVERN_LIFECYCLE_MASTER"})
	daemon := observeCommand(t, bins["kavernd"], serverPath, env)
	ready := daemon.ready(t, "server_ready")
	agentPath := filepath.Join(dir, "agent.json")
	writeJSON(t, agentPath, config.NativeBootstrap{Server: ready.Control, DeviceID: "device", SecretEnv: "KAVERN_LIFECYCLE_DEVICE", CAFile: cert})
	agent := observeCommand(t, bins["kavern-agent"], agentPath, env)
	agent.ready(t, "agent_ready")
	ctl := func(action string, args ...string) []byte {
		t.Helper()
		c := exec.Command(bins["kavernctl"], append([]string{"online", "--socket", socket, action}, args...)...)
		c.Env = env
		var diag bytes.Buffer
		c.Stderr = &diag
		data, e := c.Output()
		if e != nil || diag.Len() != 0 {
			t.Fatalf("owned lifecycle CLI %s failed: %v", action, e)
		}
		return data
	}
	status := func() config.AdminDeviceStatus {
		t.Helper()
		var s config.AdminDeviceStatus
		if e := json.Unmarshal(ctl("device-status", "--id", "device"), &s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	waitReady := func() config.AdminDeviceStatus {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			s := status()
			if s.Ready && len(s.Listeners) == 1 && s.Listeners[0].State == "bound" {
				return s
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("lifecycle process readiness timeout")
		return config.AdminDeviceStatus{}
	}
	initial := waitReady()
	revision := initial.DesiredRevision
	connect := func(address string) (net.Conn, *bufio.Reader, string) {
		t.Helper()
		c, e := net.DialTimeout("tcp", address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(c)
		header, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal("target connection greeting missing", e)
		}
		_ = c.SetReadDeadline(time.Time{})
		return c, reader, strings.TrimSpace(header)
	}
	connection, reader, identity := connect(initial.Listeners[0].BoundAddress)
	if identity != "connection-1" {
		t.Fatal("unexpected target connection identity")
	}
	exchange := func(c net.Conn, r *bufio.Reader, id, payload string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, e := io.WriteString(c, payload+"\n"); e != nil {
			t.Fatal("lifecycle stream write", e)
		}
		line, e := r.ReadString('\n')
		expected := id + ":" + payload + "\n"
		if e != nil || line != expected {
			t.Fatal("same target-confirmed stream changed or lost bytes", e)
		}
		select {
		case receipt := <-receipts:
			if receipt != expected {
				t.Fatal("target receipt mismatch")
			}
		case <-time.After(time.Second):
			t.Fatal("target receipt missing")
		}
		_ = c.SetDeadline(time.Time{})
	}
	start := time.Now()
	exchange(connection, reader, identity, "start")
	// Eleven exchanges on this exact connection, with quiet read periods between.
	for i := 1; i <= 10; i++ {
		timer := time.NewTimer(time.Until(start.Add(time.Duration(i) * 10 * time.Second)))
		select {
		case <-timer.C:
		case <-agent.exit:
			timer.Stop()
			t.Fatal("agent exited during sustained lifecycle smoke")
		case <-daemon.exit:
			timer.Stop()
			t.Fatal("daemon exited during sustained lifecycle smoke")
		}
		exchange(connection, reader, identity, fmt.Sprintf("receipt-%d", i))
		s := status()
		if !s.Ready || s.DesiredRevision != revision || s.Session.AppliedRevision != revision {
			t.Fatal("renewal changed desired/applied revision or readiness")
		}
		if i%3 == 0 || i == 10 {
			t.Logf("same target connection receipt=%d elapsed=%s renewals=%d revision=%d", i, time.Since(start).Round(time.Millisecond), s.Session.RenewalCount, revision)
		}
	}
	sustained := status()
	if sustained.Session.RenewalCount < 3 || ordinal.Load() != 1 {
		t.Fatal("same connection did not survive multiple renewals")
	}
	update := func(enabled bool, operation string) {
		t.Helper()
		var desired domain.DeviceConfiguration
		if e := json.Unmarshal(ctl("get-device", "--id", "device"), &desired); e != nil {
			t.Fatal(e)
		}
		var window config.AdminWindow
		if e := json.Unmarshal(ctl("window"), &window); e != nil {
			t.Fatal(e)
		}
		desired.Device.Enabled = enabled
		p := filepath.Join(dir, operation+".json")
		writeJSON(t, p, config.AdminMutation{Window: window, OperationID: operation, Kind: "put_device", DeviceID: "device", ExpectedRevision: desired.Revision, Configuration: &desired})
		var result config.AdminResult
		if e := json.Unmarshal(ctl("put-device", "--file", p), &result); e != nil || !result.Saved {
			t.Fatal("lifecycle mutation was not saved")
		}
	}
	update(false, "lifecycle-disable")
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, e = reader.ReadByte(); e == nil {
		t.Fatal("revoked old stream remained usable")
	}
	select {
	case <-firstClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked target did not join")
	}
	if status().Ready {
		t.Fatal("disabled device remained ready")
	}
	update(true, "lifecycle-enable")
	agent.ready(t, "agent_ready")
	fresh := waitReady()
	if fresh.DesiredRevision == revision || fresh.Session.RenewalCount != 0 {
		t.Fatal("fresh reconnect did not reset lease and synchronize new revision")
	}
	newConn, newReader, newIdentity := connect(fresh.Listeners[0].BoundAddress)
	if newIdentity == identity {
		t.Fatal("reconnect resumed old application connection")
	}
	exchange(newConn, newReader, newIdentity, "fresh-resync")
	_ = newConn.Close()
	t.Logf("terminal smoke: elapsed=%s renewals=%d target connections=%d daemon_pid=%d agent_pid=%d", time.Since(start).Round(time.Millisecond), sustained.Session.RenewalCount, ordinal.Load(), daemon.cmd.Process.Pid, agent.cmd.Process.Pid)
	agent.stop(t)
	daemon.stop(t)
	_ = connection.Close()
	closeTarget()
	reopened, e := store.OpenConfigOwner(statePath, master, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal("terminal daemon retained state lock", e)
	}
	_ = reopened.Close()
	if _, e = os.Lstat(socket); !os.IsNotExist(e) {
		t.Fatal("terminal daemon retained admin socket")
	}
	for _, address := range []string{ready.Control, fresh.Listeners[0].BoundAddress, target.Addr().String()} {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			t.Fatal("terminal process retained listener")
		}
	}
}
