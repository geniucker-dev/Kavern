package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
	"github.com/geniucker-dev/kavern/internal/session"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestActualAgentProcessMixedServerFailsClosedWithSafeMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("actual process disabled by -short")
	}
	bins := buildNativeCommands(t)
	svc, _, _, _, secret := serviceFixture(t, "127.0.0.1:2001")
	manager := session.NewManager()
	old := agent_v1.NewAuthService(svc.owner, manager)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		done <- old.ServeTransport(ctx, tls.Server(raw, svc.trust), config.Limits{})
	}()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svc.trust.Certificates[0].Certificate[0]}), 0600)
	path := filepath.Join(dir, "agent.json")
	writeJSON(t, path, config.NativeBootstrap{Server: listener.Addr().String(), DeviceID: "device", SecretEnv: "KAVERN_MIXED_DEVICE", CAFile: ca})
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	env := append(os.Environ(), "KAVERN_MIXED_DEVICE="+encoded)
	agent := observeCommand(t, bins["kavern-agent"], path, env)
	event := agent.ready(t, "agent_reconnecting")
	if event.Event != "agent_reconnecting" {
		t.Fatal("mixed server reported ready")
	}
	select {
	case e := <-agent.events:
		if e.Event == "agent_ready" {
			t.Fatal("mixed server authenticated")
		}
	default:
	}
	agent.stop(t)
	_ = serviceWait(t, done)
	if _, err = manager.CurrentForDevice(context.Background(), "device"); err == nil {
		t.Fatal("mixed version authenticated on old server")
	}
	// Deprecated fields fail before network contact and never echo their values.
	writeJSON(t, path, map[string]any{"server": listener.Addr().String(), "device_id": "device", "secret_env": "KAVERN_MIXED_DEVICE", "ca_file": ca, "targets": map[string]string{"t": encoded}})
	rejected := exec.CommandContext(ctx, bins["kavern-agent"], "-config", path)
	rejected.Env = env
	output, err := rejected.CombinedOutput()
	if err == nil || bytes.Contains(output, []byte(encoded)) || !bytes.Contains(output, []byte("on the server")) {
		t.Fatal("deprecated agent configuration accepted or leaked values")
	}
}

// Native schema-0 is a previous Kavern protocol, not NPC/NPS. Its wire request
// cannot attach/replace a session on the synchronized actual daemon command.
func rejectOldNativePeer(t *testing.T, address, caPath, device string) {
	t.Helper()
	data, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("fixture CA invalid")
	}
	trust := config.DefaultTLSConfig()
	trust.RootCAs = roots
	trust.ServerName = "127.0.0.1"
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	nonce, err := agent_v1.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"version": agent_v1.ProtocolVersion, "role": "control", "type": "auth_start", "device_id": device, "client_nonce": nonce})
	if err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err = conn.Write(append(prefix[:], payload...)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > 4096 {
		t.Fatal("unbounded mixed-version reply")
	}
	reply := make([]byte, n)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	var frame struct{ Type, Code string }
	if json.Unmarshal(reply, &frame) != nil || frame.Type != "auth_reject" || frame.Code != "upgrade_required" {
		t.Fatal("old native peer not explicitly rejected")
	}
}
