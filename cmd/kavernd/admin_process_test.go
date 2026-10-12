//go:build linux

package main

import (
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestActualOnlineDaemonCLIHotMutationsAndRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("actual local process assembly disabled by -short")
	}
	bins := buildNativeCommands(t)
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "r")
	if e := os.Mkdir(runtimeDir, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(runtimeDir, "a.sock")
	master := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	env := append(os.Environ(), "KAVERN_ADMIN_TEST_MASTER="+master)
	state := filepath.Join(dir, "state", "state.json")
	execCLI := func(args ...string) ([]byte, []byte, error) {
		t.Helper()
		c := exec.Command(bins["kavernctl"], args...)
		c.Env = env
		var diag bytes.Buffer
		c.Stderr = &diag
		data, e := c.Output()
		return data, diag.Bytes(), e
	}
	offline := func(args ...string) {
		t.Helper()
		_, diag, e := execCLI(args...)
		if e != nil {
			t.Fatalf("offline fixture command failed: %v %s", e, diag)
		}
	}
	offline("init-state", "-state", state, "-master-key-env", "KAVERN_ADMIN_TEST_MASTER", "-user", "initial-user", "-project", "initial-project")
	cert, key := testCertificate(t, dir)
	serverPath := filepath.Join(dir, "server.json")
	serverCfg := config.NativeServer{AdminSocket: socket, ControlListen: "127.0.0.1:0", CertFile: cert, KeyFile: key, StateFile: state, MasterKeyEnv: "KAVERN_ADMIN_TEST_MASTER"}
	writeJSON(t, serverPath, serverCfg)
	daemon := observeCommand(t, bins["kavernd"], serverPath, env)
	ready := daemon.ready(t, "server_ready")
	ctl := func(action string, args ...string) []byte {
		t.Helper()
		all := append([]string{"online", "--socket", socket, action}, args...)
		data, diag, e := execCLI(all...)
		if e != nil {
			t.Fatalf("online %s failed: %v %s", action, e, diag)
		}
		return data
	}
	window := func() config.AdminWindow {
		t.Helper()
		var w config.AdminWindow
		if e := json.Unmarshal(ctl("window"), &w); e != nil {
			t.Fatal(e)
		}
		return w
	}
	seq := 0
	saveRequest := func(m config.AdminMutation) string {
		t.Helper()
		seq++
		p := filepath.Join(dir, fmt.Sprintf("request-%d.json", seq))
		writeJSON(t, p, m)
		return p
	}
	mutate := func(action string, m config.AdminMutation, credential string) (config.AdminResult, string) {
		t.Helper()
		m.Window = window()
		m.OperationID = "process-op-" + strconv.Itoa(seq+1)
		p := saveRequest(m)
		args := []string{"--file", p}
		if credential != "" {
			args = append(args, "--credential-output", credential)
		}
		raw := ctl(action, args...)
		var r config.AdminResult
		if e := json.Unmarshal(raw, &r); e != nil || !r.Saved {
			t.Fatal("saved result missing")
		}
		if bytes.Contains(raw, []byte(`"issuance"`)) {
			t.Fatal("stdout exposed issuance")
		}
		return r, p
	}
	mutate("create-user", config.AdminMutation{Kind: "create_user", User: &domain.User{ID: "live-user"}}, "")
	mutate("create-project", config.AdminMutation{Kind: "create_project", Project: &domain.Project{ID: "live-project", UserID: "live-user"}}, "")
	credentialFile := filepath.Join(runtimeDir, "device-credential.json")
	_, createdRequest := mutate("create-device", config.AdminMutation{Kind: "create_device", Device: &domain.Device{ID: "live-device", ProjectID: "live-project", Enabled: true}, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}, credentialFile)
	var credential struct {
		DeviceID string               `json:"device_id"`
		Issuance config.AdminIssuance `json:"issuance"`
	}
	credentialData, e := os.ReadFile(credentialFile)
	if e != nil || json.Unmarshal(credentialData, &credential) != nil || credential.Issuance.Credential == "" {
		t.Fatal("protected issuance missing")
	}
	if st, e := os.Stat(credentialFile); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("issuance permissions")
	}
	if r := ctl("retry", "--file", createdRequest); bytes.Contains(r, []byte(credential.Issuance.Credential)) {
		t.Fatal("retry leaked credential")
	}
	var initial config.AdminDeviceStatus
	if e = json.Unmarshal(ctl("device-status", "--id", "live-device"), &initial); e != nil || initial.Ready || initial.Session.Present {
		t.Fatal("saved incorrectly ready")
	}
	get := func() domain.DeviceConfiguration {
		t.Helper()
		var c domain.DeviceConfiguration
		if e := json.Unmarshal(ctl("get-device", "--id", "live-device"), &c); e != nil {
			t.Fatal(e)
		}
		return c
	}
	deviceStatus := func() config.AdminDeviceStatus {
		t.Helper()
		var v config.AdminDeviceStatus
		if e := json.Unmarshal(ctl("device-status", "--id", "live-device"), &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	waitStatus := func(predicate func(config.AdminDeviceStatus) bool) config.AdminDeviceStatus {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			v := deviceStatus()
			if predicate(v) {
				return v
			}
			time.Sleep(40 * time.Millisecond)
		}
		t.Fatal("live status did not reach expected facts")
		return config.AdminDeviceStatus{}
	}
	policyReceived := make(chan struct{})
	var policyOnce sync.Once
	target1 := adminProcessEcho(t, "first:", func(data []byte) {
		if bytes.Contains(data, []byte("policy-stream")) {
			policyOnce.Do(func() { close(policyReceived) })
		}
	})
	rotationReceived := make(chan struct{})
	var receivedOnce sync.Once
	target2 := adminProcessEcho(t, "second:", func(data []byte) {
		if bytes.Contains(data, []byte("rotation-stream")) {
			receivedOnce.Do(func() { close(rotationReceived) })
		}
	})
	c := get()
	c.Tunnels = []domain.Tunnel{{ID: "live-tunnel", DeviceID: "live-device", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:0", TargetAddr: target1.Addr().String(), Enabled: true}}
	c.Policy.Carriers = 1
	mutate("put-device", config.AdminMutation{Kind: "put_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Configuration: &c}, "")
	agentPath := filepath.Join(dir, "agent.json")
	writeJSON(t, agentPath, config.NativeBootstrap{Server: ready.Control, DeviceID: "live-device", SecretEnv: "KAVERN_ADMIN_TEST_DEVICE", CAFile: cert})
	agentEnv := append(env, "KAVERN_ADMIN_TEST_DEVICE="+credential.Issuance.Credential)
	agent := observeCommand(t, bins["kavern-agent"], agentPath, agentEnv)
	agent.ready(t, "agent_ready")
	status := waitStatus(func(v config.AdminDeviceStatus) bool { return v.Ready && len(v.Listeners) == 1 })
	assertProcessEOF(t, status.Listeners[0].BoundAddress, "first:")
	// An explicitly stale CAS is not silently refreshed or overwritten.
	stale := c
	stale.Tunnels = append([]domain.Tunnel(nil), c.Tunnels...)
	stale.Tunnels[0].TargetAddr = target2.Addr().String()
	m := config.AdminMutation{Window: window(), OperationID: "stale-cas", Kind: "put_device", DeviceID: "live-device", ExpectedRevision: stale.Revision, Configuration: &stale}
	p := saveRequest(m)
	_, diag, e := execCLI("online", "--socket", socket, "put-device", "--file", p)
	if e == nil || !bytes.Contains(diag, []byte("revision_conflict")) {
		t.Fatal("stale CAS accepted")
	}

	// Change carrier policy with the real agent already ready and an application
	// stream confirmed at its target. The old session must retire and reconnect
	// with the new policy before status or a fresh route becomes ready.
	policyStream, e := net.DialTimeout("tcp", status.Listeners[0].BoundAddress, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer policyStream.Close()
	_ = policyStream.SetDeadline(time.Now().Add(6 * time.Second))
	if _, e = policyStream.Write([]byte("policy-stream")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-policyReceived:
	case <-time.After(time.Second):
		t.Fatal("policy stream not active at target")
	}
	c = get()
	c.Policy.Carriers = 2
	policySaved, _ := mutate("put-device", config.AdminMutation{Kind: "put_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Configuration: &c}, "")
	status = waitStatus(func(v config.AdminDeviceStatus) bool {
		return v.Ready && v.DesiredRevision == policySaved.Revision && v.Session.Carriers == 2
	})
	var policyByte [1]byte
	if _, e = policyStream.Read(policyByte[:]); e == nil {
		t.Fatal("old session stream survived policy retirement")
	}
	assertProcessEOF(t, status.Listeners[0].BoundAddress, "first:")
	c = get()
	c.Tunnels[0].TargetAddr = target2.Addr().String()
	mutate("put-device", config.AdminMutation{Kind: "put_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Configuration: &c}, "")
	status = waitStatus(func(v config.AdminDeviceStatus) bool { return v.Ready && v.DesiredRevision == c.Revision+1 })
	assertProcessEOF(t, status.Listeners[0].BoundAddress, "second:")
	// Desired save survives a real bind failure and later retries without a rewrite.
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c = get()
	c.Tunnels[0].Listener = domain.ListenerRef(occupied.Addr().String())
	saved, _ := mutate("put-device", config.AdminMutation{Kind: "put_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Configuration: &c}, "")
	failed := waitStatus(func(v config.AdminDeviceStatus) bool {
		return len(v.Listeners) == 1 && v.Listeners[0].State == "bind_failed"
	})
	if failed.Ready || failed.DesiredRevision != saved.Revision {
		t.Fatal("bind failure save/readiness conflated")
	}
	occupied.Close()
	status = waitStatus(func(v config.AdminDeviceStatus) bool { return v.Ready })
	assertProcessEOF(t, status.Listeners[0].BoundAddress, "second:")
	c = get()
	c.Device.Enabled = false
	mutate("put-device", config.AdminMutation{Kind: "put_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Configuration: &c}, "")
	waitStatus(func(v config.AdminDeviceStatus) bool { return !v.Device.Enabled && !v.Session.Present && !v.Ready })
	c = get()
	c.Device.Enabled = true
	mutate("put-device", config.AdminMutation{Kind: "put_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Configuration: &c}, "")
	status = waitStatus(func(v config.AdminDeviceStatus) bool { return v.Ready })
	assertProcessEOF(t, status.Listeners[0].BoundAddress, "second:")
	// Explicit disconnect/reconnect resynchronizes the same durable configuration.
	agent.stop(t)
	waitStatus(func(v config.AdminDeviceStatus) bool { return !v.Session.Present })
	agent = observeCommand(t, bins["kavern-agent"], agentPath, agentEnv)
	agent.ready(t, "agent_ready")
	status = waitStatus(func(v config.AdminDeviceStatus) bool { return v.Ready })
	active, e := net.DialTimeout("tcp", status.Listeners[0].BoundAddress, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	active.SetDeadline(time.Now().Add(3 * time.Second))
	active.Write([]byte("rotation-stream"))
	select {
	case <-rotationReceived:
	case <-time.After(time.Second):
		t.Fatal("active target did not receive marker before rotation")
	}
	c = get()
	rotatedFile := filepath.Join(runtimeDir, "rotated-credential.json")
	rotation, rotationRequest := mutate("rotate-device", config.AdminMutation{Kind: "rotate_credential", DeviceID: "live-device", ExpectedRevision: c.Revision, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}, rotatedFile)
	waitStatus(func(v config.AdminDeviceStatus) bool {
		return !v.Session.Present && !v.Ready && v.DesiredRevision == rotation.Revision
	})
	var b [1]byte
	if _, e = active.Read(b[:]); e == nil {
		t.Fatal("rotated stream retained")
	}
	if r := ctl("retry", "--file", rotationRequest); bytes.Contains(r, []byte(`"issuance"`)) {
		t.Fatal("retry response contained credential")
	}
	rotatedData, e := os.ReadFile(rotatedFile)
	if e != nil || json.Unmarshal(rotatedData, &credential) != nil {
		t.Fatal("rotated issuance missing")
	}
	agent.stop(t)
	agentEnv = append(env, "KAVERN_ADMIN_TEST_DEVICE="+credential.Issuance.Credential)
	agent = observeCommand(t, bins["kavern-agent"], agentPath, agentEnv)
	agent.ready(t, "agent_ready")
	status = waitStatus(func(v config.AdminDeviceStatus) bool { return v.Ready })
	assertProcessEOF(t, status.Listeners[0].BoundAddress, "second:")
	// Device delete requires an explicit cascade and joins the running native session.
	c = get()
	mutate("delete-device", config.AdminMutation{Kind: "delete_device", DeviceID: "live-device", ExpectedRevision: c.Revision, Cascade: true}, "")
	_, diag, e = execCLI("online", "--socket", socket, "get-device", "--id", "live-device")
	if e == nil || !bytes.Contains(diag, []byte("not_found")) {
		t.Fatal("device not deleted")
	}
	agent.stop(t)
	// Slow headers and idle connections must not delay joined shutdown/socket removal.
	slow, e := config.DialAdmin(context.Background(), socket)
	if e != nil {
		t.Fatal(e)
	}
	defer slow.Close()
	slow.Write([]byte("GET /admin/v1/status HTTP/1.1\r\n"))
	daemon.stop(t)
	if _, e = os.Lstat(socket); !os.IsNotExist(e) {
		t.Fatal("socket retained after shutdown")
	}
	unlock, e := store.LockState(state)
	if e != nil {
		t.Fatal("state lock retained", e)
	}
	unlock()
	daemon = observeCommand(t, bins["kavernd"], serverPath, env)
	daemon.ready(t, "server_ready")
	var health config.AdminHealth
	if e = json.Unmarshal(ctl("status"), &health); e != nil || health.Health != "running" {
		t.Fatal("restart unavailable")
	}
	daemon.stop(t)
	// Never report synthetic secret values, even on a failing assertion.
	if bytes.Contains(daemon.stderr.Bytes(), []byte(credential.Issuance.Credential)) {
		t.Fatal("daemon leaked secret")
	}
	if strings.Contains(string(ctlOptionalFailure(t, execCLI, socket)), credential.Issuance.Credential) {
		t.Fatal("diagnostic secret")
	}
}
func ctlOptionalFailure(t *testing.T, run func(...string) ([]byte, []byte, error), socket string) []byte {
	t.Helper()
	_, diag, e := run("online", "--socket", socket, "status")
	if e == nil {
		t.Fatal("stopped endpoint remained usable")
	}
	return diag
}

func adminProcessEcho(t *testing.T, prefix string, progress func([]byte)) net.Listener {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	joined := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(joined)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				var reader io.Reader = conn
				if progress != nil {
					reader = &receiptReader{Reader: conn, progress: progress}
				}
				payload, e := io.ReadAll(reader)
				if e == nil {
					_, _ = conn.Write(append([]byte(prefix), payload...))
				}
			}()
		}
	}()
	t.Cleanup(func() { cancel(); listener.Close(); <-joined; workers.Wait() })
	return listener
}
