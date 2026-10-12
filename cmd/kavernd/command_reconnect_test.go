package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type commandEvent struct {
	Event    string            `json:"event"`
	Control  string            `json:"control"`
	Public   map[string]string `json:"public"`
	Revision string            `json:"revision"`
}
type observedCommand struct {
	events         chan commandEvent
	scanDone, exit chan struct{}
	cmd            *exec.Cmd
	stderr         *bytes.Buffer
	err            error
	once           sync.Once
}

func observeCommand(t *testing.T, binary, path string, env []string) *observedCommand {
	t.Helper()
	p := &observedCommand{events: make(chan commandEvent, 8), scanDone: make(chan struct{}), exit: make(chan struct{}), stderr: &bytes.Buffer{}}
	p.cmd = exec.Command(binary, "-config", path)
	p.cmd.Env = env
	p.cmd.Stderr = p.stderr
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.scanDone)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), config.MaxJSONBytes)
		for scanner.Scan() {
			var event commandEvent
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				select {
				case p.events <- event:
				default:
				}
			}
		}
	}()
	go func() { p.err = p.cmd.Wait(); close(p.exit) }()
	t.Cleanup(func() { p.stop(t) })
	return p
}
func (p *observedCommand) stop(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case <-p.exit:
		case <-time.After(4 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exit
			t.Error("owned command did not join gracefully")
		}
		<-p.scanDone
		if p.err != nil {
			t.Errorf("owned command exit: %v", p.err)
		}
		if p.stderr.Len() != 0 {
			t.Error("unexpected owned command diagnostic")
		}
	})
}
func (p *observedCommand) ready(t *testing.T, kind string) commandEvent {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-p.events:
			if event.Event == kind {
				return event
			}
		case <-p.exit:
			t.Fatal("owned command exited before readiness")
		case <-timer.C:
			t.Fatal("owned command readiness timed out")
		}
	}
}
func buildNativeCommands(t *testing.T) map[string]string {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	bins := map[string]string{}
	for _, name := range []string{"kavernd", "kavern-agent", "kavernctl"} {
		path := filepath.Join(t.TempDir(), name)
		cmd := exec.Command("go", "build", "-buildvcs=false", "-race", "-o", path, "./cmd/"+name)
		cmd.Dir = repo
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("owned command build: %v %s", err, output)
		}
		bins[name] = path
	}
	return bins
}
func processEchoTarget(t *testing.T, prefix string) net.Listener {
	return processObservedEchoTarget(t, prefix, nil)
}
func processObservedEchoTarget(t *testing.T, prefix string, observe func([]byte), progress ...func([]byte)) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var reader io.Reader = c
				if len(progress) > 0 {
					reader = &receiptReader{Reader: io.LimitReader(c, config.MaxJSONBytes), progress: progress[0]}
				}
				payload, err := io.ReadAll(reader)
				if observe != nil {
					observe(payload)
				}
				if err == nil {
					_, _ = c.Write(append([]byte(prefix), payload...))
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	return listener
}
func assertProcessEOF(t *testing.T, address, prefix string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{1, 0, 255, 7}, 16384)
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(response, append([]byte(prefix), payload...)) {
		t.Fatal("fresh synchronized EOF response mismatch", err)
	}
}
func TestActualCommandsAgentSurvivesRestartFullResyncRotationAndDisable(t *testing.T) {
	if testing.Short() {
		t.Skip("actual command test disabled by -short")
	}
	bins := buildNativeCommands(t)
	dir := t.TempDir()
	master := bytes.Repeat([]byte{0x31}, 32)
	secret := bytes.Repeat([]byte{0x32}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(secret)
	env := append(os.Environ(), "KAVERN_RECONNECT_MASTER="+base64.RawURLEncoding.EncodeToString(master), "KAVERN_RECONNECT_DEVICE="+encoded)
	state := store.NewMemoryStore()
	ctx := context.Background()
	_ = state.CreateUser(ctx, domain.User{ID: "u"})
	_ = state.CreateProject(ctx, domain.Project{ID: "p", UserID: "u"})
	_ = state.CreateDevice(ctx, domain.Device{ID: "d", ProjectID: "p", Enabled: true})
	_ = state.SetKAPv1DeviceSecret(ctx, "d", secret)
	first, second := processEchoTarget(t, "first:"), processEchoTarget(t, "second:")
	_ = state.CreateTunnel(ctx, domain.Tunnel{ID: "t", DeviceID: "d", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:0", TargetAddr: first.Addr().String(), Enabled: true})
	statePath := filepath.Join(dir, "private", "state.json")
	if err := state.SaveState(statePath, master); err != nil {
		t.Fatal(err)
	}
	cert, key := testCertificate(t, dir)
	serverCfg := config.NativeServer{ControlListen: "127.0.0.1:0", StateFile: statePath, CertFile: cert, KeyFile: key, MasterKeyEnv: "KAVERN_RECONNECT_MASTER"}
	serverPath := filepath.Join(dir, "server.json")
	writeJSON(t, serverPath, serverCfg)
	server := observeCommand(t, bins["kavernd"], serverPath, env)
	initial := server.ready(t, "server_ready")
	agentPath := filepath.Join(dir, "agent.json")
	writeJSON(t, agentPath, config.NativeBootstrap{Server: initial.Control, DeviceID: "d", SecretEnv: "KAVERN_RECONNECT_DEVICE", CAFile: cert})
	agent := observeCommand(t, bins["kavern-agent"], agentPath, env)
	_ = agent.ready(t, "agent_ready")
	assertProcessEOF(t, initial.Public["t"], "first:")
	rejectOldNativePeer(t, initial.Control, cert, "d")
	assertProcessEOF(t, initial.Public["t"], "first:")
	server.stop(t)
	// Stopped-daemon fixture mutation uses the reviewed owner; credential
	// rotation/disable use the existing offline CLI. No live admin backdoor.
	ctl := func(args ...string) []byte {
		t.Helper()
		args = append(args, "-state", statePath, "-master-key-env", "KAVERN_RECONNECT_MASTER")
		cmd := exec.Command(bins["kavernctl"], args...)
		cmd.Env = env
		output, err := cmd.Output()
		if err != nil {
			t.Fatal("offline fixture administration failed", err)
		}
		return output
	}
	owner, err := store.OpenConfigOwner(statePath, master, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal("stopped daemon retained state lock", err)
	}
	desired, err := owner.DeviceConfiguration(ctx, "d")
	if err != nil {
		t.Fatal(err)
	}
	desired.Tunnels[0].TargetAddr = second.Addr().String()
	if _, err = owner.Commit(ctx, []domain.DeviceConfiguration{desired}); err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	serverCfg.ControlListen = initial.Control
	writeJSON(t, serverPath, serverCfg)
	server = observeCommand(t, bins["kavernd"], serverPath, env)
	restarted := server.ready(t, "server_ready")
	if event := agent.ready(t, "agent_ready"); event.Revision != "2" {
		t.Fatal("reconnect did not fully synchronize latest revision")
	}
	assertProcessEOF(t, restarted.Public["t"], "second:")
	server.stop(t)
	var rotated struct {
		Secret string `json:"device_secret"`
	}
	if json.Unmarshal(ctl("rotate-device", "-id", "d"), &rotated) != nil || rotated.Secret == "" {
		t.Fatal("fixture rotation invalid")
	}
	server = observeCommand(t, bins["kavernd"], serverPath, env)
	rotatedServer := server.ready(t, "server_ready")
	// A route after rotation has no authenticated session with the old secret.
	conn, err := net.DialTimeout("tcp", rotatedServer.Public["t"], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = conn.Read(b[:]); err == nil {
		t.Fatal("old credential routed after rotation")
	}
	_ = conn.Close()
	agent.stop(t)
	env = append(env, "KAVERN_RECONNECT_DEVICE="+rotated.Secret)
	agent = observeCommand(t, bins["kavern-agent"], agentPath, env)
	_ = agent.ready(t, "agent_ready")
	assertProcessEOF(t, rotatedServer.Public["t"], "second:")
	agent.stop(t)
	server.stop(t)
	ctl("set-device-enabled", "-id", "d", "-enabled=false")
	server = observeCommand(t, bins["kavernd"], serverPath, env)
	disabled := server.ready(t, "server_ready")
	if len(disabled.Public) != 0 {
		t.Fatal("disabled device had public listener")
	}
	server.stop(t)
	lock, err := store.LockState(statePath)
	if err != nil {
		t.Fatal("command state lock not released", err)
	}
	_ = lock()
	for _, p := range []*observedCommand{agent, server} {
		if bytes.Contains(p.stderr.Bytes(), []byte(encoded)) || bytes.Contains(p.stderr.Bytes(), []byte(rotated.Secret)) {
			t.Fatal("credential in command diagnostics")
		}
	}
}

// A fixture-only reader reports cumulative bytes received before request EOF.
type receiptReader struct {
	io.Reader
	received []byte
	progress func([]byte)
}

func (r *receiptReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	if n > 0 {
		r.received = append(r.received, data[:n]...)
		r.progress(r.received)
	}
	return n, err
}
