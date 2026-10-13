//go:build linux && ui_browser_acceptance

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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestActualBrowserDaemonAgentConfigurationFlow(t *testing.T) {
	browser := os.Getenv("UI_BROWSER_BIN")
	if browser == "" {
		t.Fatal("ui_browser_acceptance requires installed UI_BROWSER_BIN and node")
	}
	artifacts := os.Getenv("UI_BROWSER_ARTIFACT_DIR")
	if artifacts == "" {
		artifacts = t.TempDir()
	}
	if e := os.MkdirAll(artifacts, 0700); e != nil {
		t.Fatal(e)
	}
	bins := buildNativeCommands(t)
	dir := t.TempDir()
	private := filepath.Join(dir, "r")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(private, "a.sock")
	state := filepath.Join(dir, "state", "state.json")
	env := append(os.Environ(), "KAVERN_W2_MASTER="+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)))
	init := exec.Command(bins["kavernctl"], "init-state", "-state", state, "-master-key-env", "KAVERN_W2_MASTER", "-user", "owner", "-project", "studio")
	init.Env = env
	if b, e := init.CombinedOutput(); e != nil {
		t.Fatalf("init fixture: %v %s", e, b)
	}
	cert, key := testCertificate(t, dir)
	serverPath := filepath.Join(dir, "server.json")
	cfg := config.NativeServer{AdminSocket: socket, ControlListen: "127.0.0.1:0", CertFile: cert, KeyFile: key, StateFile: state, MasterKeyEnv: "KAVERN_W2_MASTER"}
	writeJSON(t, serverPath, cfg)
	daemon := observeCommand(t, bins["kavernd"], serverPath, env)
	ready := daemon.ready(t, "server_ready")
	cfg.ControlListen = ready.Control
	writeJSON(t, serverPath, cfg)
	client := config.NewAdminClient(socket, 1)
	defer client.Close()
	target1 := processEchoTarget(t, "first:")
	target2 := processEchoTarget(t, "second:")
	freeListener := func() string {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := l.Addr().String()
		l.Close()
		return address
	}
	listener1, listener2 := freeListener(), freeListener()
	var hidden []domain.Tunnel
	var preservedPolicy domain.NativePolicy
	var mu sync.Mutex
	startBridge := func() string {
		t.Helper()
		p := &observedCommand{events: make(chan commandEvent, 1), scanDone: make(chan struct{}), exit: make(chan struct{}), stderr: &bytes.Buffer{}}
		p.cmd = exec.Command(bins["kavernctl"], "ui", "--socket", socket, "--credential-dir", private)
		p.cmd.Env = env
		p.cmd.Stderr = p.stderr
		stdout, e := p.cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = p.cmd.Start(); e != nil {
			t.Fatal(e)
		}
		line := make(chan string, 1)
		go func() {
			defer close(p.scanDone)
			scan := bufio.NewScanner(stdout)
			if scan.Scan() {
				line <- scan.Text()
			}
			for scan.Scan() {
			}
		}()
		go func() { p.err = p.cmd.Wait(); close(p.exit) }()
		t.Cleanup(func() { p.stop(t) })
		select {
		case launch := <-line:
			return launch
		case <-time.After(8 * time.Second):
			t.Fatal("bridge launch did not complete")
			return ""
		}
	}
	launch := startBridge()
	started := map[string]bool{}
	secrets := []string{}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fail := func() { http.Error(w, "synthetic fixture action failed", 500) }
		switch r.URL.Path {
		case "/info":
			json.NewEncoder(w).Encode(map[string]string{"target1": target1.Addr().String(), "target2": target2.Addr().String(), "listener1": listener1, "listener2": listener2})
		case "/start-agents":
			entries, e := os.ReadDir(private)
			if e != nil {
				fail()
				return
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), "kavern-") {
					continue
				}
				var credential struct {
					DeviceID string               `json:"device_id"`
					Issuance config.AdminIssuance `json:"issuance"`
				}
				data, e := os.ReadFile(filepath.Join(private, entry.Name()))
				if e != nil || json.Unmarshal(data, &credential) != nil || credential.Issuance.Credential == "" {
					continue
				}
				if started[credential.DeviceID] {
					continue
				}
				started[credential.DeviceID] = true
				secrets = append(secrets, credential.Issuance.Credential)
				path := filepath.Join(dir, "agent-"+credential.DeviceID+".json")
				writeJSON(t, path, config.NativeBootstrap{Server: ready.Control, DeviceID: credential.DeviceID, SecretEnv: "KAVERN_W2_DEVICE", CAFile: cert})
				agent := observeCommand(t, bins["kavern-agent"], path, append(env, "KAVERN_W2_DEVICE="+credential.Issuance.Credential))
				agent.ready(t, "agent_ready")
			}
			json.NewEncoder(w).Encode(map[string]int{"started": len(started)})
		case "/probe":
			id := r.URL.Query().Get("device")
			prefix := r.URL.Query().Get("prefix")
			var status config.AdminDeviceStatus
			if client.Request(context.Background(), "GET", "/admin/v1/devices/"+id+"/status", nil, &status) != nil || !status.Ready {
				fail()
				return
			}
			address := ""
			for _, l := range status.Listeners {
				if string(l.TunnelID) == id+"-tcp" {
					address = l.BoundAddress
				}
			}
			c, e := net.DialTimeout("tcp", address, time.Second)
			if e != nil {
				fail()
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = c.Write([]byte("browser-receipt")); e != nil {
				fail()
				return
			}
			c.(*net.TCPConn).CloseWrite()
			b, e := io.ReadAll(c)
			if e != nil || string(b) != prefix+"browser-receipt" {
				fail()
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"target_confirmed": true})
		case "/hidden-tunnels":
			var c domain.DeviceConfiguration
			var window config.AdminWindow
			if client.Request(context.Background(), "GET", "/admin/v1/devices/alpha/configuration", nil, &c) != nil || client.Request(context.Background(), "GET", "/admin/v1/window", nil, &window) != nil {
				fail()
				return
			}
			preservedPolicy = c.Policy
			for i := 0; i < 51; i++ {
				tunnel := domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("hidden-%02d", i)), DeviceID: "alpha", Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("localhost:%d", 10000+i)), TargetAddr: target1.Addr().String(), Enabled: false}
				hidden = append(hidden, tunnel)
				c.Tunnels = append(c.Tunnels, tunnel)
			}
			m := config.AdminMutation{Window: window, OperationID: "fixture-hidden-tunnels", Kind: "put_device", DeviceID: "alpha", ExpectedRevision: c.Revision, Configuration: &c}
			data, _ := json.Marshal(m)
			var result config.AdminResult
			if client.Request(context.Background(), "PUT", "/admin/v1/devices/alpha/configuration", data, &result) != nil {
				fail()
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"saved": true})
		case "/preserved":
			var c domain.DeviceConfiguration
			if client.Request(context.Background(), "GET", "/admin/v1/devices/alpha/configuration", nil, &c) != nil {
				fail()
				return
			}
			same := c.Policy == preservedPolicy && len(c.Tunnels) == 52
			for _, old := range hidden {
				found := false
				for _, tunnel := range c.Tunnels {
					if tunnel.ID == old.ID {
						found = reflect.DeepEqual(tunnel, old)
					}
				}
				same = same && found
			}
			json.NewEncoder(w).Encode(map[string]bool{"preserved": same})
		case "/concurrent-edit":
			var c domain.DeviceConfiguration
			if client.Request(context.Background(), "GET", "/admin/v1/devices/alpha/configuration", nil, &c) != nil {
				fail()
				return
			}
			var window config.AdminWindow
			if client.Request(context.Background(), "GET", "/admin/v1/window", nil, &window) != nil {
				fail()
				return
			}
			c.Device.Name = "Concurrent authoritative name"
			m := config.AdminMutation{Window: window, OperationID: "fixture-concurrent-edit", Kind: "put_device", DeviceID: "alpha", ExpectedRevision: c.Revision, Configuration: &c}
			data, _ := json.Marshal(m)
			var result config.AdminResult
			if client.Request(context.Background(), "PUT", "/admin/v1/devices/alpha/configuration", data, &result) != nil {
				fail()
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"saved": true})
		case "/evict-receipts":
			var c domain.DeviceConfiguration
			if client.Request(context.Background(), "GET", "/admin/v1/devices/alpha/configuration", nil, &c) != nil {
				fail()
				return
			}
			for i := 0; i < store.MaxMutationReceipts; i++ {
				var window config.AdminWindow
				if client.Request(context.Background(), "GET", "/admin/v1/window", nil, &window) != nil {
					fail()
					return
				}
				m := config.AdminMutation{Window: window, OperationID: fmt.Sprintf("fixture-evict-%03d", i), Kind: "put_device", DeviceID: "alpha", ExpectedRevision: c.Revision, Configuration: &c}
				data, _ := json.Marshal(m)
				var result config.AdminResult
				if client.Request(context.Background(), "PUT", "/admin/v1/devices/alpha/configuration", data, &result) != nil {
					fail()
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]bool{"evicted": true})
		case "/restart":
			daemon.stop(t)
			daemon = observeCommand(t, bins["kavernd"], serverPath, env)
			ready = daemon.ready(t, "server_ready")
			json.NewEncoder(w).Encode(map[string]bool{"restarted": true})
		case "/new-bridge":
			json.NewEncoder(w).Encode(map[string]string{"launch": startBridge()})
		case "/redaction":
			// Inspect only test artifact bytes for known synthetic material. Never print it.
			found := false
			filepath.WalkDir(artifacts, func(path string, d os.DirEntry, e error) error {
				if e == nil && !d.IsDir() {
					b, _ := os.ReadFile(path)
					for _, secret := range secrets {
						if bytes.Contains(b, []byte(secret)) {
							found = true
						}
					}
				}
				return nil
			})
			json.NewEncoder(w).Encode(map[string]bool{"redacted": !found})
		default:
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()
	command := exec.Command("node", "testdata/ui_browser_mutations.mjs", browser, filepath.Join(t.TempDir(), "profile"), launch, artifacts, fixture.URL)
	data, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("W2 browser flow failed: %v %s", e, data)
	}
	t.Log(string(data))

}
