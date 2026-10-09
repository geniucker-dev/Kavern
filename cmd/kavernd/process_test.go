package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
)

func TestActualCommandsNativeTLSHalfCloseAndRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("actual process assembly disabled by -short")
	}
	dir := t.TempDir()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	bins := map[string]string{}
	for _, name := range []string{"kavernd", "kavern-agent", "kavernctl"} {
		path := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-buildvcs=false", "-race", "-o", path, "./cmd/"+name)
		cmd.Dir = repo
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, output)
		}
		bins[name] = path
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "KAVERN_TEST_MASTER="+base64.RawURLEncoding.EncodeToString(master))
	statePath := filepath.Join(dir, "state", "state.json")
	ctl := func(extraEnv []string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(bins["kavernctl"], args...)
		cmd.Env = append(env, extraEnv...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("CLI %s: %v %s", args[0], err, stderr.String())
		}
		return output
	}
	common := []string{"-state", statePath, "-master-key-env", "KAVERN_TEST_MASTER"}
	ctl(nil, append([]string{"init-state", "-user", "user", "-project", "project"}, common...)...)
	output := ctl(nil, append([]string{"add-device", "-id", "device", "-project", "project"}, common...)...)
	var credential struct {
		DeviceID string `json:"device_id"`
		Secret   string `json:"device_secret"`
	}
	if err := json.Unmarshal(output, &credential); err != nil || credential.Secret == "" {
		t.Fatal("CLI credential response invalid")
	}
	env = append(env, "KAVERN_TEST_DEVICE="+credential.Secret)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetDone := make(chan struct{})
	var targets sync.WaitGroup
	go func() {
		defer close(targetDone)
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			targets.Add(1)
			go func() {
				defer targets.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				data, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				_, _ = conn.Write(append([]byte("eof:"), data...))
			}()
		}
	}()
	defer func() { target.Close(); <-targetDone; targets.Wait() }()
	ctl(nil, append([]string{"add-tunnel", "-id", "tunnel", "-device", "device", "-listen", "127.0.0.1:0", "-target", target.Addr().String()}, common...)...)
	cert, key := testCertificate(t, dir)
	serverCfg := config.Server{ControlListen: "127.0.0.1:0", CertFile: cert, KeyFile: key, StateFile: statePath, MasterKeyEnv: "KAVERN_TEST_MASTER"}
	serverPath := filepath.Join(dir, "server.json")
	writeJSON(t, serverPath, serverCfg)
	ctl(nil, "validate", "-kind", "server", "-config", serverPath)
	for attempt := range 2 {
		server, ready, stopServer := startTestProcess(t, bins["kavernd"], serverPath, env, dir)
		var endpoints struct {
			Control string            `json:"control"`
			Public  map[string]string `json:"public"`
		}
		if err := json.Unmarshal(ready, &endpoints); err != nil || endpoints.Control == "" || endpoints.Public["tunnel"] == "" {
			stopServer()
			t.Fatal("invalid daemon ready message")
		}
		_ = server
		// The daemon owns the state lock; offline mutation cannot race it.
		blocked := exec.Command(bins["kavernctl"], append([]string{"rotate-device", "-id", "device"}, common...)...)
		blocked.Env = env
		if err := blocked.Run(); err == nil {
			stopServer()
			t.Fatal("state mutated while server was running")
		}
		agentCfg := config.Agent{Server: endpoints.Control, DeviceID: "device", SecretEnv: "KAVERN_TEST_DEVICE", CAFile: cert, Targets: map[string]string{"tunnel": target.Addr().String()}, Carriers: 2}
		agentPath := filepath.Join(dir, "agent.json")
		writeJSON(t, agentPath, agentCfg)
		ctl(nil, "validate", "-kind", "agent", "-config", agentPath)
		_, _, stopAgent := startTestProcess(t, bins["kavern-agent"], agentPath, env, dir)
		payload := bytes.Repeat([]byte{byte(attempt + 1), 0, 255, 7}, 65536)
		conn, err := net.DialTimeout("tcp", endpoints.Public["tunnel"], time.Second)
		if err != nil {
			stopAgent()
			stopServer()
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write(payload); err != nil {
			conn.Close()
			stopAgent()
			stopServer()
			t.Fatal(err)
		}
		if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(conn)
		conn.Close()
		stopAgent()
		stopServer()
		if err != nil || !bytes.Equal(response, append([]byte("eof:"), payload...)) {
			t.Fatalf("actual TLS native half-close attempt %d: bytes=%d err=%v", attempt, len(response), err)
		}
	}
	logs, err := filepath.Glob(filepath.Join(dir, "process-stderr-*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range logs {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(credential.Secret)) || bytes.Contains(data, []byte(base64.RawURLEncoding.EncodeToString(master))) {
			t.Fatal("credential leaked in actual process diagnostics")
		}
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(credential.Secret)) {
		t.Fatal("device secret leaked to state")
	}
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func testCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Kavern isolated test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
func startTestProcess(t *testing.T, binary, cfg string, env []string, dir string) (*exec.Cmd, []byte, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "-config", cfg)
	cmd.Env = env
	cmd.Dir = dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.CreateTemp(dir, "process-stderr-*")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = stderr
	if err = cmd.Start(); err != nil {
		stderr.Close()
		t.Fatal(err)
	}
	lines := make(chan []byte, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case lines <- append([]byte(nil), scanner.Bytes()...):
			default:
			}
		}
	}()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case err := <-waited:
				if err != nil {
					t.Errorf("process exited: %v", err)
				}
			case <-time.After(3 * time.Second):
				cancel()
				<-waited
				t.Error("process did not shut down gracefully")
			}
			cancel()
			<-scanDone
			stderr.Close()
			log, _ := os.ReadFile(stderr.Name())
			if len(log) > 0 {
				t.Errorf("process stderr: %s", log)
			}
		})
	}
	t.Cleanup(stop)
	select {
	case line := <-lines:
		return cmd, line, stop
	case <-time.After(10 * time.Second):
		cancel()
		stop()
		t.Fatal("process readiness timeout")
	}
	return nil, nil, stop
}
