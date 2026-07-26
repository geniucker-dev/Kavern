//go:build legacy_npc_integration && legacy_npc_observe

package legacy_npc

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/geniucker-dev/kavern/internal/domain"
	gateway "github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

const (
	observeFrameLimit  = 4 * 1024
	observeTotalLimit  = 64 * 1024
	observeOutputLimit = 8 * 1024
)

var (
	hex32Pattern       = regexp.MustCompile(`[0-9a-fA-F]{32}`)
	sessionBodyPattern = regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{8,9}Z`)
	loopbackPattern    = regexp.MustCompile(`127\.0\.0\.1(?::[0-9]{1,5})?`)
	portPattern        = regexp.MustCompile(`(?i)(port["'=:\s]+)[0-9]{1,5}`)
	hostPortPattern    = regexp.MustCompile(`(?i)((?:host|addr|target|server|ip)["'=:\s]+)<loopback>(?::[0-9]{1,5})?`)
	jsonScalarMaxLen   = 80
)

func TestObserveKavernIdleMode(t *testing.T) {
	npcBin := requireNPCBin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	st, manager, vkey := newObserveStore(t, ctx)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	recorder := newObserveRecorder(t, "kavern_idle", vkey, []byte("server-secret"))
	observed := &observeListener{Listener: listener, recorder: recorder}
	gw, err := gateway.New(gateway.Config{ServerSecret: []byte("server-secret"), Store: st, Sessions: manager})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- gw.Serve(serveCtx, observed)
	}()

	cmdCtx, stopNPC := context.WithCancel(ctx)
	defer stopNPC()
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+listener.Addr().String(), "-vkey="+vkey)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	recorder.note("npc_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(npcBin), cmd.Process != nil))
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	current := waitCurrent(t, ctx, manager, "device-1")
	if current.Protocol() != domain.AgentProtocolLegacyNPC {
		t.Fatalf("current protocol = %q, want legacy_npc", current.Protocol())
	}
	recorder.note("online", fmt.Sprintf("protocol=%s session_id_present=%t", current.Protocol(), current.ID() != ""))

	time.Sleep(750 * time.Millisecond)
	stopNPC()
	select {
	case err := <-waitDone:
		recorder.note("npc_exit", fmt.Sprintf("status=%s", sanitizeProcessStatus(err)))
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timeout waiting for stock npc process exit")
	}
	waitNoCurrent(t, ctx, manager, "device-1")
	recorder.note("offline", "SessionManager.CurrentForDevice returned no current session")

	stopServe()
	_ = listener.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("gateway Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for gateway Serve() exit")
	}

	recorder.readiness("Insufficient for Gate 6B: Mode A can observe main/chan idle behavior only; it cannot prove logical stream open, data frame shape, target metadata, close/reset semantics, or heartbeat/ping behavior during data forwarding.")
}

func TestObserveStockNPSOracleMode(t *testing.T) {
	npcBin := requireNPCBin(t)
	npsBin := os.Getenv("NPS_BIN")
	if npsBin == "" {
		t.Skip("NPS_BIN is required for stock_nps_oracle mode; skipping because Mode A alone cannot support Gate 6B readiness")
	}
	requireExecutable(t, npsBin, "NPS_BIN")
	vkey := observeRandomVKey(t)
	secrets := newObserveSecrets(t)
	recorder := newObserveRecorder(t, "stock_nps_oracle", vkey, []byte("server-secret"), secrets.authKey, secrets.webPassword)
	npcSHA := sha256File(t, npcBin)
	npsSHA := sha256File(t, npsBin)
	recorder.setFixtureMetadata(npcSHA, npsSHA)
	recorder.note("npc_bin", fmt.Sprintf("basename=%s sha256=%s", filepath.Base(npcBin), formatSHA256ForLog(npcSHA)))
	recorder.note("nps_bin", fmt.Sprintf("basename=%s sha256=%s", filepath.Base(npsBin), formatSHA256ForLog(npsSHA)))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := observeRoot(t)
	topology := newOracleTopology(t, ctx, recorder)
	defer topology.Close()

	runtime := prepareStockNPSRuntime(t, root, topology, secrets, recorder)
	npsCtx, stopNPS := context.WithCancel(ctx)
	defer stopNPS()
	npsCmd := exec.CommandContext(npsCtx, runtime.npsPath)
	npsCmd.Dir = runtime.dir
	npsStdout := newBoundedBuffer(observeOutputLimit)
	npsStderr := newBoundedBuffer(observeOutputLimit)
	npsCmd.Stdout = npsStdout
	npsCmd.Stderr = npsStderr
	if err := npsCmd.Start(); err != nil {
		t.Fatalf("start stock nps basename=%s: %v", filepath.Base(npsBin), err)
	}
	recorder.note("nps_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(runtime.npsPath), npsCmd.Process != nil))
	npsMonitor := newProcessMonitor(npsCmd)
	defer func() {
		recorder.outputSummary("nps_stdout_summary", npsStdout.String())
		recorder.outputSummary("nps_stderr_summary", npsStderr.String())
		recorder.fileTailSummary("nps_log_summary", runtime.logPath, observeOutputLimit)
	}()
	defer func() {
		stopNPS()
		waitObservedProcess(t, "nps", npsCmd, npsMonitor, recorder)
	}()

	api := newStockNPSAPI(runtime.webAddr, secrets.authKey)
	if err := api.waitReady(ctx); err != nil {
		recorder.readiness("Out of scope: stock nps did not expose the documented Web API gettime endpoint from loopback temp runtime.")
		t.Fatalf("wait for stock nps Web API: %v", err)
	}
	clientID, err := api.addClient(ctx, vkey)
	recorder.apiSummary("nps_client_add_response", api.lastResponseShape())
	if err != nil {
		recorder.readiness("Out of scope: stock nps Web API client setup failed; sanitized error indicates docs/runtime mismatch.")
		t.Fatalf("stock nps client setup failed: %v", sanitizeErr(err, secrets.redactValues()...))
	}
	recorder.note("nps_client_added", fmt.Sprintf("id_present=%t", clientID != ""))
	if err := api.addTCPTunnel(ctx, clientID, runtime.publicPort, topology.targetProxyAddr()); err != nil {
		recorder.apiSummary("nps_tunnel_add_response", api.lastResponseShape())
		recorder.readiness("Out of scope: stock nps Web API tunnel setup failed; sanitized error indicates docs/runtime mismatch.")
		t.Fatalf("stock nps tcp tunnel setup failed: %v", sanitizeErr(err, secrets.redactValues()...))
	}
	recorder.apiSummary("nps_tunnel_add_response", api.lastResponseShape())
	recorder.note("nps_tunnel_added", "type=tcp public=loopback target=target_proxy")
	recorder.note("nps_client_online", "client_online=unknown notes=no_documented_oracle_endpoint_used")

	npcCtx, stopNPC := context.WithCancel(ctx)
	defer stopNPC()
	npcCmd := exec.CommandContext(npcCtx, npcBin, "-server="+topology.npcServerAddr(), "-vkey="+vkey)
	npcStdout := newBoundedBuffer(observeOutputLimit)
	npcStderr := newBoundedBuffer(observeOutputLimit)
	npcCmd.Stdout = npcStdout
	npcCmd.Stderr = npcStderr
	if err := npcCmd.Start(); err != nil {
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	recorder.note("npc_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(npcBin), npcCmd.Process != nil))
	npcMonitor := newProcessMonitor(npcCmd)
	defer func() {
		recorder.outputSummary("npc_stdout_summary", npcStdout.String())
		recorder.outputSummary("npc_stderr_summary", npcStderr.String())
	}()
	defer func() {
		stopNPC()
		waitObservedProcess(t, "npc", npcCmd, npcMonitor, recorder)
	}()

	bridgeSeen, npcExitStatus := waitBridgeOrNPCExit(ctx, topology.legacyProxy, npcMonitor, 8*time.Second)
	recorder.note("bridge_proxy_connection", fmt.Sprintf("bridge_proxy_connection_seen=%t count=%d timeout=%t", bridgeSeen, topology.legacyProxy.Count(), !bridgeSeen && npcExitStatus == ""))
	if npcExitStatus != "" {
		recorder.note("npc_early_exit", fmt.Sprintf("status=%s", npcExitStatus))
		recorder.outputSummary("npc_stdout_summary", npcStdout.String())
		recorder.outputSummary("npc_stderr_summary", npcStderr.String())
		recorder.legacyReadiness(topology.legacyProxy.Readiness())
		recorder.readiness("Insufficient for Gate 6B: stock npc exited before a bridge proxy connection was observed.")
		t.Fatalf("stock_nps_oracle bridge wait failed: npc exited before bridge proxy connection")
	}
	if !bridgeSeen {
		recorder.legacyReadiness(topology.legacyProxy.Readiness())
		recorder.readiness("Insufficient for Gate 6B: npc did not connect to bridge proxy before bounded timeout; public payload was not sent.")
		t.Fatalf("stock_nps_oracle bridge wait failed: no bridge proxy connection observed")
	}
	if !waitLegacyReady(ctx, topology.legacyProxy, npcMonitor, "main", 8*time.Second) {
		recorder.legacyReadiness(topology.legacyProxy.Readiness())
		if npcMonitor.Exited() {
			recorder.note("npc_early_exit", fmt.Sprintf("status=%s", npcMonitor.Status()))
		}
		recorder.readiness("Insufficient for Gate 6B: main_not_ready before bounded timeout; public payload was not sent.")
		t.Fatalf("stock_nps_oracle readiness wait failed: main_not_ready")
	}
	recorder.legacyReadiness(topology.legacyProxy.Readiness())
	if !waitLegacyReady(ctx, topology.legacyProxy, npcMonitor, "chan", 8*time.Second) {
		recorder.legacyReadiness(topology.legacyProxy.Readiness())
		if npcMonitor.Exited() {
			recorder.note("npc_early_exit", fmt.Sprintf("status=%s", npcMonitor.Status()))
		}
		recorder.readiness("Insufficient for Gate 6B: chan_not_ready before bounded timeout; public payload was not sent.")
		t.Fatalf("stock_nps_oracle readiness wait failed: chan_not_ready")
	}
	recorder.legacyReadiness(topology.legacyProxy.Readiness())
	if npcMonitor.Exited() {
		recorder.note("npc_early_exit", fmt.Sprintf("status=%s", npcMonitor.Status()))
		recorder.readiness("Insufficient for Gate 6B: stock npc exited after bridge connection observation but before public payload; public payload was not sent.")
		t.Fatalf("stock_nps_oracle timing guard failed: npc exited before public payload")
	}
	recorder.note("public_payload_gate", "sent=true reason=main_ready_and_chan_ready")
	echoSuccess, err := observeOracleProbes(ctx, topology.publicClientAddr(), recorder)
	if err != nil {
		waitObserveGrace(ctx, 1500*time.Millisecond)
		recorder.legacyReadiness(topology.legacyProxy.Readiness())
		recorder.note("target_tcp_observed", fmt.Sprintf("seen=%t count=%d", topology.targetProxy.Count() > 0, topology.targetProxy.Count()))
		recorder.note("chan_frame_capture", fmt.Sprintf("chan_frame_capture_missing=%t", !topology.legacyProxy.Readiness().ChanPostHandshakeSeen))
		recorder.readiness("Insufficient for Gate 6B: stock_nps_oracle did not complete one local TCP echo through stock nps/npc; use sanitized transcript to identify the missing black-box setup or protocol state.")
		t.Fatalf("stock_nps_oracle echo failed: %v", err)
	}
	recorder.note("echo_result", fmt.Sprintf("echo_success=%t", echoSuccess))
	legacyReadiness := topology.legacyProxy.Readiness()
	recorder.legacyReadiness(legacyReadiness)
	recorder.sessionControlEvidence(legacyReadiness.SessionControl)
	recorder.note("target_tcp_observed", fmt.Sprintf("seen=%t count=%d", topology.targetProxy.Count() > 0, topology.targetProxy.Count()))
	if !legacyReadiness.ChanPostHandshakeSeen {
		recorder.note("chan_frame_capture", "chan_frame_capture_missing=true")
		recorder.readiness("insufficient for Gate 6B")
		t.Fatalf("stock_nps_oracle transcript missing post-handshake chan frame summaries")
	}
	recorder.note("chan_frame_capture", "chan_frame_capture_missing=false")
	readiness := fixtureReadiness(legacyReadiness, topology.targetProxy.Count() > 0, echoSuccess)
	recorder.readiness(readiness)
	recorder.writeFixtureIfRequested(t, legacyReadiness, topology.targetProxy.Count() > 0, echoSuccess)
}

func newObserveStore(t *testing.T, ctx context.Context) (*store.MemoryStore, session.SessionManager, string) {
	t.Helper()
	st := store.NewMemoryStore()
	if err := st.CreateUser(ctx, domain.User{ID: "user-1", Name: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProject(ctx, domain.Project{ID: "project-1", UserID: "user-1", Name: "project"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Name: "device", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	issued, err := st.IssueLegacyCredential(ctx, "device-1", []byte("server-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return st, session.NewManager(), issued.VKey
}

func observeRandomVKey(t *testing.T) string {
	t.Helper()
	return observeRandomSecret(t)
}

type observeSecrets struct {
	authKey     string
	webPassword string
}

func newObserveSecrets(t *testing.T) observeSecrets {
	t.Helper()
	return observeSecrets{
		authKey:     observeRandomSecret(t),
		webPassword: observeRandomSecret(t),
	}
}

func (s observeSecrets) redactValues() []string {
	return []string{s.authKey, s.webPassword}
}

func observeRandomSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func observeRoot(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("NPS_OBSERVE_DIR"); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			t.Fatalf("NPS_OBSERVE_DIR basename=%s cannot be made absolute: %v", filepath.Base(dir), err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		repoRoot, err := findKavernRepoRoot(cwd)
		if err != nil {
			t.Fatalf("find Kavern repository root from cwd basename=%s: %v", filepath.Base(cwd), err)
		}
		if err := requireOutsideRepo("NPS_OBSERVE_DIR", abs, repoRoot); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(abs, 0o700); err != nil {
			t.Fatalf("create NPS_OBSERVE_DIR basename=%s: %v", filepath.Base(abs), err)
		}
		return abs
	}
	return t.TempDir()
}

func findKavernRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		info, err := os.Stat(filepath.Join(dir, "go.mod"))
		if err == nil && !info.IsDir() {
			return dir, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

func requireOutsideRepo(label, path, repoRoot string) error {
	if isPathWithin(path, repoRoot) {
		return fmt.Errorf("%s basename=%s is inside the Kavern repository; use a temp or external directory", label, filepath.Base(path))
	}
	return nil
}

func isPathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func TestObserveFindKavernRepoRoot(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := findKavernRepoRoot(cwd)
	if err != nil {
		t.Fatal(err)
	}
	goModPath := filepath.Join(root, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		t.Fatalf("repo root basename=%s does not contain go.mod: %v", filepath.Base(root), err)
	}
	goMod, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod from repo root basename=%s: %v", filepath.Base(root), err)
	}
	if !strings.Contains(string(goMod), "module github.com/geniucker-dev/kavern") {
		t.Fatalf("repo root go.mod does not declare module github.com/geniucker-dev/kavern")
	}
}

func TestObserveRepoBoundaryValidation(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := findKavernRepoRoot(cwd)
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "tests", "legacy_npc", "observe-runtime")
	if err := requireOutsideRepo("NPS_OBSERVE_DIR", inside, root); err == nil {
		t.Fatal("path under repo root was allowed")
	}
	external := t.TempDir()
	if err := requireOutsideRepo("NPS_OBSERVE_DIR", external, root); err != nil {
		t.Fatalf("external temp dir was rejected: %v", err)
	}
}

func TestObserveGeneratedSecretsAreRandom(t *testing.T) {
	first := newObserveSecrets(t)
	second := newObserveSecrets(t)
	if first.authKey == "" || first.webPassword == "" || second.authKey == "" || second.webPassword == "" {
		t.Fatal("generated observe secrets must be non-empty")
	}
	if first.authKey == second.authKey {
		t.Fatal("generated auth keys matched")
	}
	if first.webPassword == second.webPassword {
		t.Fatal("generated web passwords matched")
	}
}

func TestObserveGeneratedSecretsAreRedacted(t *testing.T) {
	secrets := newObserveSecrets(t)
	recorder := newObserveRecorder(t, "stock_nps_oracle", "", nil, secrets.authKey, secrets.webPassword)
	msg := recorder.redact("auth=" + secrets.authKey + " password=" + secrets.webPassword)
	if strings.Contains(msg, secrets.authKey) || strings.Contains(msg, secrets.webPassword) {
		t.Fatal("recorder did not redact generated observe secrets")
	}
	errMsg := sanitizeErr(fmt.Errorf("auth=%s password=%s", secrets.authKey, secrets.webPassword), secrets.redactValues()...)
	if strings.Contains(errMsg, secrets.authKey) || strings.Contains(errMsg, secrets.webPassword) {
		t.Fatal("sanitizeErr did not redact generated observe secrets")
	}
}

type stockNPSRuntime struct {
	dir        string
	npsPath    string
	webAddr    string
	publicPort string
	logPath    string
}

func prepareStockNPSRuntime(t *testing.T, root string, topology *oracleTopology, secrets observeSecrets, recorder *observeRecorder) stockNPSRuntime {
	t.Helper()
	npsBin := os.Getenv("NPS_BIN")
	runtimeDir := filepath.Join(root, "nps-oracle")
	confDir := filepath.Join(runtimeDir, "conf")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatalf("create stock nps runtime conf dir basename=%s: %v", filepath.Base(confDir), err)
	}
	npsPath := filepath.Join(runtimeDir, filepath.Base(npsBin))
	if err := copyExecutable(npsBin, npsPath); err != nil {
		t.Fatalf("copy stock nps binary basename=%s into temp runtime: %v", filepath.Base(npsBin), err)
	}
	bridgeHost, bridgePort := splitHostPortForTest(t, topology.npsBridgeAddr)
	webAddr := reserveLoopbackAddr(t)
	webHost, webPort := splitHostPortForTest(t, webAddr)
	publicHost, publicPort := splitHostPortForTest(t, topology.npsPublicAddr)
	if bridgeHost != "127.0.0.1" || webHost != "127.0.0.1" || publicHost != "127.0.0.1" {
		t.Fatal("stock nps oracle requires loopback-only bridge, web, and public ports")
	}
	conf := strings.Join([]string{
		"bridge_type=tcp",
		"bridge_ip=127.0.0.1",
		"bridge_port=" + bridgePort,
		"tls_enable=false",
		"tls_bridge_port=",
		"web_ip=127.0.0.1",
		"web_port=" + webPort,
		"web_username=admin",
		"web_password=" + secrets.webPassword,
		"auth_key=" + secrets.authKey,
		"auth_crypt_key=0123456789abcdef",
		"http_proxy_ip=127.0.0.1",
		"http_proxy_port=",
		"https_proxy_port=",
		"allow_local_proxy=false",
		"allow_ports=" + publicPort + "-" + publicPort,
		"disconnect_timeout=2",
		"flow_store_interval=",
		"log_level=7",
		"log_path=nps-observe.log",
		"ip_limit=false",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(confDir, "nps.conf"), []byte(conf), 0o600); err != nil {
		t.Fatalf("write sanitized stock nps config basename=nps.conf: %v", err)
	}
	recorder.note("nps_runtime", "dir=temp_external conf=nps.conf bridge=loopback web=loopback public=loopback")
	return stockNPSRuntime{dir: runtimeDir, npsPath: npsPath, webAddr: webAddr, publicPort: publicPort, logPath: filepath.Join(runtimeDir, "nps-observe.log")}
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func splitHostPortForTest(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split loopback address: %v", err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("address host=%s, want 127.0.0.1", host)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("address port is not numeric: %v", err)
	}
	return host, port
}

type stockNPSAPI struct {
	base     string
	authKey  string
	http     *http.Client
	lastResp npsAPIShape
}

func newStockNPSAPI(webAddr, authKey string) *stockNPSAPI {
	return &stockNPSAPI{
		base:    "http://" + webAddr,
		authKey: authKey,
		http:    &http.Client{Timeout: 2 * time.Second},
	}
}

func (a *stockNPSAPI) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := a.serverTime(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("timeout waiting for /auth/gettime/: %w", lastErr)
}

func (a *stockNPSAPI) addClient(ctx context.Context, vkey string) (string, error) {
	form := url.Values{
		"remark":            {"oracle"},
		"vkey":              {vkey},
		"u":                 {""},
		"p":                 {""},
		"compress":          {"false"},
		"crypt":             {"false"},
		"config_conn_allow": {"false"},
		"rate_limit":        {""},
		"flow_limit":        {""},
		"max_conn":          {""},
		"max_tunnel":        {""},
		"web_username":      {""},
		"web_password":      {""},
		"blackiplist":       {""},
		"ipwhite":           {"false"},
		"ipwhitepass":       {""},
		"ipwhitelist":       {""},
		"expire_time":       {""},
	}
	var resp npsAPIResponse
	if err := a.post(ctx, "/client/add/", form, &resp); err != nil {
		return "", err
	}
	if resp.Status != 1 || resp.ID == 0 {
		return "", fmt.Errorf("client add response status=%d id_present=%t msg_present=%t", resp.Status, resp.ID != 0, resp.Msg != "")
	}
	return strconv.Itoa(resp.ID), nil
}

func (a *stockNPSAPI) addTCPTunnel(ctx context.Context, clientID, publicPort, targetAddr string) error {
	form := url.Values{
		"client_id":     {clientID},
		"type":          {"tcp"},
		"remark":        {"oracle-tcp"},
		"port":          {publicPort},
		"server_ip":     {"127.0.0.1"},
		"target":        {targetAddr},
		"local_proxy":   {"false"},
		"password":      {""},
		"local_path":    {""},
		"strip_pre":     {""},
		"proto_version": {""},
	}
	var resp npsAPIResponse
	if err := a.post(ctx, "/index/add/", form, &resp); err != nil {
		return err
	}
	if resp.Status != 1 {
		return fmt.Errorf("tcp tunnel add response status=%d id_present=%t msg_present=%t", resp.Status, resp.ID != 0, resp.Msg != "")
	}
	return nil
}

func (a *stockNPSAPI) post(ctx context.Context, path string, form url.Values, out any) error {
	ts, err := a.serverTime(ctx)
	if err != nil {
		return err
	}
	form = cloneValues(form)
	form.Set("timestamp", ts)
	form.Set("auth_key", md5Hex(a.authKey+ts))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16*1024))
	if err != nil {
		return err
	}
	a.lastResp = summarizeNPSAPIShape(body)
	return json.Unmarshal(body, out)
}

func (a *stockNPSAPI) serverTime(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/auth/gettime/", nil)
	if err != nil {
		return "", err
	}
	res, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var body struct {
		Time int64 `json:"time"`
	}
	if err := decodeLimitedJSON(res.Body, &body); err != nil {
		return "", err
	}
	if body.Time <= 0 {
		return "", fmt.Errorf("gettime response missing positive time")
	}
	return strconv.FormatInt(body.Time, 10), nil
}

type npsAPIResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
	ID     int    `json:"id"`
}

type npsAPIShape struct {
	StatusPresent   bool
	Status          int
	MsgPresent      bool
	Msg             string
	IDPresent       bool
	ClientIDPresent bool
}

func (a *stockNPSAPI) lastResponseShape() npsAPIShape {
	return a.lastResp
}

func summarizeNPSAPIShape(body []byte) npsAPIShape {
	var raw map[string]any
	shape := npsAPIShape{}
	if err := json.Unmarshal(body, &raw); err != nil {
		shape.Msg = "invalid_json"
		return shape
	}
	if v, ok := raw["status"]; ok {
		shape.StatusPresent = true
		switch n := v.(type) {
		case float64:
			shape.Status = int(n)
		}
	}
	if v, ok := raw["msg"]; ok {
		shape.MsgPresent = true
		if s, ok := v.(string); ok {
			shape.Msg = s
		}
	}
	if _, ok := raw["id"]; ok {
		shape.IDPresent = true
	}
	if _, ok := raw["client_id"]; ok {
		shape.ClientIDPresent = true
	}
	return shape
}

func decodeLimitedJSON(r io.Reader, out any) error {
	return json.NewDecoder(io.LimitReader(r, 16*1024)).Decode(out)
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, vs := range in {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

type oracleTopology struct {
	cancel        context.CancelFunc
	echoAddr      string
	npsBridgeAddr string
	npsPublicAddr string
	targetProxy   *observeProxy
	legacyProxy   *observeProxy
	publicProxy   *observeProxy
}

func newOracleTopology(t *testing.T, ctx context.Context, recorder *observeRecorder) *oracleTopology {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	echoAddr := startObserveEchoTarget(t, ctx, recorder)
	topology := &oracleTopology{
		cancel:        cancel,
		echoAddr:      echoAddr,
		npsBridgeAddr: reserveLoopbackAddr(t),
		npsPublicAddr: reserveLoopbackAddr(t),
	}
	topology.targetProxy = startObserveProxy(t, ctx, recorder, "target_tcp", echoAddr)
	topology.legacyProxy = startObserveProxy(t, ctx, recorder, "legacy_nps_npc", topology.npsBridgeAddr)
	topology.publicProxy = startObserveProxy(t, ctx, recorder, "public_tcp", topology.npsPublicAddr)
	recorder.setSemanticAddresses(map[string]string{
		topology.targetProxy.Addr(): "<target_proxy_addr>",
		topology.npsPublicAddr:      "<nps_public_addr>",
		topology.legacyProxy.Addr(): "<npc_bridge_addr>",
		topology.publicProxy.Addr(): "<public_client_addr>",
		topology.echoAddr:           "<echo_target_addr>",
	})
	recorder.note("oracle_topology", fmt.Sprintf("roles=legacy_nps_npc,public_tcp,target_tcp nps_legacy=loopback nps_public=loopback echo=loopback"))
	return topology
}

func (t *oracleTopology) Close() {
	t.cancel()
	t.targetProxy.Close()
	t.legacyProxy.Close()
	t.publicProxy.Close()
}

func (t *oracleTopology) npcServerAddr() string {
	return t.legacyProxy.Addr()
}

func (t *oracleTopology) publicClientAddr() string {
	return t.publicProxy.Addr()
}

func (t *oracleTopology) targetProxyAddr() string {
	return t.targetProxy.Addr()
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func startObserveEchoTarget(t *testing.T, ctx context.Context, recorder *observeRecorder) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			recorder.note("target_connection", "role=echo_target remote=loopback")
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							if ctx.Err() != nil {
								return
							}
							continue
						}
						return
					}
				}
			}(conn)
		}
	}()
	return l.Addr().String()
}

type observeProxy struct {
	listener net.Listener
	role     string
	upstream string
	recorder *observeRecorder
	cancel   context.CancelFunc
	mu       sync.Mutex
	seq      int
	seen     chan struct{}
	seenOnce sync.Once
	tracker  *legacyBridgeTracker
}

func startObserveProxy(t *testing.T, ctx context.Context, recorder *observeRecorder, role, upstream string) *observeProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &observeProxy{listener: l, role: role, upstream: upstream, recorder: recorder, cancel: cancel, seen: make(chan struct{})}
	if role == "legacy_nps_npc" {
		p.tracker = newLegacyBridgeTracker(recorder)
	}
	go p.serve(ctx)
	return p
}

func (p *observeProxy) Addr() string {
	return p.listener.Addr().String()
}

func (p *observeProxy) Close() {
	p.cancel()
	_ = p.listener.Close()
}

func (p *observeProxy) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seq
}

func (p *observeProxy) Seen() <-chan struct{} {
	return p.seen
}

func (p *observeProxy) Readiness() legacyBridgeReadiness {
	if p.tracker == nil {
		return legacyBridgeReadiness{ConnectionCount: p.Count()}
	}
	return p.tracker.Readiness()
}

func (p *observeProxy) ReadyChan(role string) <-chan struct{} {
	if p.tracker == nil {
		ch := make(chan struct{})
		return ch
	}
	return p.tracker.ReadyChan(role)
}

func (p *observeProxy) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = p.listener.Close()
	}()
	for {
		downstream, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.seq++
		id := p.seq
		p.mu.Unlock()
		p.seenOnce.Do(func() {
			close(p.seen)
		})
		p.recorder.note("proxy_connection", fmt.Sprintf("role=%s conn=%d upstream=loopback", p.role, id))
		go p.handle(ctx, id, downstream)
	}
}

func waitBridgeOrNPCExit(ctx context.Context, proxy *observeProxy, npcMonitor *processMonitor, timeout time.Duration) (bool, string) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-proxy.Seen():
		return true, ""
	case <-npcMonitor.Done():
		return false, npcMonitor.Status()
	case <-timer.C:
		return false, ""
	case <-ctx.Done():
		return false, ""
	}
}

type legacyBridgeTracker struct {
	recorder  *observeRecorder
	mu        sync.Mutex
	conns     map[int]*legacyBridgeConnState
	mainConn  int
	chanConn  int
	mainReady chan struct{}
	chanReady chan struct{}
	mainOnce  sync.Once
	chanOnce  sync.Once
}

type legacyBridgeConnState struct {
	prefaceSeen         bool
	challengeSeen       bool
	tokenSeen           bool
	successSeen         bool
	connType            string
	postHandshakeFrames int
	sessionControl      chanSessionControlDecoder
}

type legacyBridgeReadiness struct {
	MainReady             bool
	ChanReady             bool
	MainConn              int
	ChanConn              int
	ConnectionCount       int
	ChanPostHandshakeSeen bool
	SessionControl        sessionControlEvidence
}

const maxObservedSessionControlBody = 4096

type observedSessionControlFrame struct {
	Direction string
	Opcode    byte
	StreamID  uint32
	Body      []byte
}

type chanSessionControlDecoder struct {
	buffers map[string][]byte
	frames  []observedSessionControlFrame
	invalid bool
}

type sessionControlEvidence struct {
	Sequence                    []string `json:"sequence,omitempty"`
	Client00BodyLen             int      `json:"client_00_body_len,omitempty"`
	Server00BodyLen             int      `json:"server_00_body_len,omitempty"`
	Server08BodyLen             int      `json:"server_08_body_len,omitempty"`
	Client08BodyLen             int      `json:"client_08_body_len,omitempty"`
	Server08EqualsClient00      bool     `json:"server_08_equals_client_00"`
	Client08EqualsServer00      bool     `json:"client_08_equals_server_00"`
	Server08EqualsServer00      bool     `json:"server_08_equals_server_00"`
	Client08EqualsClient00      bool     `json:"client_08_equals_client_00"`
	RelationshipConfirmed       bool     `json:"relationship_confirmed"`
	Complete                    bool     `json:"complete"`
	StrictDecoderRejectedStream bool     `json:"strict_decoder_rejected_stream"`
}

func (d *chanSessionControlDecoder) Observe(direction string, data []byte) {
	if d.invalid || len(data) == 0 {
		return
	}
	if d.buffers == nil {
		d.buffers = make(map[string][]byte)
	}
	buf := append(d.buffers[direction], data...)
	if len(buf) > observeTotalLimit {
		d.invalid = true
		return
	}
	for {
		frameLen, ok := observedChanFrameLength(buf)
		if !ok {
			break
		}
		if frameLen < 0 || frameLen > len(buf) {
			d.invalid = true
			return
		}
		frame := buf[:frameLen]
		if (frame[0] == 0x00 || frame[0] == 0x08) && binary.LittleEndian.Uint32(frame[1:5]) == 0xffffffff {
			d.frames = append(d.frames, observedSessionControlFrame{
				Direction: direction,
				Opcode:    frame[0],
				StreamID:  binary.LittleEndian.Uint32(frame[1:5]),
				Body:      append([]byte(nil), frame[7:]...),
			})
		}
		buf = buf[frameLen:]
	}
	d.buffers[direction] = append(d.buffers[direction][:0], buf...)
}

func observedChanFrameLength(buf []byte) (int, bool) {
	if len(buf) == 0 {
		return 0, false
	}
	switch buf[0] {
	case 0x01, 0x06, 0x07:
		if len(buf) < 5 {
			return 0, false
		}
		return 5, true
	case 0x05:
		if len(buf) < 13 {
			return 0, false
		}
		return 13, true
	case 0x00, 0x03, 0x08:
		if len(buf) < 7 {
			return 0, false
		}
		bodyLen := int(binary.LittleEndian.Uint16(buf[5:7]))
		if bodyLen > maxObservedSessionControlBody {
			return -1, true
		}
		total := 7 + bodyLen
		if len(buf) < total {
			return 0, false
		}
		return total, true
	default:
		return -1, true
	}
}

func (d *chanSessionControlDecoder) Evidence() sessionControlEvidence {
	evidence := sessionControlEvidence{StrictDecoderRejectedStream: d.invalid}
	if d.invalid {
		return evidence
	}
	for _, frame := range d.frames {
		if len(evidence.Sequence) == 4 {
			break
		}
		evidence.Sequence = append(evidence.Sequence, fmt.Sprintf("%s:0x%02x", frame.Direction, frame.Opcode))
	}
	var client00, server00, server08, client08 *observedSessionControlFrame
	for i := range d.frames {
		frame := &d.frames[i]
		switch {
		case client00 == nil && frame.Direction == "npc_to_nps" && frame.Opcode == 0x00:
			client00 = frame
		case server00 == nil && frame.Direction == "nps_to_npc" && frame.Opcode == 0x00:
			server00 = frame
		case server08 == nil && frame.Direction == "nps_to_npc" && frame.Opcode == 0x08:
			server08 = frame
		case client08 == nil && frame.Direction == "npc_to_nps" && frame.Opcode == 0x08:
			client08 = frame
		}
	}
	if client00 == nil || server00 == nil || server08 == nil || client08 == nil {
		return evidence
	}
	evidence.Complete = true
	evidence.Client00BodyLen = len(client00.Body)
	evidence.Server00BodyLen = len(server00.Body)
	evidence.Server08BodyLen = len(server08.Body)
	evidence.Client08BodyLen = len(client08.Body)
	evidence.Server08EqualsClient00 = equalSessionControlBodies(server08.Body, client00.Body)
	evidence.Client08EqualsServer00 = equalSessionControlBodies(client08.Body, server00.Body)
	evidence.Server08EqualsServer00 = equalSessionControlBodies(server08.Body, server00.Body)
	evidence.Client08EqualsClient00 = equalSessionControlBodies(client08.Body, client00.Body)
	evidence.RelationshipConfirmed = evidence.Server08EqualsClient00 && evidence.Client08EqualsServer00
	return evidence
}

func equalSessionControlBodies(left, right []byte) bool {
	leftHash := sha256.Sum256(left)
	rightHash := sha256.Sum256(right)
	return leftHash == rightHash
}

func newLegacyBridgeTracker(recorder *observeRecorder) *legacyBridgeTracker {
	return &legacyBridgeTracker{
		recorder:  recorder,
		conns:     map[int]*legacyBridgeConnState{},
		mainReady: make(chan struct{}),
		chanReady: make(chan struct{}),
	}
}

func (t *legacyBridgeTracker) ReadyChan(role string) <-chan struct{} {
	switch role {
	case "main":
		return t.mainReady
	case "chan":
		return t.chanReady
	default:
		ch := make(chan struct{})
		return ch
	}
}

func (t *legacyBridgeTracker) Observe(connID int, direction string, data []byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.conns[connID]
	if st == nil {
		st = &legacyBridgeConnState{}
		t.conns[connID] = st
	}
	switch {
	case direction == "npc_to_nps" && !st.prefaceSeen && isObservedHandshakeFrame(data):
		st.prefaceSeen = true
		t.recorder.note("legacy_bridge_preface", fmt.Sprintf("conn=%d preface_seen=true", connID))
		return false
	case direction == "nps_to_npc" && st.prefaceSeen && !st.challengeSeen && len(data) == 32:
		st.challengeSeen = true
		t.recorder.note("legacy_bridge_challenge", fmt.Sprintf("conn=%d challenge_32_seen=true", connID))
		return false
	case direction == "npc_to_nps" && st.challengeSeen && !st.tokenSeen && len(data) == 32:
		st.tokenSeen = true
		t.recorder.note("legacy_bridge_token", fmt.Sprintf("conn=%d token_32_seen=true preview=<redacted>", connID))
		return false
	case direction == "nps_to_npc" && st.tokenSeen && !st.successSeen && string(data) == "sucs":
		st.successSeen = true
		t.recorder.note("legacy_bridge_success", fmt.Sprintf("conn=%d success_seen=true value=sucs", connID))
		return false
	case direction == "npc_to_nps" && st.successSeen && st.connType == "" && len(data) >= 4:
		connType := string(data[:4])
		if connType == "main" || connType == "chan" {
			st.connType = connType
			t.recorder.note("legacy_bridge_connection_type", fmt.Sprintf("conn=%d type=%s", connID, connType))
			if connType == "main" && t.mainConn == 0 {
				t.mainConn = connID
				t.mainOnce.Do(func() {
					close(t.mainReady)
				})
			}
			if connType == "chan" && t.chanConn == 0 {
				t.chanConn = connID
				t.chanOnce.Do(func() {
					close(t.chanReady)
				})
			}
			if connType == "chan" && len(data) > 4 {
				st.postHandshakeFrames++
				st.sessionControl.Observe(direction, data[4:])
				t.recorder.chanFrame(connID, direction, st.postHandshakeFrames, data[4:])
				return true
			}
		} else {
			st.connType = "unsupported"
			t.recorder.note("legacy_bridge_connection_type", fmt.Sprintf("conn=%d type=unsupported", connID))
		}
		return false
	case st.connType == "chan":
		st.postHandshakeFrames++
		st.sessionControl.Observe(direction, data)
		t.recorder.chanFrame(connID, direction, st.postHandshakeFrames, data)
		return true
	}
	return false
}

func (t *legacyBridgeTracker) Readiness() legacyBridgeReadiness {
	t.mu.Lock()
	defer t.mu.Unlock()
	readiness := legacyBridgeReadiness{
		MainReady:       t.mainConn != 0,
		ChanReady:       t.chanConn != 0,
		MainConn:        t.mainConn,
		ChanConn:        t.chanConn,
		ConnectionCount: len(t.conns),
	}
	if t.chanConn != 0 {
		if st := t.conns[t.chanConn]; st != nil && st.postHandshakeFrames > 0 {
			readiness.ChanPostHandshakeSeen = true
		}
		if st := t.conns[t.chanConn]; st != nil {
			readiness.SessionControl = st.sessionControl.Evidence()
		}
	}
	return readiness
}

func (p *observeProxy) handle(ctx context.Context, id int, downstream net.Conn) {
	defer downstream.Close()
	upstream, err := net.DialTimeout("tcp", p.upstream, 2*time.Second)
	if err != nil {
		p.recorder.note("proxy_dial_failed", fmt.Sprintf("role=%s conn=%d upstream=loopback err=%s", p.role, id, sanitizeErr(err)))
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		copyObserved(ctx, p.recorder, p.tracker, id, p.role, roleDirection(p.role, true), upstream, downstream)
		done <- struct{}{}
	}()
	go func() {
		copyObserved(ctx, p.recorder, p.tracker, id, p.role, roleDirection(p.role, false), downstream, upstream)
		done <- struct{}{}
	}()
	<-done
}

func roleDirection(role string, inbound bool) string {
	switch role {
	case "legacy_nps_npc":
		if inbound {
			return "npc_to_nps"
		}
		return "nps_to_npc"
	case "public_tcp":
		if inbound {
			return "public_client_to_nps"
		}
		return "nps_to_public_client"
	case "target_tcp":
		if inbound {
			return "npc_to_target"
		}
		return "target_to_npc"
	default:
		if inbound {
			return "inbound"
		}
		return "outbound"
	}
}

func copyObserved(ctx context.Context, recorder *observeRecorder, tracker *legacyBridgeTracker, connID int, role, direction string, dst, src net.Conn) {
	buf := make([]byte, 4096)
	total := 0
	for {
		_ = src.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := src.Read(buf)
		if n > 0 {
			total += n
			handledByTracker := false
			if tracker != nil && role == "legacy_nps_npc" {
				handledByTracker = tracker.Observe(connID, direction, buf[:n])
			}
			if !handledByTracker {
				recorder.frame(connID, role, direction, total, buf[:n])
			}
			_ = dst.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			return
		}
	}
}

func waitLegacyReady(ctx context.Context, proxy *observeProxy, npcMonitor *processMonitor, role string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-proxy.ReadyChan(role):
		return true
	case <-npcMonitor.Done():
		return false
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func waitObserveGrace(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func observeOracleProbes(ctx context.Context, addr string, recorder *observeRecorder) (bool, error) {
	probes := []struct {
		id      int
		payload []byte
	}{
		{id: 1, payload: []byte("abcde")},
		{id: 2, payload: []byte("kavern-observe-echo")},
		{id: 3, payload: bytes.Repeat([]byte("z"), 257)},
	}
	for _, probe := range probes {
		recorder.startProbe(probe.id, len(probe.payload), probe.payload)
		if err := observeOracleEcho(ctx, addr, recorder, probe.id, probe.payload); err != nil {
			recorder.endProbe(probe.id)
			return false, err
		}
		recorder.markProbeCloseEvent(probe.id, "public_client_closed")
		recorder.note("public_probe_close", fmt.Sprintf("probe_id=%d payload_len=%d public_client_closed=true", probe.id, len(probe.payload)))
		waitObserveGrace(ctx, 750*time.Millisecond)
		recorder.endProbe(probe.id)
	}
	return true, nil
}

func probeCloseAction(id int) string {
	return "normal_echo_then_client_close"
}

func observeOracleEcho(ctx context.Context, addr string, recorder *observeRecorder, probeID int, payload []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	recorder.note("public_probe_send", fmt.Sprintf("probe_id=%d payload_len=%d", probeID, len(payload)))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: got %d bytes", len(got))
	}
	recorder.note("public_probe_echo", fmt.Sprintf("probe_id=%d payload_len=%d echo_success=true", probeID, len(payload)))
	return nil
}

func waitObservedProcess(t *testing.T, label string, cmd *exec.Cmd, monitor *processMonitor, recorder *observeRecorder) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	select {
	case <-monitor.Done():
		recorder.note(label+"_exit", fmt.Sprintf("status=%s", monitor.Status()))
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		recorder.note(label+"_exit", "status=killed_after_timeout")
	}
}

type processMonitor struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func newProcessMonitor(cmd *exec.Cmd) *processMonitor {
	m := &processMonitor{done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		m.err = err
		m.mu.Unlock()
		close(m.done)
	}()
	return m
}

func (m *processMonitor) Done() <-chan struct{} {
	return m.done
}

func (m *processMonitor) Exited() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

func (m *processMonitor) Status() string {
	select {
	case <-m.done:
	default:
		return "running"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return sanitizeProcessStatus(m.err)
}

type boundedBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-b.limit:]...)
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.buf...))
}

type observeListener struct {
	net.Listener
	recorder *observeRecorder
	mu       sync.Mutex
	seq      int
}

func (l *observeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.seq++
	id := l.seq
	l.mu.Unlock()
	role := "unknown"
	l.recorder.note("connection_received", fmt.Sprintf("conn=%d role=%s remote=loopback", id, role))
	return &observedConn{Conn: conn, recorder: l.recorder, connID: id, role: role}, nil
}

type observedConn struct {
	net.Conn
	recorder     *observeRecorder
	connID       int
	role         string
	read         int
	written      int
	rawSeen      bool
	pendingToken bool
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read += n
		data := p[:n]
		if c.role == "unknown" && len(data) == 32 && hex32Pattern.Match(data) {
			c.pendingToken = true
			c.recorder.note("auth_token_field", fmt.Sprintf("conn=%d role=unknown direction=npc_to_gateway bytes=32 preview=<hex32> notes=observed_split_auth_token", c.connID))
			return n, err
		}
		if c.pendingToken && len(data) == 4 {
			c.pendingToken = false
			role := string(data)
			if role == "main" || role == "chan" {
				c.role = role
			} else {
				c.role = "unsupported"
			}
			c.recorder.note("auth_connection_type", fmt.Sprintf("conn=%d role=%s direction=npc_to_gateway bytes=4 notes=observed_split_auth_type", c.connID, c.role))
			return n, err
		}
		if role, ok := observedAuthRole(data); ok {
			c.role = role
		}
		if c.role != "unknown" && !isObservedHandshakeFrame(data) && !isObservedAuthFrame(data) {
			if !c.rawSeen {
				c.rawSeen = true
				c.recorder.note("post_auth_bytes", fmt.Sprintf("conn=%d role=%s direction=npc_to_gateway bytes=%d preview=<payload:%d> notes=fields_unknown", c.connID, c.role, len(data), len(data)))
			}
			return n, err
		}
		c.recorder.frame(c.connID, c.role, "npc_to_gateway", c.read, data)
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.written += n
		data := p[:n]
		c.recorder.frame(c.connID, c.role, "gateway_to_npc", c.written, data)
	}
	return n, err
}

func observedAuthRole(data []byte) (string, bool) {
	if !isObservedAuthFrame(data) {
		return "", false
	}
	role := string(data[32:])
	if role == "main" || role == "chan" {
		return role, true
	}
	return "unsupported", true
}

func isObservedAuthFrame(data []byte) bool {
	return len(data) == 36 && hex32Pattern.Match(data[:32])
}

func isObservedHandshakeFrame(data []byte) bool {
	return bytes.HasPrefix(data, []byte("TST")) || len(data) == 4 || string(data) == "0.26.0" || string(data) == "0.26.34"
}

type observeRecorder struct {
	t                 *testing.T
	mode              string
	redactValues      []string
	semanticAddresses map[string]string
	fixture           *observeFixture
	mu                sync.Mutex
	activeProbe       observeProbeState
}

type observeProbeState struct {
	ID         int
	Length     int
	Payload    []byte
	CloseEvent string
}

func newObserveRecorder(t *testing.T, mode, vkey string, serverSecret []byte, extraRedactValues ...string) *observeRecorder {
	t.Helper()
	values := []string{vkey}
	if vkey != "" {
		sum := md5.Sum([]byte(vkey))
		values = append(values, hex.EncodeToString(sum[:]))
	}
	if len(serverSecret) > 0 {
		values = append(values, string(serverSecret))
	}
	values = append(values, extraRedactValues...)
	fixture := &observeFixture{
		Version: "gate6b1_fixture_v1",
		Mode:    mode,
	}
	return &observeRecorder{t: t, mode: mode, redactValues: values, fixture: fixture}
}

type observeFixture struct {
	Version              string                 `json:"version"`
	Mode                 string                 `json:"mode"`
	BinarySHA256         map[string]string      `json:"binary_sha256"`
	Frames               []observeFixtureFrame  `json:"frames"`
	ProbeSummary         []observeFixtureProbe  `json:"probe_summary"`
	FieldMap             observeFixtureFieldMap `json:"field_map"`
	Readiness            string                 `json:"readiness"`
	TargetTCPObserved    bool                   `json:"target_tcp_observed"`
	EchoSuccess          bool                   `json:"echo_success"`
	SessionControl       sessionControlEvidence `json:"session_control"`
	RedactionPolicy      []string               `json:"redaction_policy"`
	CleanRoomConstraints []string               `json:"clean_room_constraints"`
}

type observeFixtureProbe struct {
	ProbeID            int    `json:"probe_id"`
	PublicConnectionID string `json:"public_connection_id"`
	PayloadLength      int    `json:"payload_length"`
	CloseAction        string `json:"close_action"`
	CloseObservation   string `json:"close_observation"`
}

type observeFixtureFrame struct {
	Version                       string            `json:"version"`
	Mode                          string            `json:"mode"`
	BinarySHA256                  map[string]string `json:"binary_sha256"`
	ConnectionRole                string            `json:"connection_role"`
	Direction                     string            `json:"direction"`
	Seq                           int               `json:"seq"`
	ProbeID                       int               `json:"probe_id"`
	PublicConnectionID            string            `json:"public_connection_id"`
	ByteCount                     int               `json:"byte_count"`
	SanitizedHex                  string            `json:"sanitized_hex"`
	CandidateOpcodeByte           string            `json:"candidate_opcode_byte,omitempty"`
	CandidateStreamIDLE32         uint32            `json:"candidate_stream_id_le32,omitempty"`
	CandidateLengthLE16           uint16            `json:"candidate_length_le16,omitempty"`
	CandidateLengthLE32           uint32            `json:"candidate_length_le32,omitempty"`
	CandidatePayloadOffset        int               `json:"candidate_payload_offset,omitempty"`
	MetadataBodyFormat            string            `json:"metadata_body_format,omitempty"`
	MetadataKeySummary            []string          `json:"metadata_key_summary,omitempty"`
	MetadataSanitizedPreview      string            `json:"metadata_sanitized_preview,omitempty"`
	SemanticAddressPlaceholders   []string          `json:"semantic_address_placeholders,omitempty"`
	MetadataHostPlaceholder       string            `json:"metadata_host_placeholder,omitempty"`
	MetadataRemoteAddrPlaceholder string            `json:"metadata_remote_addr_placeholder,omitempty"`
	CloseCandidateDirection       string            `json:"close_candidate_direction,omitempty"`
	CloseCandidateAfterEvent      string            `json:"close_candidate_after_event,omitempty"`
	CloseCandidateStreamID        uint32            `json:"close_candidate_stream_id,omitempty"`
	CloseSemanticsEvidence        string            `json:"close_semantics_evidence,omitempty"`
	PayloadPlaceholder            string            `json:"payload_placeholder,omitempty"`
	ObservedLabel                 string            `json:"observed_label"`
	TimingMarker                  string            `json:"timing_marker"`
	KnownFieldAnnotations         []string          `json:"known_field_annotations"`
	UnknownFields                 []string          `json:"unknown_fields"`
}

type observeFixtureFieldMap struct {
	FrameBoundaries             string   `json:"frame_boundaries"`
	FrameTypeFlagCandidates     []string `json:"frame_type_flag_candidates"`
	StreamCorrelationCandidates []string `json:"stream_correlation_id_candidates"`
	PayloadLengthCandidates     []string `json:"payload_length_candidates"`
	PayloadOffsetCandidates     []string `json:"payload_offset_candidates"`
	MetadataOpenStreamCandidate string   `json:"metadata_open_stream_candidate"`
	TCPPayloadFrameCandidate    string   `json:"tcp_payload_frame_candidate"`
	CloseResetEOFCandidate      string   `json:"close_reset_eof_candidate"`
	PingKeepaliveCandidate      string   `json:"ping_keepalive_candidate"`
	TargetSelectionSafety       string   `json:"target_selection_safety"`
	Unknowns                    []string `json:"unknowns"`
}

func (r *observeRecorder) setFixtureMetadata(npcSHA, npsSHA string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fixture.BinarySHA256 = map[string]string{
		"npc": npcSHA,
		"nps": npsSHA,
	}
}

func (r *observeRecorder) setSemanticAddresses(addresses map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.semanticAddresses = make(map[string]string, len(addresses))
	for addr, placeholder := range addresses {
		if addr != "" && placeholder != "" {
			r.semanticAddresses[addr] = placeholder
		}
	}
}

func (r *observeRecorder) frame(connID int, role, direction string, total int, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if total > observeTotalLimit {
		r.t.Logf("mode=%s conn=%d role=%s direction=%s state=capture_limit total_bytes=%d", r.mode, connID, role, direction, total)
		return
	}
	trimmed := data
	if len(trimmed) > observeFrameLimit {
		trimmed = trimmed[:observeFrameLimit]
	}
	summary := r.frameSummary(role, trimmed)
	r.t.Logf("mode=%s conn=%d role=%s direction=%s bytes=%d state=%s frame=%s preview=%s hex32=%t notes=%s",
		r.mode, connID, role, direction, len(data), summary.state, summary.shape, summary.preview, summary.hex32, summary.notes)
}

func (r *observeRecorder) chanFrame(connID int, direction string, seq int, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	trimmed := data
	if len(trimmed) > observeFrameLimit {
		trimmed = trimmed[:observeFrameLimit]
	}
	summary := r.chanFrameSummary(trimmed)
	r.t.Logf("mode=%s conn=%d role=legacy_nps_npc direction=%s chan_seq=%d bytes=%d state=%s frame=%s preview=%s hex32=%t notes=%s",
		r.mode, connID, direction, seq, len(data), summary.state, summary.shape, summary.preview, summary.hex32, summary.notes)
	r.recordFixtureFrameLocked(connID, direction, seq, data, summary)
}

func (r *observeRecorder) note(state, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.t.Logf("mode=%s state=%s notes=%s", r.mode, state, r.redact(msg))
}

func (r *observeRecorder) readiness(msg string) {
	r.note("readiness", msg)
}

func (r *observeRecorder) sessionControlEvidence(evidence sessionControlEvidence) {
	r.mu.Lock()
	r.fixture.SessionControl = evidence
	r.mu.Unlock()
	r.note("session_control_sequence", strings.Join(evidence.Sequence, ","))
	r.note("server_08_equals_client_00", fmt.Sprintf("%t", evidence.Server08EqualsClient00))
	r.note("client_08_equals_server_00", fmt.Sprintf("%t", evidence.Client08EqualsServer00))
	r.note("server_08_equals_server_00", fmt.Sprintf("%t", evidence.Server08EqualsServer00))
	r.note("client_08_equals_client_00", fmt.Sprintf("%t", evidence.Client08EqualsClient00))
	r.note("session_control_body_lengths", fmt.Sprintf("client_00_body_len=%d server_00_body_len=%d server_08_body_len=%d client_08_body_len=%d", evidence.Client00BodyLen, evidence.Server00BodyLen, evidence.Server08BodyLen, evidence.Client08BodyLen))
	r.note("relationship_confirmed", fmt.Sprintf("%t complete=%t strict_decoder_rejected_stream=%t", evidence.RelationshipConfirmed, evidence.Complete, evidence.StrictDecoderRejectedStream))
}

func (r *observeRecorder) startProbe(id, payloadLen int, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activeProbe = observeProbeState{ID: id, Length: payloadLen, Payload: append([]byte(nil), payload...)}
	closeAction := probeCloseAction(id)
	r.fixture.ProbeSummary = append(r.fixture.ProbeSummary, observeFixtureProbe{
		ProbeID:            id,
		PublicConnectionID: fmt.Sprintf("public-%d", id),
		PayloadLength:      payloadLen,
		CloseAction:        closeAction,
		CloseObservation:   "public client closed after echo; bounded chan grace observed",
	})
}

func (r *observeRecorder) markProbeCloseEvent(id int, event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeProbe.ID == id {
		r.activeProbe.CloseEvent = event
	}
}

func (r *observeRecorder) endProbe(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeProbe.ID == id {
		r.activeProbe = observeProbeState{}
	}
}

func (r *observeRecorder) writeFixtureIfRequested(t *testing.T, readiness legacyBridgeReadiness, targetObserved, echoSuccess bool) {
	t.Helper()
	out := os.Getenv("KAVERN_OBSERVE_FIXTURE_OUT")
	if out == "" {
		return
	}
	r.mu.Lock()
	fixture := *r.fixture
	fixture.Frames = append([]observeFixtureFrame(nil), r.fixture.Frames...)
	fixture.ProbeSummary = append([]observeFixtureProbe(nil), r.fixture.ProbeSummary...)
	fixture.Readiness = fixtureReadiness(readiness, targetObserved, echoSuccess)
	fixture.TargetTCPObserved = targetObserved
	fixture.EchoSuccess = echoSuccess
	fixture.RedactionPolicy = []string{
		"vkey redacted",
		"wire_token redacted",
		"lookup_key redacted",
		"raw_md5_vkey redacted",
		"auth_key redacted",
		"web_password redacted",
		"full_command_args omitted",
		"local_random_ports omitted",
		"arbitrary_payload_bytes replaced with placeholders",
	}
	fixture.CleanRoomConstraints = []string{
		"generated from pinned v0.26.34 release binaries as black-box oracle",
		"no yisier/nps source inspected/imported/vendored/copied/derived",
		"fixture contains sanitized non-secret observation bytes only",
	}
	fixture.FieldMap = buildFixtureFieldMap(fixture)
	r.mu.Unlock()

	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal observe fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("create observe fixture dir basename=%s: %v", filepath.Base(filepath.Dir(out)), err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write observe fixture basename=%s: %v", filepath.Base(out), err)
	}
	r.note("fixture_written", fmt.Sprintf("basename=%s frames=%d", filepath.Base(out), len(fixture.Frames)))
}

func (r *observeRecorder) recordFixtureFrameLocked(connID int, direction string, seq int, data []byte, summary frameSummary) {
	probe := r.activeProbe
	payloadPlaceholder := ""
	if probe.ID > 0 && payloadObserved(data, probe.Payload) {
		payloadPlaceholder = fmt.Sprintf("<payload:probe-%d:%d>", probe.ID, probe.Length)
	}
	candidates := r.candidateFrameFields(data, probe)
	if candidates.closeDirection != "" {
		candidates.closeDirection = direction
	}
	r.fixture.Frames = append(r.fixture.Frames, observeFixtureFrame{
		Version:                       r.fixture.Version,
		Mode:                          r.mode,
		BinarySHA256:                  cloneStringMap(r.fixture.BinarySHA256),
		ConnectionRole:                "legacy_nps_npc_chan",
		Direction:                     direction,
		Seq:                           seq,
		ProbeID:                       probe.ID,
		PublicConnectionID:            publicConnectionID(probe.ID),
		ByteCount:                     len(data),
		SanitizedHex:                  sanitizeFixtureHex(data, probe),
		CandidateOpcodeByte:           candidates.opcodeByte,
		CandidateStreamIDLE32:         candidates.streamIDLE32,
		CandidateLengthLE16:           candidates.lengthLE16,
		CandidateLengthLE32:           candidates.lengthLE32,
		CandidatePayloadOffset:        candidates.payloadOffset,
		MetadataBodyFormat:            candidates.metadataBodyFormat,
		MetadataKeySummary:            candidates.metadataKeySummary,
		MetadataSanitizedPreview:      candidates.metadataPreview,
		SemanticAddressPlaceholders:   candidates.semanticAddressPlaceholders,
		MetadataHostPlaceholder:       candidates.metadataHostPlaceholder,
		MetadataRemoteAddrPlaceholder: candidates.metadataRemoteAddrPlaceholder,
		CloseCandidateDirection:       candidates.closeDirection,
		CloseCandidateAfterEvent:      candidates.closeAfterEvent,
		CloseCandidateStreamID:        candidates.closeStreamID,
		CloseSemanticsEvidence:        candidates.closeEvidence,
		PayloadPlaceholder:            payloadPlaceholder,
		ObservedLabel:                 summary.state,
		TimingMarker:                  fixtureTimingMarker(probe.ID, summary.state),
		KnownFieldAnnotations:         knownFixtureFields(summary.state, len(data), payloadPlaceholder != "", candidates),
		UnknownFields:                 unknownFixtureFields(summary.state, candidates),
	})
}

type candidateFrameFields struct {
	opcodeByte                    string
	streamIDLE32                  uint32
	lengthLE16                    uint16
	lengthLE32                    uint32
	payloadOffset                 int
	metadataBodyFormat            string
	metadataKeySummary            []string
	metadataPreview               string
	semanticAddressPlaceholders   []string
	metadataHostPlaceholder       string
	metadataRemoteAddrPlaceholder string
	closeDirection                string
	closeAfterEvent               string
	closeStreamID                 uint32
	closeEvidence                 string
}

func (r *observeRecorder) candidateFrameFields(data []byte, probe observeProbeState) candidateFrameFields {
	fields := candidateFrameFields{}
	if payloadOffset, payloadBytes, ok := findPayloadSegment(data, probe.Payload); ok && payloadOffset == 0 && payloadBytes == len(data) {
		return fields
	}
	if len(data) >= 1 {
		fields.opcodeByte = fmt.Sprintf("0x%02x", data[0])
	}
	if len(data) >= 5 {
		fields.streamIDLE32 = binary.LittleEndian.Uint32(data[1:5])
	}
	if len(data) == 5 && data[0] == 0x07 {
		fields.closeDirection = "observed_frame_direction"
		fields.closeAfterEvent = probe.CloseEvent
		fields.closeStreamID = fields.streamIDLE32
		if fields.closeAfterEvent != "" {
			fields.closeEvidence = "0x07 frame observed during bounded grace after " + fields.closeAfterEvent
		} else {
			fields.closeEvidence = "0x07 frame observed before explicit close event marker"
		}
	}
	if len(data) >= 7 {
		fields.lengthLE16 = binary.LittleEndian.Uint16(data[5:7])
		if data[0] == 0x03 && int(fields.lengthLE16)+7 <= len(data) {
			fields.payloadOffset = 7
		}
	}
	if len(data) >= 11 {
		fields.lengthLE32 = binary.LittleEndian.Uint32(data[7:11])
		if data[0] == 0x03 && int(fields.lengthLE16)+7 <= len(data) && int(fields.lengthLE32)+11 <= len(data) {
			fields.payloadOffset = 11
			body := data[11 : 11+int(fields.lengthLE32)]
			metadata := r.summarizeMetadataBody(body, probe)
			fields.applyMetadataSummary(metadata)
		}
	}
	if fields.metadataBodyFormat == "" && len(data) >= 5 {
		continuationLength := binary.LittleEndian.Uint32(data[:4])
		if continuationLength > 0 && int(continuationLength)+4 <= len(data) {
			body := data[4 : 4+int(continuationLength)]
			metadata := r.summarizeMetadataBody(body, probe)
			if metadata.Format == "json_object_generic" || metadata.Format == "json_array_generic" || metadata.Format == "printable_ascii" {
				fields.lengthLE32 = continuationLength
				fields.payloadOffset = 4
				metadata.Format = "split_continuation_" + metadata.Format
				fields.applyMetadataSummary(metadata)
			}
		}
	}
	if fields.payloadOffset == 0 {
		if payloadOffset, _, ok := findPayloadSegment(data, probe.Payload); ok {
			fields.payloadOffset = payloadOffset
		}
	}
	return fields
}

func (f *candidateFrameFields) applyMetadataSummary(summary metadataBodySummary) {
	f.metadataBodyFormat = summary.Format
	f.metadataKeySummary = summary.KeySummary
	f.metadataPreview = summary.Preview
	f.semanticAddressPlaceholders = summary.SemanticAddressPlaceholders
	f.metadataHostPlaceholder = summary.HostPlaceholder
	f.metadataRemoteAddrPlaceholder = summary.RemoteAddrPlaceholder
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func publicConnectionID(probeID int) string {
	if probeID <= 0 {
		return "before-public-probe"
	}
	return fmt.Sprintf("public-%d", probeID)
}

func payloadObserved(data, payload []byte) bool {
	_, _, ok := findPayloadSegment(data, payload)
	return ok
}

func findPayloadSegment(data, payload []byte) (int, int, bool) {
	if len(payload) == 0 {
		return 0, 0, false
	}
	if idx := bytes.Index(data, payload); idx >= 0 {
		return idx, len(payload), true
	}
	return 0, 0, false
}

type metadataBodySummary struct {
	Format                      string
	KeySummary                  []string
	Preview                     string
	SemanticAddressPlaceholders []string
	HostPlaceholder             string
	RemoteAddrPlaceholder       string
}

func (r *observeRecorder) summarizeMetadataBody(body []byte, probe observeProbeState) metadataBodySummary {
	if len(body) == 0 {
		return metadataBodySummary{}
	}
	if _, _, ok := findPayloadSegment(body, probe.Payload); ok {
		return metadataBodySummary{Format: "payload_redacted", Preview: fmt.Sprintf("<payload:probe-%d:%d>", probe.ID, probe.Length)}
	}
	if !looksPrintableUTF8(body) {
		return metadataBodySummary{Format: "binary_unknown"}
	}
	semantic := r.metadataSemanticPlaceholders(body)
	sanitized := r.sanitizeMetadataText(string(body))
	trimmed := strings.TrimSpace(sanitized)
	if strings.HasPrefix(trimmed, "{") {
		keys, preview, ok := r.genericJSONSummary(trimmed)
		if ok {
			semantic.Format = "json_object_generic"
			semantic.KeySummary = keys
			semantic.Preview = preview
			return semantic
		}
	}
	if strings.HasPrefix(trimmed, "[") {
		keys, preview, ok := r.genericJSONSummary(trimmed)
		if ok {
			semantic.Format = "json_array_generic"
			semantic.KeySummary = keys
			semantic.Preview = preview
			return semantic
		}
	}
	semantic.Format = "printable_ascii"
	semantic.Preview = asciiPreview([]byte(sanitized), 240)
	return semantic
}

func (r *observeRecorder) metadataSemanticPlaceholders(body []byte) metadataBodySummary {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return metadataBodySummary{}
	}
	summary := metadataBodySummary{}
	if host, ok := raw["Host"].(string); ok {
		summary.HostPlaceholder = r.semanticPlaceholderForAddress(host)
	}
	if remote, ok := raw["RemoteAddr"].(string); ok {
		summary.RemoteAddrPlaceholder = r.semanticPlaceholderForAddress(remote)
	}
	seen := map[string]struct{}{}
	for _, placeholder := range []string{summary.HostPlaceholder, summary.RemoteAddrPlaceholder} {
		if placeholder != "" {
			seen[placeholder] = struct{}{}
		}
	}
	for placeholder := range seen {
		summary.SemanticAddressPlaceholders = append(summary.SemanticAddressPlaceholders, placeholder)
	}
	sort.Strings(summary.SemanticAddressPlaceholders)
	return summary
}

func (r *observeRecorder) sanitizeMetadataText(text string) string {
	out := r.redact(text)
	out = r.replaceSemanticAddresses(out)
	out = replaceUnknownLoopbackAddresses(out)
	out = hostPortPattern.ReplaceAllString(out, "${1}<unknown_loopback_addr>")
	out = portPattern.ReplaceAllString(out, "${1}<port>")
	return out
}

func (r *observeRecorder) replaceSemanticAddresses(text string) string {
	out := text
	keys := make([]string, 0, len(r.semanticAddresses))
	for addr := range r.semanticAddresses {
		keys = append(keys, addr)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	for _, addr := range keys {
		out = strings.ReplaceAll(out, addr, r.semanticAddresses[addr])
	}
	return out
}

func (r *observeRecorder) semanticPlaceholderForAddress(addr string) string {
	if placeholder := r.semanticAddresses[addr]; placeholder != "" {
		return placeholder
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host == "127.0.0.1" {
		return "<unknown_loopback_addr>"
	}
	if addr == "127.0.0.1" {
		return "<unknown_loopback_addr>"
	}
	return ""
}

func (r *observeRecorder) genericJSONSummary(text string) ([]string, string, bool) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, "", false
	}
	keys := summarizeJSONKeys(value, "")
	sort.Strings(keys)
	previewValue := r.sanitizeJSONValue(value)
	previewBytes, err := json.Marshal(previewValue)
	if err != nil {
		return keys, "", true
	}
	return keys, asciiPreview(previewBytes, 240), true
}

func summarizeJSONKeys(value any, prefix string) []string {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key, child := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			keys = append(keys, path+":"+jsonValueKind(child))
			keys = append(keys, summarizeJSONKeys(child, path)...)
		}
		return keys
	case []any:
		if len(v) == 0 {
			return []string{prefix + "[]:empty"}
		}
		keys := []string{prefix + "[]:" + jsonValueKind(v[0])}
		keys = append(keys, summarizeJSONKeys(v[0], prefix+"[]")...)
		return keys
	default:
		return nil
	}
}

func (r *observeRecorder) sanitizeJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			out[key] = r.sanitizeJSONValue(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = r.sanitizeJSONValue(child)
		}
		return out
	case string:
		if len(v) > jsonScalarMaxLen {
			v = v[:jsonScalarMaxLen] + "<truncated>"
		}
		v = hex32Pattern.ReplaceAllString(v, "<hex32>")
		v = r.replaceSemanticAddresses(v)
		v = replaceUnknownLoopbackAddresses(v)
		v = hostPortPattern.ReplaceAllString(v, "${1}<unknown_loopback_addr>")
		v = portPattern.ReplaceAllString(v, "${1}<port>")
		return v
	case json.Number:
		return v
	case float64:
		return v
	case bool:
		return v
	case nil:
		return nil
	default:
		return fmt.Sprintf("<%T>", v)
	}
}

func replaceUnknownLoopbackAddresses(text string) string {
	return loopbackPattern.ReplaceAllString(text, "<unknown_loopback_addr>")
}

func jsonValueKind(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number, float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

func sanitizeFixtureHex(data []byte, probe observeProbeState) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) >= 7 && (data[0] == 0x00 || data[0] == 0x08) {
		bodyLen := int(binary.LittleEndian.Uint16(data[5:7]))
		if bodyLen > 0 && len(data) >= 7+bodyLen {
			out := fmt.Sprintf("%s <session_control_body:%d>", hex.EncodeToString(data[:7]), bodyLen)
			if tail := data[7+bodyLen:]; len(tail) > 0 {
				out += " " + sanitizeSessionControlTail(tail)
			}
			return out
		}
	}
	if len(data) >= 11 && data[0] == 0x03 {
		lengthLE32 := binary.LittleEndian.Uint32(data[7:11])
		if lengthLE32 > 0 && int(lengthLE32)+11 <= len(data) {
			afterMetadata := data[11+int(lengthLE32):]
			if probe.ID > 0 {
				if payloadOffset, payloadBytes, ok := findPayloadSegment(afterMetadata, probe.Payload); ok {
					prefix := hex.EncodeToString(data[:11])
					between := afterMetadata[:payloadOffset]
					suffixBytes := len(afterMetadata) - payloadOffset - payloadBytes
					out := fmt.Sprintf("%s <metadata_body:%d>", prefix, lengthLE32)
					if len(between) > 0 {
						out += " " + hex.EncodeToString(between)
					}
					out += fmt.Sprintf(" <payload:probe-%d:%d>", probe.ID, probe.Length)
					if suffixBytes > 0 {
						out += fmt.Sprintf(" <redacted_after_payload:%d>", suffixBytes)
					}
					return out
				}
			}
			return fmt.Sprintf("%s <metadata_body:%d> <redacted_after_metadata:%d>", hex.EncodeToString(data[:11]), lengthLE32, len(afterMetadata))
		}
	}
	if len(data) >= 4 {
		lengthLE32 := binary.LittleEndian.Uint32(data[:4])
		if lengthLE32 > 0 && int(lengthLE32)+4 <= len(data) {
			afterMetadata := data[4+int(lengthLE32):]
			if probe.ID > 0 {
				if payloadOffset, payloadBytes, ok := findPayloadSegment(afterMetadata, probe.Payload); ok {
					prefix := hex.EncodeToString(data[:4])
					between := afterMetadata[:payloadOffset]
					suffixBytes := len(afterMetadata) - payloadOffset - payloadBytes
					out := fmt.Sprintf("%s <metadata_body:%d>", prefix, lengthLE32)
					if len(between) > 0 {
						out += " " + hex.EncodeToString(between)
					}
					out += fmt.Sprintf(" <payload:probe-%d:%d>", probe.ID, probe.Length)
					if suffixBytes > 0 {
						out += fmt.Sprintf(" <redacted_after_payload:%d>", suffixBytes)
					}
					return out
				}
			}
			return fmt.Sprintf("%s <metadata_body:%d> <redacted_after_metadata:%d>", hex.EncodeToString(data[:4]), lengthLE32, len(afterMetadata))
		}
	}
	if probe.ID > 0 {
		if payloadOffset, payloadBytes, ok := findPayloadSegment(data, probe.Payload); ok {
			prefix := hex.EncodeToString(data[:payloadOffset])
			suffixBytes := len(data) - payloadOffset - payloadBytes
			if suffixBytes > 0 {
				return fmt.Sprintf("%s <payload:probe-%d:%d> <redacted_after_payload:%d>", prefix, probe.ID, probe.Length, suffixBytes)
			}
			return fmt.Sprintf("%s <payload:probe-%d:%d>", prefix, probe.ID, probe.Length)
		}
	}
	if redacted, ok := redactSessionControlBodyContinuations(data); ok {
		return redacted
	}
	if looksTextual(data) {
		return fmt.Sprintf("<redacted_text:%d>", len(data))
	}
	return hex.EncodeToString(data)
}

// This is redaction-only handling for observed timestamp-shaped control bodies split across TCP reads.
func redactSessionControlBodyContinuations(data []byte) (string, bool) {
	matches := sessionBodyPattern.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return "", false
	}
	var out strings.Builder
	off := 0
	for _, match := range matches {
		if match[0] > off {
			out.WriteString(hex.EncodeToString(data[off:match[0]]))
			out.WriteByte(' ')
		}
		out.WriteString(fmt.Sprintf("<session_control_body:%d>", match[1]-match[0]))
		out.WriteByte(' ')
		off = match[1]
	}
	if off < len(data) {
		out.WriteString(hex.EncodeToString(data[off:]))
	}
	return strings.TrimSpace(out.String()), true
}

func sanitizeSessionControlTail(data []byte) string {
	if len(data) == 5 && (data[0] == 0x01 || data[0] == 0x06 || data[0] == 0x07) {
		return hex.EncodeToString(data)
	}
	if len(data) == 13 && data[0] == 0x05 {
		return hex.EncodeToString(data)
	}
	return fmt.Sprintf("<redacted_after_session_control:%d>", len(data))
}

func hexPrefix(data []byte, n int) string {
	if len(data) <= n {
		return hex.EncodeToString(data)
	}
	return hex.EncodeToString(data[:n])
}

func hexSuffix(data []byte, n int) string {
	if len(data) <= n {
		return ""
	}
	if len(data) < n {
		n = len(data)
	}
	return hex.EncodeToString(data[len(data)-n:])
}

func fixtureTimingMarker(probeID int, state string) string {
	if probeID <= 0 {
		return "before_public_probe"
	}
	if state == "chan_payload_related" {
		return fmt.Sprintf("probe_%d_payload_related", probeID)
	}
	return fmt.Sprintf("probe_%d_post_public_payload", probeID)
}

func knownFixtureFields(state string, byteCount int, payloadRelated bool, candidates candidateFrameFields) []string {
	fields := []string{
		fmt.Sprintf("observed_frame_boundary=%d_bytes", byteCount),
	}
	if candidates.opcodeByte != "" {
		fields = append(fields, "candidate_opcode_byte="+candidates.opcodeByte)
	}
	if candidates.streamIDLE32 != 0 {
		fields = append(fields, fmt.Sprintf("candidate_stream_id_le32=%d", candidates.streamIDLE32))
	}
	if candidates.lengthLE16 != 0 {
		fields = append(fields, fmt.Sprintf("candidate_length_le16=%d", candidates.lengthLE16))
	}
	if candidates.lengthLE32 != 0 {
		fields = append(fields, fmt.Sprintf("candidate_length_le32=%d", candidates.lengthLE32))
	}
	if candidates.payloadOffset != 0 {
		fields = append(fields, fmt.Sprintf("candidate_payload_offset=%d", candidates.payloadOffset))
	}
	switch state {
	case "chan_possible_ping":
		fields = append(fields, "candidate_short_control_frame")
	case "chan_possible_stream_open":
		fields = append(fields, "candidate_open_or_control_frame")
	case "chan_possible_data_frame":
		fields = append(fields, "candidate_data_or_metadata_frame")
	case "chan_payload_related":
		fields = append(fields, "payload_placeholder_marks_observed_payload_bytes")
	}
	if candidates.metadataBodyFormat != "" {
		fields = append(fields, "metadata_body_format="+candidates.metadataBodyFormat)
	}
	if payloadRelated {
		fields = append(fields, "payload_bytes_redacted")
	}
	return fields
}

func unknownFixtureFields(state string, candidates candidateFrameFields) []string {
	unknowns := []string{"frame_type", "stream_or_correlation_id", "payload_length_field", "payload_offset"}
	if state == "chan_possible_ping" {
		return []string{"ping_opcode", "ping_payload_semantics"}
	}
	if candidates.metadataBodyFormat == "binary_unknown" {
		unknowns = append(unknowns, "metadata_body_binary_semantics")
	}
	if candidates.metadataBodyFormat == "" && state == "chan_possible_data_frame" {
		unknowns = append(unknowns, "metadata_body_presence")
	}
	return unknowns
}

func fixtureReadiness(readiness legacyBridgeReadiness, targetObserved, echoSuccess bool) string {
	if !readiness.ChanPostHandshakeSeen || !targetObserved || !echoSuccess {
		return "insufficient for 6B-2"
	}
	return "insufficient for 6B-2"
}

func buildFixtureFieldMap(fixture observeFixture) observeFixtureFieldMap {
	return observeFixtureFieldMap{
		FrameBoundaries:         "Observed TCP read boundaries are recorded per chan frame; implementation must treat them as candidate protocol frame boundaries until validated by decoder tests.",
		FrameTypeFlagCandidates: uniqueLabels(fixture.Frames),
		StreamCorrelationCandidates: []string{
			"candidate stream/correlation id offset bytes 1..4 little endian; observed public probes map to stream ids summarized in frame candidate_stream_id_le32 fields",
			candidateByProbe("stream/correlation id candidate requires comparing non-payload header bytes across at least two public connections", fixture.Frames)[0],
		},
		PayloadLengthCandidates: []string{
			"payload frame candidate opcode byte 0x03; stream id candidate offset bytes 1..4 little endian; payload length candidate offset bytes 5..6 little endian; small probes observed direct payload offset byte 7, while the 257-byte probe observed a split 7-byte length header followed by a payload-only read",
			candidateByProbe("payload length candidate requires comparing frames for 5, 19, and 257 byte probes", fixture.Frames)[0],
		},
		PayloadOffsetCandidates: []string{
			"candidate payload offset 7 for direct payload frames; split payload body can arrive as a later read after a 7-byte 0x03 length header; candidate metadata body offset 11 when bytes 7..10 little-endian length matches remaining body",
			candidateByProbe("payload offset candidate is any stable non-redacted header before payload placeholder", fixture.Frames)[0],
		},
		MetadataOpenStreamCandidate: "large 0x03 nps_to_npc frames with length_le16=178 and nested length_le32=174 are open/metadata candidates; metadata_body_format, metadata_host_placeholder, metadata_remote_addr_placeholder, and sanitized preview fields record whether body is printable/json/binary_unknown and which semantic addresses appear.",
		TCPPayloadFrameCandidate:    "0x03 payload frames correlate with 5 / 19 / 257 byte probes; payload bytes are replaced with placeholders and candidate payload offset/length fields are recorded per frame.",
		CloseResetEOFCandidate:      "0x07 <stream_id_le32> short frames are close/reset candidates; close_candidate_direction, close_candidate_after_event, close_candidate_stream_id, and close_semantics_evidence are recorded when observed, but exact EOF/reset semantics remain unknown unless stable across probes.",
		PingKeepaliveCandidate:      "0x05 <stream_id_le32> and other short control frames are window/ack/control or ping candidates; exact semantics remain unknown.",
		TargetSelectionSafety:       "oracle target is configured by stock nps Web API setup to <target_proxy_addr>; metadata Host/RemoteAddr placeholders distinguish <target_proxy_addr>, <nps_public_addr>, <npc_bridge_addr>, <public_client_addr>, <echo_target_addr>, and <unknown_loopback_addr>. Public payload is redacted and not used as a target address. Gate 6B-2 remains unsafe until target metadata and close behavior are reviewed together.",
		Unknowns: []string{
			"exact opcode byte positions",
			"exact stream/correlation id byte positions",
			"exact payload length field byte positions",
			"exact close/reset/EOF semantics",
			"whether observed target metadata is sufficient to construct safe minimal TCP target open",
		},
	}
}

func uniqueLabels(frames []observeFixtureFrame) []string {
	seen := map[string]struct{}{}
	for _, frame := range frames {
		seen[frame.ObservedLabel] = struct{}{}
	}
	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	return labels
}

func candidateByProbe(note string, frames []observeFixtureFrame) []string {
	probes := map[int]struct{}{}
	for _, frame := range frames {
		if frame.ProbeID > 0 {
			probes[frame.ProbeID] = struct{}{}
		}
	}
	return []string{fmt.Sprintf("%s; observed_probe_count=%d", note, len(probes))}
}

func (r *observeRecorder) apiSummary(state string, shape npsAPIShape) {
	r.note(state, fmt.Sprintf("status_present=%t status=%d msg_present=%t id_present=%t client_id_present=%t msg=%s",
		shape.StatusPresent, shape.Status, shape.MsgPresent, shape.IDPresent, shape.ClientIDPresent, shape.Msg))
}

func (r *observeRecorder) legacyReadiness(readiness legacyBridgeReadiness) {
	r.note("legacy_bridge_readiness", fmt.Sprintf("legacy_main_ready=%t legacy_chan_ready=%t main_conn=%d chan_conn=%d bridge_connection_count=%d chan_post_handshake_seen=%t",
		readiness.MainReady, readiness.ChanReady, readiness.MainConn, readiness.ChanConn, readiness.ConnectionCount, readiness.ChanPostHandshakeSeen))
}

func (r *observeRecorder) outputSummary(state, text string) {
	if text == "" {
		r.note(state, "present=false bytes=0")
		return
	}
	r.note(state, fmt.Sprintf("present=true bytes=%d preview=%s", len(text), asciiPreview([]byte(r.redact(text)), 240)))
}

func (r *observeRecorder) fileTailSummary(state, path string, limit int) {
	data, err := readFileTail(path, limit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.note(state, "present=false")
			return
		}
		r.note(state, fmt.Sprintf("present=unknown err=%s", sanitizeErr(err)))
		return
	}
	if len(data) == 0 {
		r.note(state, "present=true bytes=0")
		return
	}
	r.note(state, fmt.Sprintf("present=true tail_bytes=%d preview=%s", len(data), asciiPreview([]byte(r.redact(string(data))), 240)))
}

func readFileTail(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	offset := int64(0)
	if size > int64(limit) {
		offset = size - int64(limit)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, int64(limit)))
}

type frameSummary struct {
	state   string
	shape   string
	preview string
	hex32   bool
	notes   string
}

func (r *observeRecorder) frameSummary(role string, data []byte) frameSummary {
	redacted := r.redactBytes(data)
	shape := "raw"
	state := "unknown"
	notes := "fields_unknown"
	if isPayloadRole(role) {
		state = "tcp_payload"
		shape = "payload_bytes"
		redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		notes = "payload_redacted"
	} else if bytes.HasPrefix(data, []byte("TST")) {
		state = "stock_handshake_preface_or_ack"
		shape = "TST + optional uint32_le strings"
		notes = "observed"
	} else if isObservedAuthFrame(data) {
		state = "stock_auth_material"
		shape = "hex32_token + 4_byte_connection_type"
		notes = "observed_token_redacted"
	} else if len(data) >= 4 {
		shape = "possible_uint32_le_prefix"
		if !looksTextual(data) {
			redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		}
	}
	return frameSummary{
		state:   state,
		shape:   shape,
		preview: asciiPreview(redacted, 96),
		hex32:   hex32Pattern.Match(redacted),
		notes:   notes,
	}
}

func (r *observeRecorder) chanFrameSummary(data []byte) frameSummary {
	redacted := r.redactBytes(data)
	state := "chan_post_handshake_unknown"
	shape := "raw"
	notes := "fields_unknown"
	if len(data) == 5 || len(data) == 7 || len(data) == 13 {
		state = "chan_possible_ping"
		shape = "short_control_frame"
		redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		notes = "conservative_label"
	} else if len(data) >= 26 && len(data) <= 64 {
		state = "chan_possible_stream_open"
		shape = "possible_control_or_metadata_frame"
		redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		notes = "conservative_label"
	} else if len(data) > 64 {
		state = "chan_possible_data_frame"
		shape = "possible_data_frame"
		redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		notes = "conservative_label"
	}
	if bytes.Contains(data, []byte("kavern-observe-echo")) {
		state = "chan_payload_related"
		shape = "payload_related_bytes"
		redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		notes = "payload_marker_redacted"
	}
	if len(data) >= 4 && shape == "raw" {
		shape = "possible_uint32_le_prefix"
		if !looksTextual(data) {
			redacted = []byte(fmt.Sprintf("<payload:%d>", len(data)))
		}
	}
	return frameSummary{
		state:   state,
		shape:   shape,
		preview: asciiPreview(redacted, 96),
		hex32:   hex32Pattern.Match(redacted),
		notes:   notes,
	}
}

func isPayloadRole(role string) bool {
	return role == "public_tcp" || role == "target_tcp"
}

func looksTextual(data []byte) bool {
	for _, c := range data {
		if c == 0 {
			return false
		}
		if c < 32 || c > 126 {
			return false
		}
	}
	return len(data) > 0
}

func looksPrintableUTF8(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if r == '\n' || r == '\r' || r == '\t' {
			data = data[size:]
			continue
		}
		if r < 32 || r == 127 {
			return false
		}
		data = data[size:]
	}
	return true
}

func (r *observeRecorder) redactBytes(data []byte) []byte {
	return []byte(r.redact(string(data)))
}

func (r *observeRecorder) redact(s string) string {
	out := s
	for _, value := range r.redactValues {
		if value != "" {
			out = strings.ReplaceAll(out, value, "<redacted>")
		}
	}
	out = hex32Pattern.ReplaceAllString(out, "<hex32>")
	return out
}

func asciiPreview(data []byte, max int) string {
	if len(data) > max {
		data = data[:max]
	}
	var b strings.Builder
	for _, c := range data {
		if c >= 32 && c <= 126 {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

func sanitizeProcessStatus(err error) string {
	if err == nil {
		return "exited_ok"
	}
	if strings.Contains(err.Error(), "signal: killed") {
		return "killed_by_test_context"
	}
	return "exited_nonzero"
}

func sanitizeErr(err error, extraRedactValues ...string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, value := range extraRedactValues {
		if value != "" {
			msg = strings.ReplaceAll(msg, value, "<redacted>")
		}
	}
	msg = hex32Pattern.ReplaceAllString(msg, "<hex32>")
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

func formatSHA256ForLog(sum string) string {
	if len(sum) != 64 {
		return sum
	}
	return sum[:16] + "-" + sum[16:32] + "-" + sum[32:48] + "-" + sum[48:]
}

func requireExecutable(t *testing.T, path, label string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%s basename=%s is not accessible: %v", label, filepath.Base(path), err)
	}
	if info.IsDir() {
		t.Fatalf("%s basename=%s is a directory, want executable file", label, filepath.Base(path))
	}
	if info.Mode()&0111 == 0 {
		t.Fatalf("%s basename=%s is not executable", label, filepath.Base(path))
	}
}

var _ io.Reader = (*observedConn)(nil)
