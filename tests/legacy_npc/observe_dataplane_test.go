//go:build legacy_npc_integration && legacy_npc_observe

package legacy_npc

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	gateway "github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

const (
	observeFrameLimit = 4 * 1024
	observeTotalLimit = 64 * 1024
)

var hex32Pattern = regexp.MustCompile(`[0-9a-fA-F]{32}`)

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
	recorder.note("npc_bin", fmt.Sprintf("basename=%s sha256=%s", filepath.Base(npcBin), formatSHA256ForLog(sha256File(t, npcBin))))
	recorder.note("nps_bin", fmt.Sprintf("basename=%s sha256=%s", filepath.Base(npsBin), formatSHA256ForLog(sha256File(t, npsBin))))

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
	if err := npsCmd.Start(); err != nil {
		t.Fatalf("start stock nps basename=%s: %v", filepath.Base(npsBin), err)
	}
	recorder.note("nps_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(runtime.npsPath), npsCmd.Process != nil))
	npsDone := make(chan error, 1)
	go func() {
		npsDone <- npsCmd.Wait()
	}()
	defer func() {
		stopNPS()
		waitObservedProcess(t, "nps", npsCmd, npsDone, recorder)
	}()

	api := newStockNPSAPI(runtime.webAddr, secrets.authKey)
	if err := api.waitReady(ctx); err != nil {
		recorder.readiness("Out of scope: stock nps did not expose the documented Web API gettime endpoint from loopback temp runtime.")
		t.Fatalf("wait for stock nps Web API: %v", err)
	}
	clientID, err := api.addClient(ctx, vkey)
	if err != nil {
		recorder.readiness("Out of scope: stock nps Web API client setup failed; sanitized error indicates docs/runtime mismatch.")
		t.Fatalf("stock nps client setup failed: %v", sanitizeErr(err, secrets.redactValues()...))
	}
	recorder.note("nps_client_added", fmt.Sprintf("id_present=%t", clientID != ""))
	if err := api.addTCPTunnel(ctx, clientID, runtime.publicPort, topology.targetProxyAddr()); err != nil {
		recorder.readiness("Out of scope: stock nps Web API tunnel setup failed; sanitized error indicates docs/runtime mismatch.")
		t.Fatalf("stock nps tcp tunnel setup failed: %v", sanitizeErr(err, secrets.redactValues()...))
	}
	recorder.note("nps_tunnel_added", "type=tcp public=loopback target=target_proxy")

	npcCtx, stopNPC := context.WithCancel(ctx)
	defer stopNPC()
	npcCmd := exec.CommandContext(npcCtx, npcBin, "-server="+topology.npcServerAddr(), "-vkey="+vkey)
	if err := npcCmd.Start(); err != nil {
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	recorder.note("npc_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(npcBin), npcCmd.Process != nil))
	npcDone := make(chan error, 1)
	go func() {
		npcDone <- npcCmd.Wait()
	}()
	defer func() {
		stopNPC()
		waitObservedProcess(t, "npc", npcCmd, npcDone, recorder)
	}()

	if err := observeOracleEcho(ctx, topology.publicClientAddr()); err != nil {
		recorder.readiness("Insufficient for Gate 6B: stock_nps_oracle did not complete one local TCP echo through stock nps/npc; use sanitized transcript to identify the missing black-box setup or protocol state.")
		t.Fatalf("stock_nps_oracle echo failed: %v", err)
	}
	recorder.readiness("Sufficient only for review if the sanitized transcript identifies stream open, correlation, metadata, data, close/reset, heartbeat, and target-selection behavior. Do not implement Gate 6B from this pass unless those fields are clear.")
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
	return stockNPSRuntime{dir: runtimeDir, npsPath: npsPath, webAddr: webAddr, publicPort: publicPort}
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
	base    string
	authKey string
	http    *http.Client
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
	return decodeLimitedJSON(res.Body, out)
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
}

func startObserveProxy(t *testing.T, ctx context.Context, recorder *observeRecorder, role, upstream string) *observeProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &observeProxy{listener: l, role: role, upstream: upstream, recorder: recorder, cancel: cancel}
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
		p.recorder.note("proxy_connection", fmt.Sprintf("role=%s conn=%d upstream=loopback", p.role, id))
		go p.handle(ctx, id, downstream)
	}
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
		copyObserved(ctx, p.recorder, id, p.role, roleDirection(p.role, true), upstream, downstream)
		done <- struct{}{}
	}()
	go func() {
		copyObserved(ctx, p.recorder, id, p.role, roleDirection(p.role, false), downstream, upstream)
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

func copyObserved(ctx context.Context, recorder *observeRecorder, connID int, role, direction string, dst, src net.Conn) {
	buf := make([]byte, 4096)
	total := 0
	for {
		_ = src.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := src.Read(buf)
		if n > 0 {
			total += n
			recorder.frame(connID, role, direction, total, buf[:n])
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

func observeOracleEcho(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := []byte("kavern-observe-echo")
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
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
	return nil
}

func waitObservedProcess(t *testing.T, label string, cmd *exec.Cmd, done <-chan error, recorder *observeRecorder) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	select {
	case err := <-done:
		recorder.note(label+"_exit", fmt.Sprintf("status=%s", sanitizeProcessStatus(err)))
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		recorder.note(label+"_exit", "status=killed_after_timeout")
	}
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
	t            *testing.T
	mode         string
	redactValues []string
	mu           sync.Mutex
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
	return &observeRecorder{t: t, mode: mode, redactValues: values}
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

func (r *observeRecorder) note(state, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.t.Logf("mode=%s state=%s notes=%s", r.mode, state, r.redact(msg))
}

func (r *observeRecorder) readiness(msg string) {
	r.note("readiness", msg)
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
