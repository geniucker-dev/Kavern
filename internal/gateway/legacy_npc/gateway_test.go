package legacy_npc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func TestMainHandshakeRegistersLegacySessionAndDisconnectDetaches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	client, done := serveStockPipe(t, ctx, gateway, token, connTypeMain)

	current := waitCurrent(t, ctx, manager, "device-1")
	if current.Protocol() != domain.AgentProtocolLegacyNPC {
		t.Fatalf("Protocol() = %q, want legacy_npc", current.Protocol())
	}
	if _, err := current.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrLegacyDataNotImplemented) {
		t.Fatalf("OpenStream() error = %v, want ErrLegacyDataNotImplemented", err)
	}

	_ = client.Close()
	waitDone(t, ctx, done, nil)
	waitNoCurrent(t, ctx, manager, "device-1")
}

func TestInvalidUnknownDisabledAndUnsupportedHandshakeFail(t *testing.T) {
	ctx := context.Background()
	gateway, _, token := newGatewayFixture(t, true)
	tests := []struct {
		name  string
		token string
	}{
		{name: "non_hex", token: strings.Repeat("z", 32)},
		{name: "uppercase", token: strings.ToUpper(token)},
		{name: "whitespace", token: strings.Repeat("a", 31) + " "},
		{name: "separator", token: strings.Repeat("a", 31) + "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, done := beginStockHandshake(t, ctx, gateway)
			defer client.Close()
			if outcome := sendStockTokenAndReadOutcome(t, client, tt.token); outcome != "vkey" {
				t.Fatalf("authentication outcome = %q, want vkey", outcome)
			}
			waitDone(t, ctx, done, ErrInvalidHandshake)
		})
	}

	client, done := beginStockHandshake(t, ctx, gateway)
	if outcome := sendStockTokenAndReadOutcome(t, client, token); outcome != "sucs" {
		t.Fatalf("authentication outcome = %q, want sucs", outcome)
	}
	if _, err := client.Write([]byte("file")); err != nil {
		t.Fatalf("write unsupported role: %v", err)
	}
	waitDone(t, ctx, done, ErrUnsupportedConnection)
	_ = client.Close()

	unknownGateway, _, _ := newGatewayFixture(t, true)
	client, done = beginStockHandshake(t, ctx, unknownGateway)
	if outcome := sendStockTokenAndReadOutcome(t, client, strings.Repeat("0", 32)); outcome != "vkey" {
		t.Fatalf("unknown authentication outcome = %q, want vkey", outcome)
	}
	waitDone(t, ctx, done, ErrInvalidHandshake)
	_ = client.Close()

	disabledGateway, _, disabledToken := newGatewayFixture(t, false)
	client, done = beginStockHandshake(t, ctx, disabledGateway)
	if outcome := sendStockTokenAndReadOutcome(t, client, disabledToken); outcome != "vkey" {
		t.Fatalf("disabled authentication outcome = %q, want vkey", outcome)
	}
	waitDone(t, ctx, done, ErrInvalidHandshake)
	_ = client.Close()
}

func TestAuthenticationFailureDoesNotReadRole(t *testing.T) {
	ctx := context.Background()
	gateway, _, _ := newGatewayFixture(t, true)
	client, done := beginStockHandshake(t, ctx, gateway)
	defer client.Close()

	if outcome := sendStockTokenAndReadOutcome(t, client, strings.Repeat("0", 32)); outcome != "vkey" {
		t.Fatalf("authentication outcome = %q, want vkey", outcome)
	}
	// The server must return before any role is sent. A server-side role read would
	// otherwise keep this test blocked until the handshake deadline.
	waitDone(t, ctx, done, ErrInvalidHandshake)
}

func TestStrictLegacyWireToken(t *testing.T) {
	valid := []byte("0123456789abcdef0123456789abcdef")
	if !isStrictLegacyWireToken(valid) {
		t.Fatal("valid lowercase token rejected")
	}
	for _, value := range [][]byte{
		[]byte("0123456789ABCDEF0123456789ABCDEF"),
		[]byte("0123456789abcdef0123456789abcde "),
		[]byte("0123456789abcdef0123456789abcde-"),
		[]byte("0123456789abcdef0123456789abcdef0"),
	} {
		if isStrictLegacyWireToken(value) {
			t.Fatalf("malformed token accepted: %q", value)
		}
	}
}

func TestHandshakeRejectsOversizedInput(t *testing.T) {
	ctx := context.Background()
	gateway, _, _ := newGatewayFixture(t, true)
	gateway.maxHandshakeBytes = len("0.26.34") - 1
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- gateway.ServeConn(ctx, server)
	}()
	payload := append([]byte("TST"), stockString("0.26.0")...)
	payload = append(payload, stockString("0.26.34")...)
	_, _ = client.Write(payload)
	waitDone(t, ctx, done, ErrInvalidHandshake)
	_ = client.Close()
}

func TestHandshakeRejectsPinnedVersionMismatch(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		coreVersion   string
		clientVersion string
	}{
		{name: "core", coreVersion: "0.26.1", clientVersion: legacyClientVersion},
		{name: "client", coreVersion: legacyCoreVersion, clientVersion: "0.26.35"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway, _, _ := newGatewayFixture(t, true)
			client, server := net.Pipe()
			done := make(chan error, 1)
			go func() {
				done <- gateway.ServeConn(ctx, server)
			}()
			payload := append([]byte("TST"), stockString(tt.coreVersion)...)
			payload = append(payload, stockString(tt.clientVersion)...)
			_, _ = client.Write(payload)
			waitDone(t, ctx, done, ErrInvalidHandshake)
			_ = client.Close()
		})
	}
}

func TestHandshakeRejectsMalformedVersionLengths(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "negative signed length",
			payload: append([]byte("TST"), stockSignedLength(-1)...),
		},
		{
			name:    "length above maximum",
			payload: append([]byte("TST"), stockSignedLength(defaultMaxHandshakeBytes+1)...),
		},
		{
			name: "declared body shorter than length",
			payload: append(
				append([]byte("TST"), stockSignedLength(int32(len(legacyCoreVersion)))...),
				[]byte("0.26")...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway, _, _ := newGatewayFixture(t, true)
			client, server := net.Pipe()
			done := make(chan error, 1)
			go func() {
				done <- gateway.ServeConn(context.Background(), server)
			}()
			_, _ = client.Write(tt.payload)
			_ = client.Close()
			waitDone(t, context.Background(), done, ErrInvalidHandshake)
		})
	}
}

func TestDuplicateMainReplacesOldSessionAndClosesChildChan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)

	firstClient, firstDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	first := waitCurrent(t, ctx, manager, "device-1")

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	select {
	case err := <-chanDone:
		t.Fatalf("chan exited early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	secondClient, secondDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	_ = waitCurrentDifferent(t, ctx, manager, "device-1", first.ID())
	select {
	case <-first.Done():
	case <-ctx.Done():
		t.Fatalf("old session did not close: %v", ctx.Err())
	}
	waitDone(t, ctx, firstDone, nil)
	waitDone(t, ctx, chanDone, nil)

	_ = firstClient.Close()
	_ = chanClient.Close()
	_ = secondClient.Close()
	waitDone(t, ctx, secondDone, nil)
}

func TestChanRequiresCurrentLegacyMainAndDoesNotOfflineDevice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)

	_, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	waitDone(t, ctx, chanDone, session.ErrNoCurrentSession)

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	mainSession := waitCurrent(t, ctx, manager, "device-1")
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	current := waitCurrent(t, ctx, manager, "device-1")
	if current.ID() != mainSession.ID() {
		t.Fatalf("closing chan changed current session")
	}

	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
	waitNoCurrent(t, ctx, manager, "device-1")
}

func TestErrorsDoNotIncludeSecretMaterial(t *testing.T) {
	secret := []byte("server-secret")
	gateway, err := New(Config{
		ServerSecret: secret,
		Store:        store.NewMemoryStore(),
		Sessions:     session.NewManager(),
	})
	if err != nil {
		t.Fatal(err)
	}
	vkey := "do-not-leak-vkey"
	token, err := security.LegacyWireTokenFromVKey(vkey)
	if err != nil {
		t.Fatal(err)
	}
	lookupKey, err := security.LegacyLookupKey(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	client, done := beginStockHandshake(t, context.Background(), gateway)
	if outcome := sendStockTokenAndReadOutcome(t, client, token); outcome != "vkey" {
		t.Fatalf("authentication outcome = %q, want vkey", outcome)
	}
	err = <-done
	_ = client.Close()
	if err == nil {
		t.Fatal("ServeConn() succeeded, want error")
	}
	for _, forbidden := range []string{vkey, token, strings.ToUpper(token), lookupKey} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked secret material %q in %q", forbidden, err.Error())
		}
	}
}

func TestProductionDoesNotImportForbiddenNPSPackages(t *testing.T) {
	root := repositoryRoot(t)
	forbidden := []string{"ehang.io/nps", "github.com/yisier/nps", "github.com/yisier/nps-mux"}

	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, module := range forbidden {
		if strings.Contains(string(goMod), module) {
			t.Fatalf("go.mod references forbidden nps module %q", module)
		}
	}

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || strings.HasPrefix(entry.Name(), ".kavern-") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range parsed.Imports {
			pathValue, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			for _, module := range forbidden {
				if pathValue == module || strings.HasPrefix(pathValue, module+"/") {
					return fmt.Errorf("%s imports forbidden nps module %q", path, pathValue)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func newGatewayFixture(t *testing.T, enabled bool) (*Gateway, session.SessionManager, string) {
	t.Helper()
	ctx := context.Background()
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
	if !enabled {
		if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Name: "device", Enabled: false}); err != nil {
			t.Fatal(err)
		}
	}
	wireToken, err := security.LegacyWireTokenFromVKey(issued.VKey)
	if err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager()
	var seq int
	gateway, err := New(Config{
		ServerSecret: []byte("server-secret"),
		Store:        st,
		Sessions:     manager,
		NewSessionID: func() (domain.SessionID, error) {
			seq++
			return domain.SessionID(fmt.Sprintf("legacy-session-%d", seq)), nil
		},
		NewAuthChallenge: func() ([]byte, error) {
			return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, manager, wireToken
}

func serveStockPipe(t *testing.T, ctx context.Context, gateway *Gateway, token, connType string) (net.Conn, <-chan error) {
	t.Helper()
	client, done := beginStockHandshake(t, ctx, gateway)
	if outcome := sendStockTokenAndReadOutcome(t, client, token); outcome != "sucs" {
		t.Fatalf("stock authentication outcome = %q, want sucs", outcome)
	}
	if len(connType) != 4 {
		t.Fatalf("stock connection type fixture has %d bytes, want 4", len(connType))
	}
	if _, err := client.Write([]byte(connType)); err != nil {
		t.Fatalf("write stock connection type: %v", err)
	}
	return client, done
}

func beginStockHandshake(t *testing.T, ctx context.Context, gateway *Gateway) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- gateway.ServeConn(ctx, server)
	}()
	writeStockPreface(t, client)
	readStockServerAuthField(t, client)
	return client, done
}

func sendStockTokenAndReadOutcome(t *testing.T, client net.Conn, token string) string {
	t.Helper()
	if len(token) != 32 {
		t.Fatalf("stock token fixture has %d bytes, want 32", len(token))
	}
	if _, err := client.Write([]byte(token)); err != nil {
		t.Fatalf("write stock token: %v", err)
	}
	var outcome [4]byte
	if _, err := io.ReadFull(client, outcome[:]); err != nil {
		t.Fatalf("read stock authentication outcome: %v", err)
	}
	return string(outcome[:])
}

func writeStockPreface(t *testing.T, conn net.Conn) {
	t.Helper()
	payload := append([]byte("TST"), stockString("0.26.0")...)
	payload = append(payload, stockString("0.26.34")...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write stock preface: %v", err)
	}
}

func readStockServerAuthField(t *testing.T, conn net.Conn) {
	t.Helper()
	var field [32]byte
	if _, err := io.ReadFull(conn, field[:]); err != nil {
		t.Fatalf("read server auth field: %v", err)
	}
	const want = "89a4f3fc3c89257d6f712de6964bda8e"
	if string(field[:]) != want {
		t.Fatalf("server version field = %q, want %q", string(field[:]), want)
	}
}

func stockString(value string) []byte {
	payload := stockSignedLength(int32(len(value)))
	payload = append(payload, value...)
	return payload
}

func stockSignedLength(length int32) []byte {
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(length))
	return append([]byte{}, prefix[:]...)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository go.mod")
		}
		dir = parent
	}
}

func waitCurrent(t *testing.T, ctx context.Context, manager session.SessionManager, deviceID domain.DeviceID) session.AgentSession {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, err := manager.CurrentForDevice(ctx, deviceID)
		if err == nil {
			return current
		}
		time.Sleep(10 * time.Millisecond)
	}
	current, err := manager.CurrentForDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	return current
}

func waitCurrentDifferent(t *testing.T, ctx context.Context, manager session.SessionManager, deviceID domain.DeviceID, oldID domain.SessionID) session.AgentSession {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, err := manager.CurrentForDevice(ctx, deviceID)
		if err == nil && current.ID() != oldID {
			return current
		}
		time.Sleep(10 * time.Millisecond)
	}
	current, err := manager.CurrentForDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	if current.ID() == oldID {
		t.Fatalf("duplicate main did not replace session")
	}
	return current
}

func waitNoCurrent(t *testing.T, ctx context.Context, manager session.SessionManager, deviceID domain.DeviceID) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, err := manager.CurrentForDevice(ctx, deviceID)
		if errors.Is(err, session.ErrNoCurrentSession) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err := manager.CurrentForDevice(ctx, deviceID)
	if !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("CurrentForDevice() error = %v, want ErrNoCurrentSession", err)
	}
}

func waitDone(t *testing.T, ctx context.Context, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if want == nil {
			if err != nil {
				t.Fatalf("ServeConn() error = %v", err)
			}
			return
		}
		if !errors.Is(err, want) {
			t.Fatalf("ServeConn() error = %v, want %v", err, want)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for ServeConn(): %v", ctx.Err())
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ServeConn()")
	}
}
