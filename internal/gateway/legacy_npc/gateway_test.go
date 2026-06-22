package legacy_npc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
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
		name     string
		token    string
		connType string
		want     error
	}{
		{name: "malformed", token: strings.Repeat("z", 32), connType: connTypeMain, want: ErrInvalidHandshake},
		{name: "unsupported", token: token, connType: "file", want: ErrUnsupportedConnection},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, done := serveStockPipe(t, ctx, gateway, tt.token, tt.connType)
			waitDone(t, ctx, done, tt.want)
		})
	}

	unknownGateway, _, _ := newGatewayFixture(t, true)
	_, done := serveStockPipe(t, ctx, unknownGateway, strings.Repeat("0", 32), connTypeMain)
	waitDone(t, ctx, done, store.ErrNotFound)

	disabledGateway, _, disabledToken := newGatewayFixture(t, false)
	_, done = serveStockPipe(t, ctx, disabledGateway, disabledToken, connTypeMain)
	waitDone(t, ctx, done, store.ErrDisabledDevice)
}

func TestHandshakeRejectsOversizedInput(t *testing.T) {
	ctx := context.Background()
	gateway, _, token := newGatewayFixture(t, true)
	gateway.maxHandshakeBytes = len("0.26.34") - 1
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- gateway.ServeConn(ctx, server)
	}()
	payload := append([]byte("TST"), stockString("0.26.0")...)
	payload = append(payload, stockString("0.26.34")...)
	_, _ = client.Write(payload)
	_ = token
	waitDone(t, ctx, done, ErrInvalidHandshake)
	_ = client.Close()
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
	_, done := serveStockPipe(t, context.Background(), gateway, token, connTypeMain)
	err = <-done
	if err == nil {
		t.Fatal("ServeConn() succeeded, want error")
	}
	for _, forbidden := range []string{vkey, token, strings.ToUpper(token), lookupKey} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked secret material %q in %q", forbidden, err.Error())
		}
	}
}

func TestSyntheticLineParserRemainsTestHelperOnly(t *testing.T) {
	ctx := context.Background()
	gateway, _, token := newGatewayFixture(t, true)
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		_, err := gateway.readSyntheticLineHandshake(ctx, server)
		done <- err
	}()
	if _, err := client.Write([]byte("main " + token + "\n")); err != nil {
		t.Fatalf("write synthetic handshake: %v", err)
	}
	waitDone(t, ctx, done, nil)
}

func TestLegacyNpcPackageDoesNotImportYisierNPS(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", file, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", file, err)
		}
		for _, imp := range parsed.Imports {
			if strings.Contains(imp.Path.Value, "github.com/yisier/nps") {
				t.Fatalf("%s imports yisier/nps: %s", file, imp.Path.Value)
			}
		}
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
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- gateway.ServeConn(ctx, server)
	}()
	writeStockPreface(t, client)
	readStockServerChallenge(t, client)
	auth := []byte(token + connType)
	if len(auth) != 36 {
		t.Fatalf("stock auth fixture has %d bytes, want 36", len(auth))
	}
	if _, err := client.Write(auth); err != nil {
		t.Fatalf("write stock auth: %v", err)
	}
	return client, done
}

func writeStockPreface(t *testing.T, conn net.Conn) {
	t.Helper()
	payload := append([]byte("TST"), stockString("0.26.0")...)
	payload = append(payload, stockString("0.26.34")...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write stock preface: %v", err)
	}
}

func readStockServerChallenge(t *testing.T, conn net.Conn) {
	t.Helper()
	var ack [3]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		t.Fatalf("read stock ack: %v", err)
	}
	if string(ack[:]) != "TST" {
		t.Fatalf("stock ack = %q, want TST", string(ack[:]))
	}
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("read challenge prefix: %v", err)
	}
	size := binary.LittleEndian.Uint32(prefix[:])
	if size != 32 {
		t.Fatalf("challenge size = %d, want 32", size)
	}
	challenge := make([]byte, int(size))
	if _, err := io.ReadFull(conn, challenge); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
}

func stockString(value string) []byte {
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(value)))
	payload := append([]byte{}, prefix[:]...)
	payload = append(payload, value...)
	return payload
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
