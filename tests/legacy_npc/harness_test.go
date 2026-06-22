//go:build legacy_npc_integration

package legacy_npc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	gateway "github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

const pinnedNPSTag = "v0.26.34"

func TestStockNPCConnectsAndRegistersOnline(t *testing.T) {
	npcBin := requireNPCBin(t)
	sum := sha256File(t, npcBin)
	t.Logf("expecting yisier/nps %s stock npc; NPC_BIN basename=%s sha256=%s", pinnedNPSTag, filepath.Base(npcBin), sum)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st := store.NewMemoryStore()
	manager := session.NewManager()
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

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	gw, err := gateway.New(gateway.Config{
		ServerSecret: []byte("server-secret"),
		Store:        st,
		Sessions:     manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- gw.Serve(serveCtx, listener)
	}()

	cmdCtx, stopNPC := context.WithCancel(ctx)
	defer stopNPC()
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+listener.Addr().String(), "-vkey="+issued.VKey)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	t.Logf("stock npc process started: pid=%d basename=%s", cmd.Process.Pid, filepath.Base(npcBin))
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	current := waitCurrent(t, ctx, manager, "device-1")
	if current.Protocol() != domain.AgentProtocolLegacyNPC {
		t.Fatalf("current protocol = %q, want legacy_npc", current.Protocol())
	}
	t.Logf("gateway observed online legacy_npc session id_present=%t", current.ID() != "")

	stopNPC()
	select {
	case err := <-waitDone:
		t.Logf("stock npc process exited: %v", err)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("timeout waiting for stock npc process exit")
	}
	waitNoCurrent(t, ctx, manager, "device-1")
	stopServe()
	_ = listener.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("gateway Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for gateway Serve() exit")
	}
}

func requireNPCBin(t *testing.T) string {
	t.Helper()
	npcBin := os.Getenv("NPC_BIN")
	if npcBin == "" {
		t.Fatalf("NPC_BIN is required when running with -tags=legacy_npc_integration; use a stock npc binary downloaded from yisier/nps %s release assets", pinnedNPSTag)
	}
	info, err := os.Stat(npcBin)
	if err != nil {
		t.Fatalf("NPC_BIN basename=%s is not accessible: %v", filepath.Base(npcBin), err)
	}
	if info.IsDir() {
		t.Fatalf("NPC_BIN basename=%s is a directory, want executable file", filepath.Base(npcBin))
	}
	if info.Mode()&0111 == 0 {
		t.Fatalf("NPC_BIN basename=%s is not executable", filepath.Base(npcBin))
	}
	return npcBin
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open NPC_BIN basename=%s: %v", filepath.Base(path), err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash NPC_BIN basename=%s: %v", filepath.Base(path), err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func waitCurrent(t *testing.T, ctx context.Context, manager session.SessionManager, deviceID domain.DeviceID) session.AgentSession {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, err := manager.CurrentForDevice(ctx, deviceID)
		if err == nil {
			return current
		}
		if ctx.Err() != nil {
			t.Fatalf("timeout waiting for online session: %v", ctx.Err())
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for gateway online state for device=%s", deviceID)
	return nil
}

func waitNoCurrent(t *testing.T, ctx context.Context, manager session.SessionManager, deviceID domain.DeviceID) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, err := manager.CurrentForDevice(ctx, deviceID)
		if errors.Is(err, session.ErrNoCurrentSession) {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("timeout waiting for offline session: %v", ctx.Err())
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, err := manager.CurrentForDevice(ctx, deviceID)
	t.Fatalf("timeout waiting for offline state for device=%s, last_err=%v", deviceID, fmt.Sprint(err))
}
