package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func ownedLegacyFixture(t *testing.T) (*Gateway, *session.Manager, *store.ConfigOwner, string, []byte) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()
	key := bytes.Repeat([]byte{7}, 32)
	for _, e := range []error{s.CreateUser(ctx, domain.User{ID: "user-1"}), s.CreateProject(ctx, domain.Project{ID: "project-1", UserID: "user-1"}), s.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}), s.CreateTunnel(ctx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:3101", TargetAddr: "127.0.0.1:3102", Enabled: true})} {
		if e != nil {
			t.Fatal(e)
		}
	}
	issued, e := s.IssueLegacyCredential(ctx, "device-1", key)
	if e != nil {
		t.Fatal(e)
	}
	token, e := security.LegacyWireTokenFromVKey(issued.VKey)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if e = s.SaveState(path, key); e != nil {
		t.Fatal(e)
	}
	owner, e := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = owner.Close() })
	manager := session.NewManager()
	g, e := New(Config{ServerSecret: key, Store: owner, Sessions: manager})
	if e != nil {
		t.Fatal(e)
	}
	return g, manager, owner, token, key
}
func rotateOwned(t *testing.T, o *store.ConfigOwner, key []byte) {
	t.Helper()
	ctx := context.Background()
	w, e := o.ManagementWindow(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c, e := o.DeviceConfiguration(ctx, "device-1")
	if e != nil {
		t.Fatal(e)
	}
	_, e = o.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "rotate", Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: c.Revision, CredentialKind: domain.CredentialKindLegacyNPC}, key)
	if e != nil {
		t.Fatal(e)
	}
}
func TestOwnedLegacyRotationJoinsMainAndChan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	g, manager, o, token, key := ownedLegacyFixture(t)
	main, mainDone := serveStockPipe(t, ctx, g, token, connTypeMain)
	defer main.Close()
	current := waitCurrent(t, ctx, manager, "device-1")
	chanPeer, chanDone := serveStockPipe(t, ctx, g, token, connTypeChan)
	defer chanPeer.Close()
	initial := readPeerFrame(t, chanPeer)
	writePeerFrame(t, chanPeer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: initial.Content})
	rotateOwned(t, o, key)
	waitDone(t, ctx, mainDone, nil)
	waitDone(t, ctx, chanDone, nil)
	waitNoCurrent(t, ctx, manager, "device-1")
	select {
	case <-current.Done():
	default:
		t.Fatal("session not joined")
	}
	assertGatewayRuntimeMapEmpty(t, g)
	client, done := beginStockHandshake(t, ctx, g)
	defer client.Close()
	if sendStockTokenAndReadOutcome(t, client, token) != "vkey" {
		t.Fatal("rotated token accepted")
	}
	waitDone(t, ctx, done, ErrInvalidHandshake)
}
func TestOwnedLegacyCredentialChangedBeforeRoleCannotAttach(t *testing.T) {
	for _, role := range []string{connTypeMain, connTypeChan} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			g, manager, o, token, key := ownedLegacyFixture(t)
			client, done := beginStockHandshake(t, ctx, g)
			defer client.Close()
			if sendStockTokenAndReadOutcome(t, client, token) != "sucs" {
				t.Fatal("initial auth failed")
			}
			rotateOwned(t, o, key)
			if _, e := client.Write([]byte(role)); e != nil {
				t.Fatal(e)
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("late role attached")
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			waitNoCurrent(t, ctx, manager, "device-1")
			assertGatewayRuntimeMapEmpty(t, g)
		})
	}
}
func TestOwnedLegacyPendingMainRevokedBeforeTransition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	g, manager, o, token, key := ownedLegacyFixture(t)
	holding := g.acquireRuntime("device-1", legacyRuntimeLeaseChan)
	runtime := holding.Runtime()
	runtime.mainTransitionMu.Lock()
	client, done := serveStockPipe(t, ctx, g, token, connTypeMain)
	defer client.Close()
	waitPendingMainTransitions(t, ctx, runtime, 1)
	w, e := o.ManagementWindow(ctx)
	if e != nil {
		t.Fatal(e)
	}
	changed := o.ChangeSignal()
	rotated := make(chan error, 1)
	go func() {
		_, e := o.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "pending-rotate", Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: 1, CredentialKind: domain.CredentialKindLegacyNPC}, key)
		rotated <- e
	}()
	select {
	case <-changed:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Revocation closes the pending main socket even while transition serialization is held.
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = client.Read(b[:]); e == nil {
		t.Fatal("pending socket retained")
	}
	runtime.mainTransitionMu.Unlock()
	select {
	case e = <-done:
		if e != nil && !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if e = <-rotated; e != nil {
		t.Fatal(e)
	}
	waitNoCurrent(t, ctx, manager, "device-1")
	if e = holding.Release(); e != nil {
		t.Fatal(e)
	}
	assertGatewayRuntimeMapEmpty(t, g)
}

type delayedLegacyPublication struct {
	*store.ConfigOwner
	reached, release chan struct{}
}

func (d *delayedLegacyPublication) WithLegacyPublication(ctx context.Context, id domain.DeviceID, key string, publish func() error) error {
	close(d.reached)
	<-d.release
	return d.ConfigOwner.WithLegacyPublication(ctx, id, key, publish)
}
func TestOwnedLegacyFinalAttachmentRechecksCredential(t *testing.T) {
	for _, role := range []string{connTypeMain, connTypeChan} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			g, manager, o, token, key := ownedLegacyFixture(t)
			delayed := &delayedLegacyPublication{ConfigOwner: o, reached: make(chan struct{}), release: make(chan struct{})}
			g.store = delayed
			client, done := serveStockPipe(t, ctx, g, token, role)
			defer client.Close()
			select {
			case <-delayed.reached:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			w, e := o.ManagementWindow(ctx)
			if e != nil {
				t.Fatal(e)
			}
			change := o.ChangeSignal()
			result := make(chan error, 1)
			go func() {
				_, e := o.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "late-attach-rotate", Kind: "rotate_credential", DeviceID: "device-1", ExpectedRevision: 1, CredentialKind: domain.CredentialKindLegacyNPC}, key)
				result <- e
			}()
			select {
			case <-change:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			close(delayed.release)
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("late attachment did not stop")
			}
			if e = <-result; e != nil {
				t.Fatal(e)
			}
			waitNoCurrent(t, ctx, manager, "device-1")
			assertGatewayRuntimeMapEmpty(t, g)
		})
	}
}
func TestOwnedLegacyDeviceCascadeJoinsMainAndChan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	g, manager, o, token, _ := ownedLegacyFixture(t)
	main, mainDone := serveStockPipe(t, ctx, g, token, connTypeMain)
	defer main.Close()
	waitCurrent(t, ctx, manager, "device-1")
	chanPeer, chanDone := serveStockPipe(t, ctx, g, token, connTypeChan)
	defer chanPeer.Close()
	initial := readPeerFrame(t, chanPeer)
	writePeerFrame(t, chanPeer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: initial.Content})
	w, e := o.ManagementWindow(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = o.ApplyMutation(ctx, store.Mutation{Window: w, OperationID: "cascade", Kind: "delete_device", DeviceID: "device-1", ExpectedRevision: 1, Cascade: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	waitDone(t, ctx, mainDone, nil)
	waitDone(t, ctx, chanDone, nil)
	waitNoCurrent(t, ctx, manager, "device-1")
	assertGatewayRuntimeMapEmpty(t, g)
}
