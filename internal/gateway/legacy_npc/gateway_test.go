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
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"github.com/geniucker-dev/kavern/internal/testutil"
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
	if _, err := current.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrLegacyDataChannelUnavailable) {
		t.Fatalf("OpenStream() error = %v, want ErrLegacyDataChannelUnavailable", err)
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

func TestDuplicateMainReplacementPreservesDeviceChan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)

	firstClient, firstDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	first := waitCurrent(t, ctx, manager, "device-1")

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	initial := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: initial.Content})
	select {
	case err := <-chanDone:
		t.Fatalf("chan exited early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	firstLegacy := first.(*LegacyNpcSession)
	firstStreamDone := make(chan session.AgentStream, 1)
	firstStreamErr := make(chan error, 1)
	go func() {
		stream, err := firstLegacy.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		firstStreamDone <- stream
		firstStreamErr <- err
	}()
	firstOpen := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: firstOpen.StreamID})
	_ = readPeerFrame(t, chanClient)
	firstStream := <-firstStreamDone
	if err := <-firstStreamErr; err != nil {
		t.Fatalf("first OpenStream() error = %v", err)
	}

	secondClient, secondDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	second := waitCurrentDifferent(t, ctx, manager, "device-1", first.ID())
	select {
	case <-first.Done():
	case <-ctx.Done():
		t.Fatalf("old session did not close: %v", ctx.Err())
	}
	waitDone(t, ctx, firstDone, nil)
	select {
	case err := <-chanDone:
		t.Fatalf("device chan closed with replaced main: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := firstStream.Write([]byte("survives")); err != nil {
		t.Fatalf("returned stream did not survive main replacement: %v", err)
	}
	survivingData := readPeerFrame(t, chanClient)
	if survivingData.StreamID != firstOpen.StreamID || string(survivingData.Content) != "survives" {
		t.Fatalf("surviving stream frame = %#v", survivingData)
	}
	_ = firstStream.Close()
	_ = readPeerFrame(t, chanClient)

	secondLegacy := second.(*LegacyNpcSession)
	secondOpenDone := make(chan error, 1)
	go func() {
		stream, err := secondLegacy.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		secondOpenDone <- err
	}()
	secondOpen := readPeerFrame(t, chanClient)
	if secondOpen.Flag != FrameFlagStreamOpen {
		t.Fatalf("new main frame = %#v, want stream open", secondOpen)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: secondOpen.StreamID})
	metadata := readPeerFrame(t, chanClient)
	if metadata.Flag != FrameFlagDataFinal || metadata.StreamID != secondOpen.StreamID {
		t.Fatalf("new main metadata = %#v", metadata)
	}
	if err := <-secondOpenDone; err != nil {
		t.Fatalf("second OpenStream() error = %v", err)
	}
	_ = readPeerFrame(t, chanClient)

	_ = firstClient.Close()
	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = secondClient.Close()
	waitDone(t, ctx, secondDone, nil)
}

func TestChanRequiresCurrentLegacyMainAndDoesNotOfflineDevice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	gateway.handshakeTimeout = 25 * time.Millisecond

	_, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	waitDone(t, ctx, chanDone, ErrNoCurrentMainSession)
	gateway.handshakeTimeout = defaultHandshakeTimeout

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	mainSession := waitCurrent(t, ctx, manager, "device-1").(*LegacyNpcSession)
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	initial := readPeerFrame(t, chanClient)
	if initial.Flag != FrameFlagPing || initial.StreamID != -1 {
		t.Fatalf("first chan frame = %#v, want mux ping", initial)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: initial.Content})
	if _, _, err := mainSession.snapshotMux(); err != nil {
		t.Fatalf("snapshot installed mux error = %v", err)
	}
	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	current := waitCurrent(t, ctx, manager, "device-1")
	if current.ID() != mainSession.ID() {
		t.Fatalf("closing chan changed current session")
	}

	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
	waitNoCurrent(t, ctx, manager, "device-1")
}

func TestMainAttachChanWaitsForBlockedAttach(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, _, token := newGatewayFixture(t, true)
	manager := newRendezvousSessionManager(true, false)
	gateway.sessions = manager

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainClient.Close()
	select {
	case <-manager.attachEntered:
	case <-ctx.Done():
		t.Fatalf("main Attach was not reached: %v", ctx.Err())
	}

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	select {
	case err := <-chanDone:
		t.Fatalf("chan returned while main Attach was blocked: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(manager.attachRelease)
	if err := chanClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ping := readPeerFrame(t, chanClient)
	_ = chanClient.SetReadDeadline(time.Time{})
	if ping.Flag != FrameFlagPing || ping.StreamID != -1 {
		t.Fatalf("first chan frame = %#v, want initial ping", ping)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})
	current := waitCurrent(t, ctx, manager, "device-1")
	if _, ok := current.(*LegacyNpcSession); !ok {
		t.Fatalf("current session type = %T, want LegacyNpcSession", current)
	}

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestCrossProtocolKAPCurrentLegacyMainAttachChanOverlap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, _, token := newGatewayFixture(t, true)
	manager := newRendezvousSessionManager(true, false)
	if err := manager.inner.Attach(ctx, testutil.NewFakeSession("kap-current", "device-1")); err != nil {
		t.Fatal(err)
	}
	gateway.sessions = manager

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainClient.Close()
	select {
	case <-manager.attachEntered:
	case <-ctx.Done():
		t.Fatalf("legacy main did not reach blocked Attach: %v", ctx.Err())
	}
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})
	select {
	case err := <-chanDone:
		t.Fatalf("legacy chan rejected while KAPv1 was current: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(manager.attachRelease)
	current := waitCurrentDifferent(t, ctx, manager, "device-1", "kap-current")
	legacySession, ok := current.(*LegacyNpcSession)
	if !ok {
		t.Fatalf("current session type = %T, want LegacyNpcSession", current)
	}
	openDone := make(chan error, 1)
	go func() {
		stream, err := legacySession.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		openDone <- err
	}()
	open := readPeerFrame(t, chanClient)
	if open.Flag != FrameFlagStreamOpen {
		t.Fatalf("frame after legacy attach = %#v, want stream open", open)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	metadata := readPeerFrame(t, chanClient)
	if metadata.Flag != FrameFlagDataFinal || metadata.StreamID != open.StreamID {
		t.Fatalf("metadata frame = %#v", metadata)
	}
	if err := <-openDone; err != nil {
		t.Fatalf("OpenStream() after cross-protocol replacement: %v", err)
	}

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
}

func TestMainAttachPostPublicationChanUsesPendingMainInterest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, managerInterface, token := newGatewayFixture(t, true)
	gateway.handshakeTimeout = 20 * time.Millisecond
	manager := managerInterface.(*session.Manager)
	old := newBlockingCloseSession("kap-old", "device-1")
	if err := manager.Attach(ctx, old); err != nil {
		t.Fatal(err)
	}

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainClient.Close()
	select {
	case <-old.closeEntered:
	case <-ctx.Done():
		t.Fatalf("legacy Attach did not block after manager publication: %v", ctx.Err())
	}
	managerCurrent, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	legacyMain, ok := managerCurrent.(*LegacyNpcSession)
	if !ok {
		t.Fatalf("manager current type = %T, want LegacyNpcSession", managerCurrent)
	}

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})
	select {
	case err := <-chanDone:
		t.Fatalf("chan exited while a published main transition was pending: %v", err)
	case <-time.After(3 * gateway.handshakeTimeout):
	}

	close(old.closeRelease)
	openDone := make(chan error, 1)
	go func() {
		stream, err := legacyMain.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		openDone <- err
	}()
	open := readPeerFrame(t, chanClient)
	if open.Flag != FrameFlagStreamOpen {
		t.Fatalf("frame after Attach completion = %#v, want stream open", open)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	_ = readPeerFrame(t, chanClient)
	if err := <-openDone; err != nil {
		t.Fatalf("OpenStream() after blocked Attach = %v", err)
	}
	_ = readPeerFrame(t, chanClient)

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
}

func TestCanceledMainDuringBlockedAttachCannotOpenStream(t *testing.T) {
	ctx, cancelTest := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelTest()
	gateway, managerInterface, token := newGatewayFixture(t, true)
	manager := managerInterface.(*session.Manager)
	old := newBlockingCloseSession("kap-old", "device-1")
	if err := manager.Attach(ctx, old); err != nil {
		t.Fatal(err)
	}
	mainCtx, cancelMain := context.WithCancel(ctx)
	mainClient, mainDone := serveStockPipe(t, mainCtx, gateway, token, connTypeMain)
	defer mainClient.Close()
	select {
	case <-old.closeEntered:
	case <-ctx.Done():
		t.Fatalf("legacy Attach did not block after publication: %v", ctx.Err())
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	legacyMain := current.(*LegacyNpcSession)
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})

	cancelMain()
	select {
	case <-legacyMain.lifecycleCtx.Done():
	case <-ctx.Done():
		t.Fatalf("main lifecycle was not canceled: %v", ctx.Err())
	}
	if _, err := legacyMain.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrLegacySessionClosed) {
		t.Fatalf("OpenStream() after main cancellation = %v, want ErrLegacySessionClosed", err)
	}
	assertNoStreamOpenFrame(t, chanClient)
	close(old.closeRelease)
	waitDone(t, context.Background(), mainDone, context.Canceled)
	waitDone(t, ctx, chanDone, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestMainMonitorDisconnectedDuringBlockedAttachCannotOpenStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, managerInterface, token := newGatewayFixture(t, true)
	manager := managerInterface.(*session.Manager)
	old := newBlockingCloseSession("kap-old", "device-1")
	if err := manager.Attach(ctx, old); err != nil {
		t.Fatal(err)
	}
	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	select {
	case <-old.closeEntered:
	case <-ctx.Done():
		t.Fatalf("legacy Attach did not block after publication: %v", ctx.Err())
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	legacyMain := current.(*LegacyNpcSession)
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})

	_ = mainClient.Close()
	select {
	case <-legacyMain.lifecycleCtx.Done():
	case <-ctx.Done():
		t.Fatalf("main EOF did not cancel lifecycle: %v", ctx.Err())
	}
	if _, err := legacyMain.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrLegacySessionClosed) {
		t.Fatalf("OpenStream() after main EOF = %v, want ErrLegacySessionClosed", err)
	}
	assertNoStreamOpenFrame(t, chanClient)
	close(old.closeRelease)
	waitDone(t, ctx, mainDone, nil)
	waitDone(t, ctx, chanDone, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestDisconnectedQueuedMainDoesNotReplaceHealthyCurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	mainAClient, mainADone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainAClient.Close()
	mainA := waitCurrent(t, ctx, manager, "device-1").(*LegacyNpcSession)
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})

	runtime := mainA.runtime
	runtime.mainTransitionMu.Lock()
	mainBClient, mainBDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	waitPendingMainTransitions(t, ctx, runtime, 1)
	runtime.mu.Lock()
	notify := runtime.mainNotify
	runtime.mu.Unlock()
	_ = mainBClient.Close()
	select {
	case <-notify:
	case <-ctx.Done():
		t.Fatalf("queued main monitor did not report EOF: %v", ctx.Err())
	}
	runtime.mainTransitionMu.Unlock()
	waitDone(t, ctx, mainBDone, nil)
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil || current != mainA {
		t.Fatalf("manager current = (%T, %v), want healthy main A", current, err)
	}

	openDone := make(chan error, 1)
	go func() {
		stream, err := mainA.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		openDone <- err
	}()
	open := readPeerFrame(t, chanClient)
	if open.Flag != FrameFlagStreamOpen {
		t.Fatalf("healthy main frame = %#v, want stream open", open)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	_ = readPeerFrame(t, chanClient)
	if err := <-openDone; err != nil {
		t.Fatalf("healthy main lost mux after queued EOF: %v", err)
	}
	_ = readPeerFrame(t, chanClient)

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = mainAClient.Close()
	waitDone(t, ctx, mainADone, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestQueuedMainTransitionPreservesChanMuxAfterPredecessorFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, _, token := newGatewayFixture(t, true)
	manager := newSequentialAttachSessionManager()
	gateway.sessions = manager

	failedClient, failedDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer failedClient.Close()
	select {
	case <-manager.firstAttachEntered:
	case <-ctx.Done():
		t.Fatalf("first Attach was not reached: %v", ctx.Err())
	}
	gateway.runtimeMu.Lock()
	entry := gateway.runtimes["device-1"]
	gateway.runtimeMu.Unlock()
	if entry == nil {
		t.Fatal("runtime missing for first transition")
	}

	successClient, successDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer successClient.Close()
	waitPendingMainTransitions(t, ctx, entry.runtime, 2)
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})

	close(manager.firstAttachRelease)
	waitDone(t, ctx, failedDone, manager.firstAttachErr)
	current := waitCurrent(t, ctx, manager, "device-1")
	legacyMain, ok := current.(*LegacyNpcSession)
	if !ok {
		t.Fatalf("current session type = %T, want LegacyNpcSession", current)
	}
	select {
	case err := <-chanDone:
		t.Fatalf("failed predecessor closed successor chan mux: %v", err)
	default:
	}

	openDone := make(chan error, 1)
	go func() {
		stream, err := legacyMain.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		openDone <- err
	}()
	open := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	_ = readPeerFrame(t, chanClient)
	if err := <-openDone; err != nil {
		t.Fatalf("queued successor could not use retained mux: %v", err)
	}
	_ = readPeerFrame(t, chanClient)

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = successClient.Close()
	waitDone(t, ctx, successDone, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestSupersededLegacyMainIsNotPublishedAttached(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, managerInterface, token := newGatewayFixture(t, true)
	manager := managerInterface.(*session.Manager)
	old := newBlockingCloseSession("kap-old", "device-1")
	if err := manager.Attach(ctx, old); err != nil {
		t.Fatal(err)
	}

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainClient.Close()
	select {
	case <-old.closeEntered:
	case <-ctx.Done():
		t.Fatalf("legacy Attach did not block closing old session: %v", ctx.Err())
	}

	gateway.runtimeMu.Lock()
	entry := gateway.runtimes["device-1"]
	gateway.runtimeMu.Unlock()
	if entry == nil {
		t.Fatal("legacy runtime was not created")
	}
	runtime := entry.runtime
	runtime.mu.Lock()
	notify := runtime.mainNotify
	runtime.mu.Unlock()

	kapNext := testutil.NewFakeSession("kap-next", "device-1")
	attachDone := make(chan error, 1)
	go func() { attachDone <- manager.Attach(ctx, kapNext) }()
	select {
	case err := <-attachDone:
		if err != nil {
			t.Fatalf("attach replacement KAPv1 session: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("replacement KAPv1 Attach blocked: %v", ctx.Err())
	}
	close(old.closeRelease)
	waitDone(t, ctx, mainDone, errLegacyMainSuperseded)

	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil || current != kapNext {
		t.Fatalf("manager current = (%T, %v), want replacement KAPv1", current, err)
	}
	runtime.mu.Lock()
	attached := runtime.attachedMain
	pending := runtime.pendingMainTransitions
	runtime.mu.Unlock()
	if attached != nil {
		t.Fatalf("superseded legacy main published as attached: %s", attached.ID())
	}
	if pending != 0 {
		t.Fatalf("pending main transitions = %d, want zero", pending)
	}
	// mainNotify is a state-change hint. Supersession may rotate it, but the
	// authoritative attachedMain state above must remain empty.
	_ = notify
}

func TestSupersededLegacyMainCanceledAfterAttachIsDetached(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	gateway, managerInterface, token := newGatewayFixture(t, true)
	manager := managerInterface.(*session.Manager)
	old := newBlockingCloseSession("kap-old", "device-1")
	if err := manager.Attach(context.Background(), old); err != nil {
		t.Fatal(err)
	}

	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainClient.Close()
	select {
	case <-old.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("legacy Attach did not block closing old session")
	}
	cancel()
	close(old.closeRelease)
	waitDone(t, context.Background(), mainDone, context.Canceled)
	if _, err := manager.CurrentForDevice(context.Background(), "device-1"); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("canceled attached main remained current: %v", err)
	}
	gateway.runtimeMu.Lock()
	entry := gateway.runtimes["device-1"]
	gateway.runtimeMu.Unlock()
	if entry != nil {
		entry.runtime.mu.Lock()
		attached := entry.runtime.attachedMain
		pending := entry.runtime.pendingMainTransitions
		entry.runtime.mu.Unlock()
		if attached != nil || pending != 0 {
			t.Fatalf("canceled commit state = (attached=%p pending=%d)", attached, pending)
		}
	}
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestFailedLegacyAttachRestoresExactLivePriorMainAndMux(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gateway, managerInterface, token := newGatewayFixture(t, true)
	manager := managerInterface.(*session.Manager)

	firstClient, firstDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer firstClient.Close()
	first := waitCurrent(t, ctx, manager, "device-1").(*LegacyNpcSession)
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	ping := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})

	attachFailure := errors.New("test attach failure")
	gateway.sessions = &failingAttachSessionManager{inner: manager, err: attachFailure}
	secondClient, secondDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer secondClient.Close()
	waitDone(t, ctx, secondDone, attachFailure)
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil || current != first {
		t.Fatalf("manager current = (%T, %v), want prior legacy main", current, err)
	}
	first.runtime.mu.Lock()
	runtimeCurrent := first.runtime.currentMain
	runtimeAttached := first.runtime.attachedMain
	first.runtime.mu.Unlock()
	if runtimeCurrent != first || runtimeAttached != first {
		t.Fatal("failed Attach did not restore exact prior runtime ownership")
	}

	openDone := make(chan error, 1)
	go func() {
		stream, err := first.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
		if stream != nil {
			_ = stream.Close()
		}
		openDone <- err
	}()
	open := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagStreamAccepted, StreamID: open.StreamID})
	_ = readPeerFrame(t, chanClient)
	if err := <-openDone; err != nil {
		t.Fatalf("restored main could not use preserved mux: %v", err)
	}
	_ = readPeerFrame(t, chanClient)

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = firstClient.Close()
	waitDone(t, ctx, firstDone, nil)
}

func TestCleanupContextBoundsManagerCurrentAndReleasesTransition(t *testing.T) {
	gateway, _, token := newGatewayFixture(t, true)
	gateway.handshakeTimeout = 20 * time.Millisecond
	manager := newBlockingCleanupSessionManager(true, false)
	gateway.sessions = manager

	client, done := serveStockPipe(t, context.Background(), gateway, token, connTypeMain)
	defer client.Close()
	waitDone(t, context.Background(), done, context.DeadlineExceeded)
	select {
	case <-manager.currentEntered:
	default:
		t.Fatal("post-Attach CurrentForDevice was not called")
	}
	assertGatewayRuntimeMapEmpty(t, gateway)

	lease := gateway.acquireRuntime("device-1", legacyRuntimeLeaseTransition)
	locked := make(chan struct{})
	go func() {
		lease.Runtime().mainTransitionMu.Lock()
		lease.Runtime().mainTransitionMu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("main transition mutex remained held after bounded CurrentForDevice")
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestCleanupContextBoundsFinalDetachAndReleasesSessionLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, _, token := newGatewayFixture(t, true)
	gateway.handshakeTimeout = 20 * time.Millisecond
	manager := newBlockingCleanupSessionManager(false, true)
	gateway.sessions = manager

	client, done := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	current := waitCurrent(t, ctx, manager, "device-1")
	_ = client.Close()
	waitDone(t, ctx, done, nil)
	select {
	case <-manager.detachEntered:
	default:
		t.Fatal("final Detach was not called")
	}
	select {
	case <-current.Done():
	default:
		t.Fatal("session resources were not closed before bounded Detach returned")
	}
	assertGatewayRuntimeMapEmpty(t, gateway)
	if err := manager.inner.Detach(context.Background(), current.ID()); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledMainBeforePublicationReleasesPendingInterest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	gateway, manager, token := newGatewayFixture(t, true)
	hold := gateway.acquireRuntime("device-1", legacyRuntimeLeaseChan)
	runtime := hold.Runtime()
	runtime.mainTransitionMu.Lock()
	client, done := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer client.Close()
	waitPendingMainTransitions(t, ctx, runtime, 1)
	cancel()
	runtime.mainTransitionMu.Unlock()
	waitDone(t, context.Background(), done, context.Canceled)
	runtime.mu.Lock()
	current := runtime.currentMain
	attached := runtime.attachedMain
	pending := runtime.pendingMainTransitions
	runtime.mu.Unlock()
	if current != nil || attached != nil || pending != 0 {
		t.Fatalf("pre-publication cancel state = (current=%p attached=%p pending=%d)", current, attached, pending)
	}
	if _, err := manager.CurrentForDevice(context.Background(), "device-1"); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("canceled pre-publication main reached Attach: %v", err)
	}
	if err := hold.Release(); err != nil {
		t.Fatal(err)
	}
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestMainSessionIDFailureReleasesPendingInterest(t *testing.T) {
	gateway, _, token := newGatewayFixture(t, true)
	idErr := errors.New("session ID failure")
	gateway.newSessionID = func() (domain.SessionID, error) { return "", idErr }
	client, done := serveStockPipe(t, context.Background(), gateway, token, connTypeMain)
	defer client.Close()
	waitDone(t, context.Background(), done, idErr)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestMainAttachChanTimeoutAndCancellation(t *testing.T) {
	t.Run("bounded timeout", func(t *testing.T) {
		gateway, _, token := newGatewayFixture(t, true)
		gateway.handshakeTimeout = 20 * time.Millisecond
		started := time.Now()
		client, done := serveStockPipe(t, context.Background(), gateway, token, connTypeChan)
		defer client.Close()
		waitDone(t, context.Background(), done, ErrNoCurrentMainSession)
		if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
			t.Fatalf("no-main wait was not bounded: %v", elapsed)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		gateway, _, token := newGatewayFixture(t, true)
		gateway.handshakeTimeout = time.Second
		ctx, cancel := context.WithCancel(context.Background())
		client, done := serveStockPipe(t, ctx, gateway, token, connTypeChan)
		defer client.Close()
		cancel()
		waitDone(t, context.Background(), done, context.Canceled)
	})
}

func TestMainAttachChanNoLostWakeup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	defer chanClient.Close()
	if err := chanClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ping := readPeerFrame(t, chanClient)
	_ = chanClient.SetReadDeadline(time.Time{})
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})
	select {
	case err := <-chanDone:
		t.Fatalf("chan returned before first main attachment: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	defer mainClient.Close()
	_ = waitCurrent(t, ctx, manager, "device-1")

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
}

func TestChanImmediatePostHandshakeDisconnectIsNormal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	mainSession := waitCurrent(t, ctx, manager, "device-1")

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	if current := waitCurrent(t, ctx, manager, "device-1"); current.ID() != mainSession.ID() {
		t.Fatal("immediate chan disconnect changed current main session")
	}

	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
}

func TestChanEOFWhileWaitingForMainInterestIsNormal(t *testing.T) {
	gateway, _, token := newGatewayFixture(t, true)
	gateway.handshakeTimeout = time.Second
	client, done := serveStockPipe(t, context.Background(), gateway, token, connTypeChan)
	_ = client.Close()
	waitDone(t, context.Background(), done, nil)
	assertGatewayRuntimeMapEmpty(t, gateway)
}

func TestServeChanReturnsSanitizedProtocolTerminalCause(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	mainSession := waitCurrent(t, ctx, manager, "device-1")
	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	initial := readPeerFrame(t, chanClient)
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: initial.Content})

	if _, err := chanClient.Write([]byte{0x09, 1, 0, 0, 0}); err != nil {
		t.Fatalf("write unknown mux flag: %v", err)
	}
	waitDone(t, ctx, chanDone, ErrLegacyProtocol)
	if current := waitCurrent(t, ctx, manager, "device-1"); current.ID() != mainSession.ID() {
		t.Fatal("protocol chan failure changed current main session")
	}

	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
}

func TestChanTransfersRawConnectionToLegacyMuxAndClearsAvailability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gateway, manager, token := newGatewayFixture(t, true)
	mainClient, mainDone := serveStockPipe(t, ctx, gateway, token, connTypeMain)
	legacySession := waitCurrent(t, ctx, manager, "device-1").(*LegacyNpcSession)

	chanClient, chanDone := serveStockPipe(t, ctx, gateway, token, connTypeChan)
	initial := readPeerFrame(t, chanClient)
	if initial.Flag != FrameFlagPing || initial.StreamID != -1 {
		t.Fatalf("first chan frame = %#v, want mux ping", initial)
	}
	writePeerFrame(t, chanClient, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: initial.Content})
	if _, _, err := legacySession.snapshotMux(); err != nil {
		t.Fatalf("snapshot installed mux error = %v", err)
	}

	_ = chanClient.Close()
	waitDone(t, ctx, chanDone, nil)
	if _, _, err := legacySession.snapshotMux(); !errors.Is(err, ErrLegacyDataChannelUnavailable) {
		t.Fatalf("snapshot after chan disconnect error = %v", err)
	}
	if current := waitCurrent(t, ctx, manager, "device-1"); current.ID() != legacySession.ID() {
		t.Fatal("chan disconnect changed current main session")
	}

	_ = mainClient.Close()
	waitDone(t, ctx, mainDone, nil)
}

func TestGatewayRejectsInvalidLegacyMuxConfigBeforeServing(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	if err := st.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		ServerSecret: []byte("server-secret"),
		Store:        st,
		Sessions:     session.NewManager(),
		MuxConfig: LegacyMuxConfig{
			FixedReceiveWindowBytes: 122549,
		},
	})
	if !errors.Is(err, ErrInvalidLegacyMuxConfig) {
		t.Fatalf("New(invalid mux config) error = %v, want ErrInvalidLegacyMuxConfig", err)
	}
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
	if err := st.CreateTunnel(ctx, domain.Tunnel{
		ID:         "tunnel-1",
		DeviceID:   "device-1",
		Protocol:   domain.TunnelProtocolTCP,
		TargetAddr: "127.0.0.1:8080",
		Enabled:    true,
	}); err != nil {
		t.Fatal(err)
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

func assertNoStreamOpenFrame(t *testing.T, peer net.Conn) {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		if err := peer.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(peer)
		_ = peer.SetReadDeadline(time.Time{})
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			}
			t.Fatalf("ReadFrame(peer) error = %v", err)
		}
		if frame.Flag == FrameFlagStreamOpen {
			t.Fatalf("unexpected stream-open frame = %#v", frame)
		}
		if frame.Flag == FrameFlagPing {
			writePeerFrame(t, peer, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content})
		}
	}
}

func waitPendingMainTransitions(t *testing.T, ctx context.Context, runtime *legacyDeviceRuntime, want int) {
	t.Helper()
	for {
		runtime.mu.Lock()
		if runtime.pendingMainTransitions == want {
			runtime.mu.Unlock()
			return
		}
		notify := runtime.mainNotify
		runtime.mu.Unlock()
		select {
		case <-notify:
		case <-ctx.Done():
			t.Fatalf("pending main transitions did not reach %d: %v", want, ctx.Err())
		}
	}
}

func assertGatewayRuntimeMapEmpty(t *testing.T, gateway *Gateway) {
	t.Helper()
	gateway.runtimeMu.Lock()
	defer gateway.runtimeMu.Unlock()
	if len(gateway.runtimes) != 0 {
		t.Fatalf("runtime map contains %d entries, want zero", len(gateway.runtimes))
	}
}

type blockingCloseSession struct {
	id       domain.SessionID
	deviceID domain.DeviceID

	closeEntered chan struct{}
	closeRelease chan struct{}
	closeDone    chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
}

func newBlockingCloseSession(id domain.SessionID, deviceID domain.DeviceID) *blockingCloseSession {
	return &blockingCloseSession{
		id:           id,
		deviceID:     deviceID,
		closeEntered: make(chan struct{}),
		closeRelease: make(chan struct{}),
		closeDone:    make(chan struct{}),
		done:         make(chan struct{}),
	}
}

func (s *blockingCloseSession) ID() domain.SessionID {
	return s.id
}

func (s *blockingCloseSession) DeviceID() domain.DeviceID {
	return s.deviceID
}

func (s *blockingCloseSession) Protocol() domain.AgentProtocol {
	return domain.AgentProtocolKAPv1
}

func (s *blockingCloseSession) OpenStream(context.Context, domain.StreamOpenRequest) (session.AgentStream, error) {
	return &testutil.FakeStream{}, nil
}

func (s *blockingCloseSession) Close(context.Context) error {
	s.closeOnce.Do(func() {
		close(s.closeEntered)
		<-s.closeRelease
		close(s.done)
		close(s.closeDone)
	})
	<-s.closeDone
	return nil
}

func (s *blockingCloseSession) Done() <-chan struct{} {
	return s.done
}

type rendezvousSessionManager struct {
	inner *session.Manager

	blockAttach   bool
	attachEntered chan struct{}
	attachRelease chan struct{}
	attachDone    chan struct{}
	attachOnce    sync.Once

	staleFirstQuery bool
	queryCaptured   chan struct{}
	queryRelease    chan struct{}
	queryOnce       sync.Once
}

type failingAttachSessionManager struct {
	inner session.SessionManager
	err   error
}

type sequentialAttachSessionManager struct {
	inner              *session.Manager
	firstAttachEntered chan struct{}
	firstAttachRelease chan struct{}
	firstAttachErr     error

	mu          sync.Mutex
	attachCalls int
}

type blockingCleanupSessionManager struct {
	inner        *session.Manager
	blockCurrent bool
	blockDetach  bool

	currentEntered chan struct{}
	detachEntered  chan struct{}
	currentOnce    sync.Once
	detachOnce     sync.Once
}

func newBlockingCleanupSessionManager(blockCurrent, blockDetach bool) *blockingCleanupSessionManager {
	return &blockingCleanupSessionManager{
		inner:          session.NewManager(),
		blockCurrent:   blockCurrent,
		blockDetach:    blockDetach,
		currentEntered: make(chan struct{}),
		detachEntered:  make(chan struct{}),
	}
}

func (m *blockingCleanupSessionManager) Attach(ctx context.Context, next session.AgentSession) error {
	return m.inner.Attach(ctx, next)
}

func (m *blockingCleanupSessionManager) Detach(ctx context.Context, id domain.SessionID) error {
	if m.blockDetach {
		m.detachOnce.Do(func() { close(m.detachEntered) })
		<-ctx.Done()
		return ctx.Err()
	}
	return m.inner.Detach(ctx, id)
}

func (m *blockingCleanupSessionManager) CurrentForDevice(ctx context.Context, id domain.DeviceID) (session.AgentSession, error) {
	if m.blockCurrent {
		m.currentOnce.Do(func() { close(m.currentEntered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return m.inner.CurrentForDevice(ctx, id)
}

func (m *blockingCleanupSessionManager) ListForDevice(ctx context.Context, id domain.DeviceID) ([]session.AgentSessionInfo, error) {
	return m.inner.ListForDevice(ctx, id)
}

func newSequentialAttachSessionManager() *sequentialAttachSessionManager {
	return &sequentialAttachSessionManager{
		inner:              session.NewManager(),
		firstAttachEntered: make(chan struct{}),
		firstAttachRelease: make(chan struct{}),
		firstAttachErr:     errors.New("first Attach failed"),
	}
}

func (m *sequentialAttachSessionManager) Attach(ctx context.Context, next session.AgentSession) error {
	m.mu.Lock()
	m.attachCalls++
	call := m.attachCalls
	m.mu.Unlock()
	if call == 1 {
		close(m.firstAttachEntered)
		select {
		case <-m.firstAttachRelease:
			return m.firstAttachErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.inner.Attach(ctx, next)
}

func (m *sequentialAttachSessionManager) Detach(ctx context.Context, id domain.SessionID) error {
	return m.inner.Detach(ctx, id)
}

func (m *sequentialAttachSessionManager) CurrentForDevice(ctx context.Context, id domain.DeviceID) (session.AgentSession, error) {
	return m.inner.CurrentForDevice(ctx, id)
}

func (m *sequentialAttachSessionManager) ListForDevice(ctx context.Context, id domain.DeviceID) ([]session.AgentSessionInfo, error) {
	return m.inner.ListForDevice(ctx, id)
}

func (m *failingAttachSessionManager) Attach(context.Context, session.AgentSession) error {
	return m.err
}

func (m *failingAttachSessionManager) Detach(ctx context.Context, id domain.SessionID) error {
	return m.inner.Detach(ctx, id)
}

func (m *failingAttachSessionManager) CurrentForDevice(ctx context.Context, id domain.DeviceID) (session.AgentSession, error) {
	return m.inner.CurrentForDevice(ctx, id)
}

func (m *failingAttachSessionManager) ListForDevice(ctx context.Context, id domain.DeviceID) ([]session.AgentSessionInfo, error) {
	return m.inner.ListForDevice(ctx, id)
}

func newRendezvousSessionManager(blockAttach, staleFirstQuery bool) *rendezvousSessionManager {
	return &rendezvousSessionManager{
		inner:           session.NewManager(),
		blockAttach:     blockAttach,
		attachEntered:   make(chan struct{}),
		attachRelease:   make(chan struct{}),
		attachDone:      make(chan struct{}),
		staleFirstQuery: staleFirstQuery,
		queryCaptured:   make(chan struct{}),
		queryRelease:    make(chan struct{}),
	}
}

func (m *rendezvousSessionManager) Attach(ctx context.Context, next session.AgentSession) error {
	if m.blockAttach {
		m.attachOnce.Do(func() { close(m.attachEntered) })
		select {
		case <-m.attachRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	err := m.inner.Attach(ctx, next)
	if err == nil {
		m.attachOnce.Do(func() { close(m.attachEntered) })
		select {
		case <-m.attachDone:
		default:
			close(m.attachDone)
		}
	}
	return err
}

func (m *rendezvousSessionManager) Detach(ctx context.Context, id domain.SessionID) error {
	return m.inner.Detach(ctx, id)
}

func (m *rendezvousSessionManager) CurrentForDevice(ctx context.Context, id domain.DeviceID) (session.AgentSession, error) {
	if m.staleFirstQuery {
		var current session.AgentSession
		var err error
		used := false
		m.queryOnce.Do(func() {
			used = true
			current, err = m.inner.CurrentForDevice(ctx, id)
			close(m.queryCaptured)
			select {
			case <-m.queryRelease:
			case <-ctx.Done():
				err = ctx.Err()
			}
		})
		if used {
			return current, err
		}
	}
	return m.inner.CurrentForDevice(ctx, id)
}

func (m *rendezvousSessionManager) ListForDevice(ctx context.Context, id domain.DeviceID) ([]session.AgentSessionInfo, error) {
	return m.inner.ListForDevice(ctx, id)
}

var _ session.SessionManager = (*rendezvousSessionManager)(nil)
var _ session.SessionManager = (*failingAttachSessionManager)(nil)
var _ session.SessionManager = (*sequentialAttachSessionManager)(nil)
var _ session.SessionManager = (*blockingCleanupSessionManager)(nil)
var _ session.AgentSession = (*blockingCloseSession)(nil)
