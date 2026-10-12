package legacy_npc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

type versionScriptConn struct {
	input     *bytes.Reader
	output    bytes.Buffer
	deadlines []time.Time
	closed    bool
}

func (c *versionScriptConn) Read(p []byte) (int, error)  { return c.input.Read(p) }
func (c *versionScriptConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *versionScriptConn) Close() error                { c.closed = true; return nil }
func (c *versionScriptConn) LocalAddr() net.Addr         { return versionTestAddr("local") }
func (c *versionScriptConn) RemoteAddr() net.Addr        { return versionTestAddr("remote") }
func (c *versionScriptConn) SetDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}
func (c *versionScriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *versionScriptConn) SetWriteDeadline(time.Time) error { return nil }

type versionTestAddr string

func (a versionTestAddr) Network() string { return "test" }
func (a versionTestAddr) String() string  { return string(a) }
func versionInput(core, client, token, role string) []byte {
	p := append([]byte("TST"), stockString(core)...)
	p = append(p, stockString(client)...)
	p = append(p, token...)
	return append(p, role...)
}
func opaqueBegin(t *testing.T, g *Gateway, core, client []byte, fragment bool) (net.Conn, <-chan error) {
	t.Helper()
	a, b := net.Pipe()
	_ = a.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() { done <- g.ServeConn(context.Background(), b) }()
	p := append([]byte("TST"), stockSignedLength(int32(len(core)))...)
	p = append(p, core...)
	p = append(p, stockSignedLength(int32(len(client)))...)
	p = append(p, client...)
	if fragment {
		for _, v := range p {
			if _, e := a.Write([]byte{v}); e != nil {
				t.Fatal(e)
			}
		}
	} else if _, e := a.Write(p); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 32)
	if _, e := io.ReadFull(a, reply); e != nil || !bytes.Equal(reply, legacyServerVersionField()) {
		t.Fatal("fixed response changed")
	}
	return a, done
}
func TestOpaqueServeConnMetadataAndFragmentation(t *testing.T) {
	pairs := [][2]string{{"0.26.0", "0.26.17"}, {"0.26.0", "0.26.27"}, {"unknown core", "unknown client"}, {"0.27.0", "9.9.9"}, {" vCORE\x00 ", " client\x00 +build "}, {strings.Repeat("X", 4096), strings.Repeat("Y", 4096)}}
	for i, p := range pairs {
		g, m, token := newGatewayFixture(t, true)
		a, done := opaqueBegin(t, g, []byte(p[0]), []byte(p[1]), i == 4)
		if sendStockTokenAndReadOutcome(t, a, token) != "sucs" {
			t.Fatal("opaque metadata denied valid credential")
		}
		if _, e := a.Write([]byte("main")); e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		waitCurrent(t, ctx, m, "device-1")
		a.Close()
		waitDone(t, ctx, done, nil)
		waitNoCurrent(t, ctx, m, "device-1")
		assertGatewayRuntimeMapEmpty(t, g)
		cancel()
	}
}
func TestOpaqueServeConnEachFieldBoundsAndTruncation(t *testing.T) {
	bad := [][]byte{stockSignedLength(0), stockSignedLength(-1), stockSignedLength(4097), stockSignedLength(1 << 30), stockSignedLength(2147483647), {1, 2}, append(stockSignedLength(4), []byte("xx")...)}
	for _, field := range []string{"core", "client"} {
		for _, wire := range bad {
			g, m, _ := newGatewayFixture(t, true)
			p := []byte("TST")
			if field == "client" {
				p = append(p, stockString("nonfixed core")...)
			}
			p = append(p, wire...)
			c := &versionScriptConn{input: bytes.NewReader(p)}
			if e := g.ServeConn(context.Background(), c); !errors.Is(e, ErrInvalidHandshake) || c.output.Len() != 0 || !c.closed {
				t.Fatal("unsafe metadata admitted")
			}
			if _, e := m.CurrentForDevice(context.Background(), "device-1"); !errors.Is(e, session.ErrNoCurrentSession) {
				t.Fatal("invalid field published session")
			}
			assertGatewayRuntimeMapEmpty(t, g)
		}
	}
	g, _, token := newGatewayFixture(t, true)
	configured, err := New(Config{Store: g.store, Sessions: g.sessions, ServerSecret: g.serverSecret, MaxHandshakeBytes: 2})
	if err != nil {
		t.Fatal(err)
	}
	g = configured
	c := &versionScriptConn{input: bytes.NewReader(versionInput("x", "\x00 ", token, "file"))}
	if e := g.ServeConn(context.Background(), c); !errors.Is(e, ErrUnsupportedConnection) || !bytes.Equal(c.output.Bytes(), append(legacyServerVersionField(), []byte("sucs")...)) {
		t.Fatal("smaller configured positive bound changed")
	}
	for _, p := range [][2]string{{"xxx", "x"}, {"x", "xxx"}} {
		g, _, token := newGatewayFixture(t, true)
		configured, err := New(Config{Store: g.store, Sessions: g.sessions, ServerSecret: g.serverSecret, MaxHandshakeBytes: 2})
		if err != nil {
			t.Fatal(err)
		}
		g = configured
		c := &versionScriptConn{input: bytes.NewReader(versionInput(p[0], p[1], token, "main"))}
		if e := g.ServeConn(context.Background(), c); !errors.Is(e, ErrInvalidHandshake) || c.output.Len() != 0 {
			t.Fatal("smaller configured limit ignored")
		}
	}
}
func TestOpaqueServeConnAuthAndUnsupportedRoles(t *testing.T) {
	for _, pair := range [][2]string{{"unknown core", "unknown client"}, {"\x00 core ", "0.26.999+build"}} {
		for _, kind := range []string{"malformed", "unknown", "rotated", "disabled", "file", "conf", "other"} {
			g, m, token := newGatewayFixture(t, kind != "disabled")
			role := "main"
			want := ErrInvalidHandshake
			auth := "vkey"
			switch kind {
			case "malformed":
				token = strings.Repeat("z", 32)
			case "unknown":
				token = strings.Repeat("0", 32)
			case "rotated":
				if _, e := g.store.(*store.MemoryStore).RotateLegacyCredential(context.Background(), "device-1", g.serverSecret); e != nil {
					t.Fatal(e)
				}
			case "file", "conf", "other":
				role = map[string]string{"file": "file", "conf": "conf", "other": "xxxx"}[kind]
				want = ErrUnsupportedConnection
				auth = "sucs"
			}
			created := 0
			g.newSessionID = func() (domain.SessionID, error) { created++; return "forbidden", nil }
			c := &versionScriptConn{input: bytes.NewReader(versionInput(pair[0], pair[1], token, role))}
			e := g.ServeConn(context.Background(), c)
			if !errors.Is(e, want) || !bytes.Equal(c.output.Bytes(), append(legacyServerVersionField(), []byte(auth)...)) || created != 0 {
				t.Fatal("opaque declarations bypassed auth or role")
			}
			if auth == "vkey" && c.input.Len() != 4 {
				t.Fatal("role read before successful authentication")
			}
			if _, e := m.CurrentForDevice(context.Background(), "device-1"); !errors.Is(e, session.ErrNoCurrentSession) {
				t.Fatal("rejected session published")
			}
			assertGatewayRuntimeMapEmpty(t, g)
		}
	}
}
func TestOpaqueServeConnKeepsStrictTSTAndSingleDeadline(t *testing.T) {
	g, _, _ := newGatewayFixture(t, true)
	c := &versionScriptConn{input: bytes.NewReader([]byte("BAD"))}
	if e := g.ServeConn(context.Background(), c); !errors.Is(e, ErrInvalidHandshake) || c.output.Len() != 0 {
		t.Fatal("TST check relaxed")
	}
	if len(c.deadlines) != 2 || c.deadlines[0].IsZero() || !c.deadlines[1].IsZero() || g.handshakeTimeout != 5*time.Second {
		t.Fatal("default single deadline changed")
	}
	g, _, _ = newGatewayFixture(t, true)
	g.handshakeTimeout = 100 * time.Millisecond
	a, b := net.Pipe()
	defer a.Close()
	done := make(chan error, 1)
	go func() { done <- g.ServeConn(context.Background(), b) }()
	if _, e := a.Write(append([]byte("TST"), stockString("x")...)); e != nil {
		t.Fatal(e)
	}
	timer := time.NewTimer(65 * time.Millisecond)
	<-timer.C
	if _, e := a.Write(stockSignedLength(1)); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, ErrInvalidHandshake) {
			t.Fatal("deadline return changed")
		}
	case <-time.After(70 * time.Millisecond):
		t.Fatal("deadline renewed after core/client progress")
	}
	assertGatewayRuntimeMapEmpty(t, g)
}

func TestOpaqueServeConnMainAndChanKeepSessionOwnership(t *testing.T) {
	g, m, token := newGatewayFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a, mainDone := opaqueBegin(t, g, []byte("unknown main core"), []byte("\x00 main metadata"), true)
	if sendStockTokenAndReadOutcome(t, a, token) != "sucs" {
		t.Fatal("main auth changed")
	}
	if _, e := a.Write([]byte("main")); e != nil {
		t.Fatal(e)
	}
	current := waitCurrent(t, ctx, m, "device-1")
	b, chanDone := opaqueBegin(t, g, []byte("unknown chan core"), []byte("v9.9.9 chan"), true)
	if sendStockTokenAndReadOutcome(t, b, token) != "sucs" {
		t.Fatal("chan auth changed")
	}
	if _, e := b.Write([]byte("chan")); e != nil {
		t.Fatal(e)
	}
	ping := readPeerFrame(t, b)
	writePeerFrame(t, b, Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: ping.Content})
	if _, _, e := current.(*LegacyNpcSession).snapshotMux(); e != nil {
		t.Fatal("mux unavailable")
	}
	b.Close()
	waitDone(t, ctx, chanDone, nil)
	if waitCurrent(t, ctx, m, "device-1").ID() != current.ID() {
		t.Fatal("chan changed ownership")
	}
	a.Close()
	waitDone(t, ctx, mainDone, nil)
	waitNoCurrent(t, ctx, m, "device-1")
	assertGatewayRuntimeMapEmpty(t, g)
}
