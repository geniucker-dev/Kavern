//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/store"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminStrictParserAndErrorRedaction(t *testing.T) {
	svc, _, _, _, secret := serviceFixture(t, "127.0.0.1:3101")
	tests := []struct {
		name, method, path, body string
		modify                   func(*http.Request)
		status                   int
	}{
		{name: "host", method: "GET", path: "/admin/v1/status", modify: func(r *http.Request) { r.Host = "evil" }, status: 400},
		{name: "origin", method: "GET", path: "/admin/v1/status", modify: func(r *http.Request) { r.Header.Set("Origin", "http://evil") }, status: 400},
		{name: "get-body", method: "GET", path: "/admin/v1/status", body: "{}", status: 400},
		{name: "unknown", method: "POST", path: "/admin/v1/users", body: `{"kind":"create_user","secret":"not-accepted"}`, status: 400},
		{name: "duplicate", method: "POST", path: "/admin/v1/users", body: `{"kind":"create_user","Kind":"create_user"}`, status: 400},
		{name: "trailing", method: "POST", path: "/admin/v1/users", body: `{} {}`, status: 400},
		{name: "oversized", method: "POST", path: "/admin/v1/users", body: strings.Repeat(" ", config.MaxJSONBytes+1), status: 400},
		{name: "invalid-utf8", method: "POST", path: "/admin/v1/users", body: string([]byte{0xff}), status: 400},
		{name: "unknown-query", method: "GET", path: "/admin/v1/window?x=1", status: 404},
		{name: "malformed-query", method: "GET", path: "/admin/v1/users?after=x;bad=1", status: 400},
		{name: "duplicate-query", method: "GET", path: "/admin/v1/users?after=a&after=b", status: 400},
		{name: "wrong-operation-epoch", method: "GET", path: "/admin/v1/operations/op?lineage=&epoch=00", status: 400},
		{name: "recover-null", method: "POST", path: "/admin/v1/recover", body: `null`, status: 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "http://"+config.AdminHost+tt.path, strings.NewReader(tt.body))
			if tt.method != "GET" {
				r.Header.Set("Content-Type", "application/json")
			}
			if tt.modify != nil {
				tt.modify(r)
			}
			w := httptest.NewRecorder()
			svc.adminRequest(w, r)
			if w.Code != tt.status {
				t.Fatalf("status=%d expected=%d", w.Code, tt.status)
			}
			if bytes.Contains(w.Body.Bytes(), secret) {
				t.Fatal("secret exposed")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cache enabled")
			}
		})
	}
	for _, e := range []error{store.ErrCommitUncertain, store.ErrOperationExpired, store.ErrRevisionConflict} {
		w := httptest.NewRecorder()
		adminError(w, e)
		var v config.AdminError
		if json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Code == "" {
			t.Fatal("error not redacted DTO")
		}
		if e == store.ErrCommitUncertain && w.Code != 503 {
			t.Fatal("uncertainty not fail closed")
		}
	}
}
func TestAdminExactWindowLookupAndSavedWithoutReady(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t, "127.0.0.1:3101")
	ctx := context.Background()
	c, e := svc.owner.DeviceConfiguration(ctx, "device")
	if e != nil {
		t.Fatal(e)
	}
	w, e := svc.owner.ManagementWindow(ctx)
	if e != nil {
		t.Fatal(e)
	}
	req := config.AdminMutation{Window: adminWindow(w), OperationID: "api-noop", Kind: "put_device", DeviceID: "device", ExpectedRevision: c.Revision, Configuration: &c}
	data, _ := json.Marshal(req)
	r := httptest.NewRequest("PUT", "http://"+config.AdminHost+"/admin/v1/devices/device/configuration", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	svc.adminRequest(response, r)
	var result config.AdminResult
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || response.Code != 200 || !result.Saved || result.Revision != 1 {
		t.Fatal("no-op saved contract")
	}
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://"+config.AdminHost+path, nil)
		v := httptest.NewRecorder()
		svc.adminRequest(v, r)
		return v
	}
	lookup := get("/admin/v1/operations/api-noop?lineage=&epoch=0")
	if lookup.Code != 200 || bytes.Contains(lookup.Body.Bytes(), []byte(`"issuance"`)) {
		t.Fatal("receipt lookup missing or secret")
	}
	lookup = get("/admin/v1/operations/api-noop?lineage=" + result.Window.Lineage + "&epoch=" + result.Window.Epoch)
	if lookup.Code != 409 {
		t.Fatal("result/current epoch incorrectly accepted as request window")
	}
	status := get("/admin/v1/devices/device/status")
	var v config.AdminDeviceStatus
	if json.Unmarshal(status.Body.Bytes(), &v) != nil || v.Ready || v.Session.Present || v.UserID != "user" || v.DesiredRevision != 1 {
		t.Fatal("saved status invented readiness")
	}
	for _, key := range []string{"session_id", "device_secret", "HMAC", "Ciphertext", "auth_challenge"} {
		if bytes.Contains(status.Body.Bytes(), []byte(key)) {
			t.Fatal("private gateway state exposed")
		}
	}
}
func TestAdminConnectionCapacityAndShutdownJoinsSlowHeaders(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t, "127.0.0.1:3101")
	dir := filepath.Join(t.TempDir(), "r")
	os.Mkdir(dir, 0700)
	path := filepath.Join(dir, "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- svc.runAdmin(ctx, path, started) }()
	if e := <-started; e != nil {
		t.Fatal(e)
	}
	var peers []net.Conn
	defer func() {
		for _, c := range peers {
			c.Close()
		}
	}()
	for i := 0; i < config.AdminMaxConnections; i++ {
		c, e := config.DialAdmin(context.Background(), path)
		if e != nil {
			t.Fatal(e)
		}
		peers = append(peers, c)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e = c.Write([]byte("GET /admin/v1/status HTTP/1.1\r\n")); e != nil {
			t.Fatal(e)
		}
	}
	excess, e := config.DialAdmin(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer excess.Close()
	excess.SetDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = excess.Read(b[:]); e == nil {
		t.Fatal("saturation retained connection")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("slow-header workers not joined")
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("socket retained")
	}
}

type lateAdminAcceptedListener struct {
	net.Listener
	conn             net.Conn
	entered, release chan struct{}
}

func (l *lateAdminAcceptedListener) Accept() (net.Conn, error) {
	close(l.entered)
	<-l.release
	return l.conn, nil
}
func TestAdminClosingRejectsSocketAcceptedBeforeHTTPRegistration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	os.Mkdir(dir, 0700)
	path := filepath.Join(dir, "a.sock")
	endpoint, e := config.OpenAdminListener(path)
	if e != nil {
		t.Fatal(e)
	}
	defer endpoint.Close()
	client, e := config.DialAdmin(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	accepted, e := endpoint.Listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	underlying := &lateAdminAcceptedListener{Listener: endpoint.Listener, conn: accepted, entered: make(chan struct{}), release: make(chan struct{})}
	listener := &adminListener{Listener: underlying, slots: make(chan struct{}, config.AdminMaxConnections)}
	done := make(chan error, 1)
	go func() { _, e := listener.Accept(); done <- e }()
	<-underlying.entered
	listener.Close()
	close(underlying.release)
	if e = <-done; !errors.Is(e, net.ErrClosed) {
		t.Fatal("late socket registered after close", e)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = client.Read(b[:]); e == nil {
		t.Fatal("late accepted socket not closed")
	}
	listener.workers.Wait()
	if len(listener.slots) != 0 {
		t.Fatal("late worker reservation leaked")
	}
}
