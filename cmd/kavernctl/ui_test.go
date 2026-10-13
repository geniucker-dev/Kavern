//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/session"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type uiTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*uiTestTimer
}
type uiTestTimer struct {
	clock  *uiTestClock
	fn     func()
	active bool
}

func (c *uiTestClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *uiTestClock) AfterFunc(_ time.Duration, fn func()) session.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &uiTestTimer{c, fn, true}
	c.timers = append(c.timers, t)
	return t
}
func (t *uiTestTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := t.active
	t.active = false
	return active
}
func uiFixture(t *testing.T) (*uiBridge, string, *uiTestClock) {
	t.Helper()
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != config.AdminHost || r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get(uiRequestHeader) != "" {
			t.Error("browser authority leaked into UDS request")
		}
		if r.URL.Path == "/admin/v1/status" {
			json.NewEncoder(w).Encode(config.AdminHealth{Health: "running"})
			return
		}
		json.NewEncoder(w).Encode(config.AdminPage{})
	}))
	clock := &uiTestClock{now: time.Now()}
	b, code, e := newUIBridge(context.Background(), socket, clock)
	if e != nil {
		t.Fatal(e)
	}
	b.host = "127.0.0.1:12345"
	b.origin = "http://" + b.host
	t.Cleanup(func() { b.auth.close(); b.client.Close() })
	return b, code, clock
}
func uiRequest(b *uiBridge, method, path, body string) *http.Request {
	r := httptest.NewRequest(method, b.origin+b.base+path, strings.NewReader(body))
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Host = b.host
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if method != "GET" {
		r.Header.Set("Origin", b.origin)
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}
func uiBootstrap(t *testing.T, b *uiBridge, code string) (*http.Cookie, string) {
	t.Helper()
	r := uiRequest(b, "POST", "session/bootstrap", `{"code":"`+code+`"}`)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("bootstrap failed", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Domain != "" || cookies[0].Path != b.base || cookies[0].MaxAge != 0 {
		t.Fatal("cookie boundary changed")
	}
	var data struct {
		Token    string `json:"request_token"`
		Idle     int    `json:"idle_seconds"`
		Absolute int    `json:"absolute_seconds"`
	}
	if e := config.DecodeJSON(w.Body, &data); e != nil {
		t.Fatal(e)
	}
	return cookies[0], data.Token
}
func authorize(r *http.Request, c *http.Cookie, token string) {
	r.AddCookie(c)
	r.Header.Set(uiRequestHeader, token)
}
func TestUIOneUseBootstrapAndEveryPrivateReadNeedsIndependentToken(t *testing.T) {
	b, code, _ := uiFixture(t)
	cookie, token := uiBootstrap(t, b, code)
	for _, kind := range []string{"no-auth", "cookie-only", "token-only", "wrong-cookie", "wrong-token", "duplicate-cookie", "duplicate-token", "full"} {
		r := uiRequest(b, "GET", "api/users", "")
		switch kind {
		case "cookie-only":
			r.AddCookie(cookie)
		case "token-only":
			r.Header.Set(uiRequestHeader, token)
		case "wrong-cookie":
			authorize(r, &http.Cookie{Name: cookie.Name, Value: strings.Repeat("A", 43)}, token)
		case "wrong-token":
			authorize(r, cookie, strings.Repeat("A", 43))
		case "duplicate-cookie":
			authorize(r, cookie, token)
			r.AddCookie(cookie)
		case "duplicate-token":
			authorize(r, cookie, token)
			r.Header.Add(uiRequestHeader, token)
		case "full":
			authorize(r, cookie, token)
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		want := 401
		if kind == "full" {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("%s status %d", kind, w.Code)
		}
	}
	r := uiRequest(b, "POST", "session/bootstrap", `{"code":"`+code+`"}`)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("launch code replayed")
	}
}
func TestUIBrowserBoundaryAndForwardWhitelist(t *testing.T) {
	b, code, _ := uiFixture(t)
	cookie, token := uiBootstrap(t, b, code)
	cases := []struct {
		name   string
		change func(*http.Request)
	}{{"foreign-host", func(r *http.Request) { r.Host = "evil.example:12345" }}, {"localhost", func(r *http.Request) { r.Host = "localhost:12345" }}, {"foreign-origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }}, {"null-origin", func(r *http.Request) { r.Header.Set("Origin", "null") }}, {"multiple-origin", func(r *http.Request) { r.Header.Add("Origin", b.origin); r.Header.Add("Origin", b.origin) }}, {"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }}, {"same-site-other-origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }}, {"forwarded", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", b.host) }}, {"upgrade", func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }}, {"nonloopback", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:1000" }}, {"absolute-uri", func(r *http.Request) { r.URL.Scheme = "http"; r.URL.Host = b.host }}}
	for _, c := range cases {
		r := uiRequest(b, "GET", "api/status", "")
		authorize(r, cookie, token)
		c.change(r)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s boundary status=%d", c.name, w.Code)
		}
	}
	for _, path := range []string{"api/window?unknown=x", "api/recover", "api/operations/id", "api/devices/device/rotate-credential", "api/../../private", "api/users?unknown=x", "api/devices?project_id=a&project_id=b"} {
		parts := strings.SplitN(path, "?", 2)
		r := uiRequest(b, "GET", parts[0], "")
		if len(parts) > 1 {
			r.URL.RawQuery = parts[1]
		}
		authorize(r, cookie, token)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("unapproved read route accepted", path)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT"} {
		r := uiRequest(b, method, "api/devices", "{}")
		authorize(r, cookie, token)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("W1 allowed mutation/preflight", method, w.Code)
		}
	}
	r := uiRequest(b, "GET", "api/status", "")
	r.Header.Del("Sec-Fetch-Site")
	authorize(r, cookie, token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("missing metadata rejected despite full authority")
	}
}
func TestUIExpiryPollingActivityAndLateTimerIsolation(t *testing.T) {
	b, code, clock := uiFixture(t)
	cookie, token := uiBootstrap(t, b, code)
	clock.mu.Lock()
	stale := clock.timers[0].fn
	clock.mu.Unlock()
	stale()
	r := uiRequest(b, "GET", "api/status", "")
	authorize(r, cookie, token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("stopped bootstrap callback expired session")
	}
	clock.mu.Lock()
	clock.now = clock.now.Add(9 * time.Minute)
	clock.mu.Unlock()
	r = uiRequest(b, "GET", "api/status", "")
	authorize(r, cookie, token)
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("session expired early")
	}
	clock.mu.Lock()
	clock.now = clock.now.Add(time.Minute)
	clock.mu.Unlock()
	r = uiRequest(b, "GET", "api/status", "")
	authorize(r, cookie, token)
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("polling extended idle or equality expiry not enforced")
	}
	b, code, clock = uiFixture(t)
	cookie, token = uiBootstrap(t, b, code)
	for i := 0; i < 6; i++ {
		clock.mu.Lock()
		clock.now = clock.now.Add(9 * time.Minute)
		clock.mu.Unlock()
		r = uiRequest(b, "POST", "session/activity", "{}")
		authorize(r, cookie, token)
		w = httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("valid activity failed")
		}
	}
	clock.mu.Lock()
	clock.now = clock.now.Add(6 * time.Minute)
	clock.mu.Unlock()
	r = uiRequest(b, "GET", "api/status", "")
	authorize(r, cookie, token)
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("activity bypassed absolute expiry")
	}
}
func TestUIConcurrentBootstrapConsumesCodeExactlyOnce(t *testing.T) {
	b, code, _ := uiFixture(t)
	var wg sync.WaitGroup
	results := make(chan int, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			b.ServeHTTP(w, uiRequest(b, "POST", "session/bootstrap", `{"code":"`+code+`"}`))
			results <- w.Code
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for status := range results {
		if status == 200 {
			success++
		} else if status != 401 {
			t.Fatal(status)
		}
	}
	if success != 1 {
		t.Fatal("one-use launch not atomic", success)
	}
}
func TestUIHeadersLogoutParserBoundsAndForwardCapacity(t *testing.T) {
	b, code, _ := uiFixture(t)
	cookie, token := uiBootstrap(t, b, code)
	for _, path := range []string{"", "app.js", "style.css", "api/status"} {
		r := uiRequest(b, "GET", path, "")
		if strings.HasPrefix(path, "api/") {
			authorize(r, cookie, token)
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("browser security headers missing")
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("CORS enabled")
		}
	}
	for _, body := range []string{`null`, `{"code":"x","code":"y"}`, `{"code":"x","unknown":1}`, strings.Repeat("x", 1025)} {
		r := uiRequest(b, "POST", "session/bootstrap", body)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("invalid bootstrap body accepted")
		}
	}
	for i := 0; i < uiMaxForwards; i++ {
		b.forwards <- struct{}{}
	}
	r := uiRequest(b, "GET", "api/users", "")
	authorize(r, cookie, token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal("unbounded upstream wait")
	}
	for i := 0; i < uiMaxForwards; i++ {
		<-b.forwards
	}
	r = uiRequest(b, "POST", "session/logout", "{}")
	authorize(r, cookie, token)
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("logout failed")
	}
	r = uiRequest(b, "GET", "api/status", "")
	authorize(r, cookie, token)
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("logout retained authority")
	}
}
func TestTypedAdminClientRejectsUnexpectedIssuanceAndPreservesOutcome(t *testing.T) {
	for _, code := range []string{"revision_conflict", "commit_uncertain", "request_expired", "response_capacity", "unknown"} {
		socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if code == "revision_conflict" {
				w.WriteHeader(409)
			} else {
				w.WriteHeader(503)
			}
			json.NewEncoder(w).Encode(config.AdminError{Code: code})
		}))
		c := config.NewAdminClient(socket, 1)
		var out config.AdminHealth
		e := c.Request(context.Background(), "GET", "/admin/v1/status", nil, &out)
		c.Close()
		var problem *config.AdminRequestError
		if !errors.As(e, &problem) {
			t.Fatal("typed error unavailable")
		}
		want := config.AdminUnconfirmed
		if code == "revision_conflict" {
			want = config.AdminRejected
		}
		if problem.Outcome != want {
			t.Fatal("outcome classification", code)
		}
	}
	secret := "SYNTHETIC_SECRET_MUST_NOT_REACH_BROWSER"
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"health":"running","cleanup_pending":false,"issuance":"`+secret+`"}`)
	}))
	client := config.NewAdminClient(socket, 1)
	defer client.Close()
	var out config.AdminHealth
	e := client.Request(context.Background(), "GET", "/admin/v1/status", nil, &out)
	if e == nil || bytes.Contains([]byte(e.Error()), []byte(secret)) {
		t.Fatal("unexpected credential leaked through typed error")
	}
}

func TestUISlowConnectionsShutdownJoinsSocketsAndSessionTimer(t *testing.T) {
	b, _, clock := uiFixture(t)
	socket, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	b.host = socket.Addr().String()
	b.origin = "http://" + b.host
	ctx, cancel := context.WithCancel(context.Background())
	ready := &uiReadyWriter{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- serveUI(ctx, b, socket, ready, "synthetic-launch") }()
	<-ready.ready
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < uiMaxConnections; i++ {
		c, e := net.DialTimeout("tcp", b.host, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
		if _, e = io.WriteString(c, "GET "+b.base+" HTTP/1.1\r\nHost: "+b.host+"\r\n"); e != nil {
			t.Fatal(e)
		}
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge failed to join partial headers on shutdown")
	}
	clock.mu.Lock()
	active := 0
	for _, timer := range clock.timers {
		if timer.active {
			active++
		}
	}
	clock.mu.Unlock()
	if active != 0 {
		t.Fatal("bridge shutdown retained auth timer")
	}
	if c, e := net.DialTimeout("tcp", b.host, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("bridge listener retained")
	}
}

type uiReadyWriter struct {
	ready chan struct{}
	once  sync.Once
}

func (w *uiReadyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.ready) })
	return len(p), nil
}
func TestTypedAdminClientMismatchAndOversizedBodyRemainUnconfirmed(t *testing.T) {
	for _, kind := range []string{"status-mismatch", "oversize", "malformed", "redirect"} {
		socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch kind {
			case "status-mismatch":
				w.WriteHeader(503)
				json.NewEncoder(w).Encode(config.AdminError{Code: "revision_conflict"})
			case "oversize":
				io.WriteString(w, strings.Repeat("x", config.MaxJSONBytes+1))
			case "malformed":
				io.WriteString(w, "broken")
			case "redirect":
				w.Header().Set("Location", "http://external.invalid/")
				w.WriteHeader(302)
			}
		}))
		c := config.NewAdminClient(socket, 1)
		var out config.AdminHealth
		e := c.Request(context.Background(), "GET", "/admin/v1/status", nil, &out)
		c.Close()
		var failure *config.AdminRequestError
		if !errors.As(e, &failure) || failure.Outcome != config.AdminUnconfirmed {
			t.Fatal("unconfirmed outcome certified as rejection", kind)
		}
	}
}
