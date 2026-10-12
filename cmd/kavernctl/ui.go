package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"

	"io"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed ui_assets/index.html ui_assets/app.js ui_assets/style.css
var uiAssets embed.FS

const uiRequestHeader = "X-Kavern-UI-Token"
const uiMaxForwards = 4
const uiMaxConnections = 32

type uiAuth struct {
	mu                            sync.Mutex
	clock                         session.Clock
	code, cookie, token           [32]byte
	bootstrap, sessionActive      bool
	codeEnd, idleEnd, absoluteEnd time.Time
	idle, absolute                time.Duration
	timer                         session.Timer
	ticket                        uint64
}

func uiRandom(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func uiDigest(value string) ([32]byte, bool) {
	if len(value) != 43 {
		return [32]byte{}, false
	}
	b, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != value {
		return [32]byte{}, false
	}
	return sha256.Sum256(b), true
}
func uiEqual(a, b [32]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }
func (a *uiAuth) clearLocked() {
	a.bootstrap = false
	a.sessionActive = false
	a.code = [32]byte{}
	a.cookie = [32]byte{}
	a.token = [32]byte{}
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if a.ticket < math.MaxUint64 {
		a.ticket++
	}
}
func (a *uiAuth) armLocked() {
	if a.timer != nil {
		a.timer.Stop()
	}
	if a.ticket == math.MaxUint64 {
		a.clearLocked()
		return
	}
	a.ticket++
	ticket := a.ticket
	end := a.codeEnd
	if a.sessionActive {
		end = a.idleEnd
		if a.absoluteEnd.Before(end) {
			end = a.absoluteEnd
		}
	}
	delay := end.Sub(a.clock.Now())
	if delay < 0 {
		delay = 0
	}
	a.timer = a.clock.AfterFunc(delay, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if ticket != a.ticket {
			return
		}
		now := a.clock.Now()
		if (a.bootstrap && !now.Before(a.codeEnd)) || (a.sessionActive && (!now.Before(a.idleEnd) || !now.Before(a.absoluteEnd))) {
			a.clearLocked()
		}
	})
}
func (a *uiAuth) exchange(code string) (string, string, bool) {
	codeHash, ok := uiDigest(code)
	if !ok {
		return "", "", false
	}
	cookie, e := uiRandom(32)
	if e != nil {
		return "", "", false
	}
	token, e := uiRandom(32)
	if e != nil {
		return "", "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock.Now()
	if !a.bootstrap || !now.Before(a.codeEnd) || !uiEqual(codeHash, a.code) {
		return "", "", false
	}
	a.bootstrap = false
	a.code = [32]byte{}
	a.cookie, _ = uiDigest(cookie)
	a.token, _ = uiDigest(token)
	a.sessionActive = true
	a.idleEnd = now.Add(a.idle)
	a.absoluteEnd = now.Add(a.absolute)
	a.armLocked()
	return cookie, token, true
}
func (a *uiAuth) check(cookie, token string, activity bool) bool {
	c, ok := uiDigest(cookie)
	if !ok {
		return false
	}
	t, ok := uiDigest(token)
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock.Now()
	if !a.sessionActive {
		return false
	}
	if !now.Before(a.idleEnd) || !now.Before(a.absoluteEnd) {
		a.clearLocked()
		return false
	}
	if !uiEqual(c, a.cookie) || !uiEqual(t, a.token) {
		return false
	}
	if activity {
		a.idleEnd = now.Add(a.idle)
		a.armLocked()
	}
	return true
}
func (a *uiAuth) close() { a.mu.Lock(); defer a.mu.Unlock(); a.clearLocked() }

type uiBridge struct {
	client                         *config.AdminClient
	auth                           *uiAuth
	host, origin, base, cookieName string
	forwards                       chan struct{}
}

func newUIBridge(ctx context.Context, socket string, clock session.Clock) (*uiBridge, string, error) {
	client := config.NewAdminClient(socket, uiMaxForwards)
	var health config.AdminHealth
	if e := client.Request(ctx, http.MethodGet, "/admin/v1/status", nil, &health); e != nil {
		client.Close()
		return nil, "", errors.New("cannot verify private daemon administrator endpoint")
	}
	instance, e := uiRandom(16)
	if e != nil {
		client.Close()
		return nil, "", errors.New("cannot initialize browser session")
	}
	code, e := uiRandom(32)
	if e != nil {
		client.Close()
		return nil, "", errors.New("cannot initialize browser session")
	}
	auth := &uiAuth{clock: clock, bootstrap: true, codeEnd: clock.Now().Add(120 * time.Second), idle: 10 * time.Minute, absolute: time.Hour}
	auth.code, _ = uiDigest(code)
	auth.mu.Lock()
	auth.armLocked()
	auth.mu.Unlock()
	return &uiBridge{client: client, auth: auth, base: "/ui/" + instance + "/", cookieName: "kavern_ui_" + instance, forwards: make(chan struct{}, uiMaxForwards)}, code, nil
}
func uiJSON(w http.ResponseWriter, status int, value any) {
	data, e := json.Marshal(value)
	if e != nil || len(data) > config.MaxJSONBytes {
		status = 502
		data = []byte(`{"code":"response_unconfirmed","outcome":"unconfirmed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
func uiFailure(w http.ResponseWriter, status int, code string) {
	uiJSON(w, status, struct {
		Code string `json:"code"`
	}{code})
}
func (b *uiBridge) boundary(r *http.Request, private bool) bool {
	peer, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || peer != "127.0.0.1" || r.Host != b.host || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.URL.IsAbs() || r.URL.RawPath != "" || len(r.URL.Path) > 512 || len(r.URL.RawQuery) > 1024 {
		return false
	}
	for _, h := range []string{"Upgrade", "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-For", "Authorization"} {
		if len(r.Header.Values(h)) != 0 {
			return false
		}
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != b.origin) {
		return false
	}
	if r.Method != http.MethodGet && (len(origins) != 1 || origins[0] != b.origin) {
		return false
	}
	if private {
		sites := r.Header.Values("Sec-Fetch-Site")
		if len(sites) > 1 || (len(sites) == 1 && sites[0] != "same-origin") {
			return false
		}
	}
	return true
}
func (b *uiBridge) credentials(r *http.Request) (string, string, bool) {
	cookies := r.Cookies()
	cookie := ""
	count := 0
	for _, c := range cookies {
		if c.Name == b.cookieName {
			cookie = c.Value
			count++
		}
	}
	tokens := r.Header.Values(uiRequestHeader)
	if count != 1 || len(tokens) != 1 {
		return "", "", false
	}
	return cookie, tokens[0], true
}
func (b *uiBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'none'")
	path := strings.TrimPrefix(r.URL.Path, b.base)
	private := strings.HasPrefix(path, "api/") || strings.HasPrefix(path, "session/")
	if !b.boundary(r, private) {
		uiFailure(w, 403, "browser_boundary")
		return
	}
	if !strings.HasPrefix(r.URL.Path, b.base) {
		uiFailure(w, 404, "not_found")
		return
	}
	if !private {
		if r.Method != "GET" || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			uiFailure(w, 400, "invalid_request")
			return
		}
		file, kind := "", ""
		switch path {
		case "":
			file = "index.html"
			kind = "text/html; charset=utf-8"
		case "app.js":
			file = "app.js"
			kind = "text/javascript; charset=utf-8"
		case "style.css":
			file = "style.css"
			kind = "text/css; charset=utf-8"
		default:
			uiFailure(w, 404, "not_found")
			return
		}
		data, e := uiAssets.ReadFile("ui_assets/" + file)
		if e != nil || len(data) > 256<<10 {
			uiFailure(w, 500, "asset_unavailable")
			return
		}
		w.Header().Set("Content-Type", kind)
		_, _ = w.Write(data)
		return
	}
	if path == "session/bootstrap" {
		if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.ContentLength > 1024 {
			uiFailure(w, 400, "invalid_request")
			return
		}
		var body *struct {
			Code string `json:"code"`
		}
		if config.DecodeJSON(http.MaxBytesReader(w, r.Body, 1024), &body) != nil || body == nil {
			uiFailure(w, 400, "invalid_request")
			return
		}
		if _, ok := uiDigest(body.Code); !ok {
			uiFailure(w, 400, "invalid_request")
			return
		}
		cookie, token, ok := b.auth.exchange(body.Code)
		if !ok {
			uiFailure(w, 401, "session_expired")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: b.cookieName, Value: cookie, Path: b.base, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		uiJSON(w, 200, struct {
			Token    string `json:"request_token"`
			Idle     int    `json:"idle_seconds"`
			Absolute int    `json:"absolute_seconds"`
		}{token, 600, 3600})
		return
	}
	cookie, token, ok := b.credentials(r)
	if !ok || !b.auth.check(cookie, token, false) {
		uiFailure(w, 401, "session_expired")
		return
	}
	if strings.HasPrefix(path, "session/") {
		if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.ContentLength > 1024 {
			uiFailure(w, 400, "invalid_request")
			return
		}
		var empty *struct{}
		if config.DecodeJSON(http.MaxBytesReader(w, r.Body, 1024), &empty) != nil || empty == nil {
			uiFailure(w, 400, "invalid_request")
			return
		}
		switch path {
		case "session/activity":
			if !b.auth.check(cookie, token, true) {
				uiFailure(w, 401, "session_expired")
				return
			}
		case "session/logout":
			b.auth.close()
			http.SetCookie(w, &http.Cookie{Name: b.cookieName, Value: "", Path: b.base, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		default:
			uiFailure(w, 404, "not_found")
			return
		}
		uiJSON(w, 200, struct {
			OK bool `json:"ok"`
		}{true})
		return
	}
	if r.Method != "GET" {
		uiFailure(w, 405, "read_only")
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Content-Encoding") != "" {
		uiFailure(w, 400, "invalid_request")
		return
	}
	endpoint, dst, ok := uiReadEndpoint(strings.TrimPrefix(path, "api/"), r.URL.RawQuery)
	if !ok {
		uiFailure(w, 404, "not_found")
		return
	}
	select {
	case b.forwards <- struct{}{}:
		defer func() { <-b.forwards }()
	default:
		uiFailure(w, 429, "capacity")
		return
	}
	if e := b.client.Request(r.Context(), "GET", endpoint, nil, dst); e != nil {
		var failure *config.AdminRequestError
		code, outcome := "response_unconfirmed", config.AdminUnconfirmed
		if errors.As(e, &failure) {
			code, outcome = failure.Code, failure.Outcome
		}
		uiJSON(w, 502, struct {
			Code    string              `json:"code"`
			Outcome config.AdminOutcome `json:"outcome"`
		}{code, outcome})
		return
	}
	uiJSON(w, 200, dst)
}
func uiReadEndpoint(path, query string) (string, any, bool) {
	var dst any
	allowed := []string{}
	switch path {
	case "status":
		dst = &config.AdminHealth{}
	case "users":
		dst = &config.AdminPage{}
		allowed = []string{"after"}
	case "projects":
		dst = &config.AdminPage{}
		allowed = []string{"after", "user_id"}
	case "devices":
		dst = &config.AdminPage{}
		allowed = []string{"after", "project_id"}
	default:
		parts := strings.Split(path, "/")
		if len(parts) != 3 || parts[0] != "devices" || !config.ValidID(parts[1]) {
			return "", nil, false
		}
		switch parts[2] {
		case "configuration":
			dst = &domainDeviceConfiguration{}
		case "status":
			dst = &config.AdminDeviceStatus{}
		default:
			return "", nil, false
		}
	}
	q, e := url.ParseQuery(query)
	if e != nil {
		return "", nil, false
	}
	for k, v := range q {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
			}
		}
		if !found || len(v) != 1 || (v[0] != "" && !config.ValidID(v[0])) {
			return "", nil, false
		}
	}
	endpoint := "/admin/v1/" + path
	if query != "" {
		endpoint += "?" + q.Encode()
	}
	return endpoint, dst, true
}

// Alias keeps the forwarded device DTO identical to the daemon's complete snapshot.
type domainDeviceConfiguration = domain.DeviceConfiguration

func runUI(args []string, out, diagnostics io.Writer) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	socket := fs.String("socket", "", "private daemon Unix socket (read-only UI)")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if *socket == "" || fs.NArg() != 0 {
		return errors.New("ui requires --socket PATH and no additional arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	bridge, code, e := newUIBridge(ctx, *socket, session.NewClock())
	if e != nil {
		return e
	}
	defer bridge.client.Close()
	defer bridge.auth.close()
	socketListener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return errors.New("cannot bind local browser endpoint")
	}
	bridge.host = socketListener.Addr().String()
	bridge.origin = "http://" + bridge.host
	launch := bridge.origin + bridge.base + "#launch=" + code
	code = ""
	return serveUI(ctx, bridge, socketListener, out, launch)
}
