//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUIMutationIssuanceRedactionRetryAndRejectedBoundary(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32))
	var writes atomic.Int64
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get(uiRequestHeader) != "" {
			t.Error("browser authority forwarded")
		}
		if r.URL.Path == "/admin/v1/status" {
			json.NewEncoder(w).Encode(config.AdminHealth{Health: "running"})
			return
		}
		var m config.AdminMutation
		if config.DecodeJSON(r.Body, &m) != nil {
			t.Error("mutation malformed")
			return
		}
		if r.URL.Path == "/admin/v1/operations/lookup" {
			json.NewEncoder(w).Encode(config.AdminResult{Saved: true, Kind: m.Kind, RecordID: "new-device", Revision: 1, Replay: true})
			return
		}
		n := writes.Add(1)
		result := config.AdminResult{Saved: true, Kind: m.Kind, RecordID: "new-device", Revision: 1, Window: config.AdminWindow{Lineage: "", Epoch: "0"}, Replay: n > 1}
		if n == 1 {
			result.Issuance = &config.AdminIssuance{Kind: domain.CredentialKindKAPv1DeviceSecret, Credential: secret}
		}
		json.NewEncoder(w).Encode(result)
	}))
	b, code, e := newUIBridge(context.Background(), socket, session.NewClock())
	if e != nil {
		t.Fatal(e)
	}
	defer b.auth.close()
	defer b.client.Close()
	b.host = "127.0.0.1:12345"
	b.origin = "http://" + b.host
	dir := filepath.Join(t.TempDir(), "private")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	b.credentialDir = dir
	cookie, token := uiBootstrap(t, b, code)
	request := `{"window":{"lineage":"","epoch":"0"},"operation_id":"browser-op","kind":"create_device","device":{"ID":"new-device","ProjectID":"project","Enabled":true},"credential_kind":"kapv1_device_secret"}`
	send := func(body string, change func(*http.Request)) *httptest.ResponseRecorder {
		r := uiRequest(b, "POST", "api/mutations", body)
		authorize(r, cookie, token)
		if change != nil {
			change(r)
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	for _, bad := range []func(*http.Request){func(r *http.Request) { r.Header.Del(uiRequestHeader) }, func(r *http.Request) { r.Header.Set("Origin", "null") }, func(r *http.Request) { r.Host = "evil" }} {
		if w := send(`{"request":`+request+`,"retry":false}`, bad); w.Code == 200 {
			t.Fatal("mutation auth boundary bypass")
		}
	}
	if writes.Load() != 0 {
		t.Fatal("bad request dispatched")
	}
	w := send(`{"request":`+request+`,"retry":false}`, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "issuance") {
		t.Fatal("issuance exposed or save failed", w.Code)
	}
	file := filepath.Join(dir, "kavern-browser-op.json")
	data, e := os.ReadFile(file)
	if e != nil || !strings.Contains(string(data), secret) {
		t.Fatal("protected delivery missing")
	}
	st, _ := os.Stat(file)
	if st.Mode().Perm() != 0600 {
		t.Fatal("credential mode")
	}
	w = send(`{"request":`+request+`,"retry":false}`, nil)
	if w.Code == 200 || writes.Load() != 1 {
		t.Fatal("original request overwrote protected output")
	}
	w = send(`{"request":`+request+`,"retry":true}`, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), "not_reissued") {
		t.Fatal("retry delivery boundary")
	}
	again, _ := os.ReadFile(file)
	if string(again) != string(data) {
		t.Fatal("retry changed protected output")
	}
	for _, body := range []string{`null`, `{"request":null}`, `{"request":` + request + `,"secret":"forbidden"}`, `{"request":` + request + `,"retry":false,"retry":true}`} {
		if w := send(body, nil); w.Code == 200 {
			t.Fatal("invalid mutation accepted")
		}
	}
}
func TestUIMutationOutcomesAndReceiptIssuanceNeverLeak(t *testing.T) {
	var mode atomic.Int64
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/status" {
			json.NewEncoder(w).Encode(config.AdminHealth{Health: "running"})
			return
		}
		switch mode.Load() {
		case 0:
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(config.AdminError{Code: "revision_conflict"})
		case 1:
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(config.AdminError{Code: "commit_uncertain"})
		case 2:
			json.NewEncoder(w).Encode(config.AdminResult{Saved: true, Kind: "put_device", RecordID: "device", Revision: 1, Issuance: &config.AdminIssuance{Kind: domain.CredentialKindKAPv1DeviceSecret, Credential: "synthetic-unexpected-secret"}})
		case 3:
			w.Write([]byte(`{"code":"revision_conflict","credential":"synthetic-unexpected-secret"}`))
		}
	}))
	b, code, e := newUIBridge(context.Background(), socket, session.NewClock())
	if e != nil {
		t.Fatal(e)
	}
	defer b.auth.close()
	defer b.client.Close()
	b.host = "127.0.0.1:12345"
	b.origin = "http://" + b.host
	cookie, token := uiBootstrap(t, b, code)
	for _, test := range []struct {
		mode    int64
		outcome string
	}{{0, "rejected"}, {1, "unconfirmed"}, {2, "unconfirmed"}, {3, "unconfirmed"}} {
		mode.Store(test.mode)
		r := uiRequest(b, "POST", "api/mutations", `{"request":{"window":{"lineage":"","epoch":"0"},"operation_id":"op","kind":"put_device","device_id":"device","expected_revision":"1"},"retry":false}`)
		authorize(r, cookie, token)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 502 || strings.Contains(w.Body.String(), "synthetic-unexpected-secret") || !strings.Contains(w.Body.String(), test.outcome) {
			t.Fatal("unsafe outcome or leakage", test.mode, w.Code)
		}
	}
	mode.Store(2)
	r := uiRequest(b, "GET", "api/operations/op", "")
	r.URL.RawQuery = "lineage=&epoch=0"
	authorize(r, cookie, token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 502 || strings.Contains(w.Body.String(), "synthetic-unexpected-secret") {
		t.Fatal("receipt issuance forwarded")
	}
}

func TestUIFreshIssuanceRetryCannotExecuteWithoutDelivery(t *testing.T) {
	var writes atomic.Int32
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/status" {
			json.NewEncoder(w).Encode(config.AdminHealth{Health: "running"})
			return
		}
		if r.URL.Path == "/admin/v1/operations/lookup" {
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(config.AdminError{Code: "operation_expired_or_unknown"})
			return
		}
		writes.Add(1)
		json.NewEncoder(w).Encode(config.AdminResult{Saved: true, Kind: "create_device", RecordID: "new-device", Revision: 1, Issuance: &config.AdminIssuance{Kind: domain.CredentialKindKAPv1DeviceSecret, Credential: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32))}})
	}))
	b, code, e := newUIBridge(context.Background(), socket, session.NewClock())
	if e != nil {
		t.Fatal(e)
	}
	defer b.auth.close()
	defer b.client.Close()
	b.host = "127.0.0.1:12345"
	b.origin = "http://" + b.host
	cookie, token := uiBootstrap(t, b, code)
	r := uiRequest(b, "POST", "api/mutations", `{"request":{"window":{"lineage":"","epoch":"0"},"operation_id":"never-dispatched","kind":"create_device","device":{"ID":"new-device","ProjectID":"project","Enabled":true},"credential_kind":"kapv1_device_secret"},"retry":true}`)
	authorize(r, cookie, token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if writes.Load() != 0 {
		t.Fatalf("fresh retry bypassed credential destination and executed %d mutation; browser status=%d outcome=%s", writes.Load(), w.Code, w.Body.String())
	}
}
func TestUIIssuanceReservesUnconfirmedMarkerBeforeDispatch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	destination := filepath.Join(dir, "kavern-marker-op.json")
	var found atomic.Bool
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/v1/status" {
			json.NewEncoder(w).Encode(config.AdminHealth{Health: "running"})
			return
		}
		data, e := os.ReadFile(destination)
		found.Store(e == nil && bytes.Contains(data, []byte(`"delivery":"unconfirmed"`)))
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(config.AdminError{Code: "commit_uncertain"})
	}))
	b, code, e := newUIBridge(context.Background(), socket, session.NewClock())
	if e != nil {
		t.Fatal(e)
	}
	defer b.auth.close()
	defer b.client.Close()
	b.host = "127.0.0.1:12345"
	b.origin = "http://" + b.host
	b.credentialDir = dir
	cookie, token := uiBootstrap(t, b, code)
	r := uiRequest(b, "POST", "api/mutations", `{"request":{"window":{"lineage":"","epoch":"0"},"operation_id":"marker-op","kind":"create_device","device":{"ID":"new-device","ProjectID":"project","Enabled":true},"credential_kind":"kapv1_device_secret"},"retry":false}`)
	authorize(r, cookie, token)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if !found.Load() {
		data, _ := os.ReadFile(destination)
		t.Fatalf("issuance dispatched with no synced unconfirmed marker; retained bytes=%q", data)
	}
}

func TestUIIssuanceRetryOnlyResolvesExactReceipt(t *testing.T) {
	for _, kind := range []string{"create_device", "rotate_credential"} {
		for _, mode := range []string{"missing", "retained", "wrong_record", "unexpected_issuance"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				var writes, lookups atomic.Int32
				socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/admin/v1/status" {
						json.NewEncoder(w).Encode(config.AdminHealth{Health: "running"})
						return
					}
					if r.URL.Path != "/admin/v1/operations/lookup" {
						writes.Add(1)
						w.WriteHeader(500)
						return
					}
					lookups.Add(1)
					var m config.AdminMutation
					if config.DecodeJSON(r.Body, &m) != nil || m.OperationID != "retained-original" || m.Kind != kind {
						t.Error("original request changed during receipt read")
					}
					if mode == "missing" {
						w.WriteHeader(409)
						json.NewEncoder(w).Encode(config.AdminError{Code: "operation_expired_or_unknown"})
						return
					}
					receipt := config.AdminResult{Saved: true, Replay: true, Kind: kind, RecordID: "new-device", Revision: 1}
					if mode == "wrong_record" {
						receipt.RecordID = "other-device"
					}
					if mode == "unexpected_issuance" {
						receipt.Issuance = &config.AdminIssuance{Kind: domain.CredentialKindKAPv1DeviceSecret, Credential: "synthetic-unexpected-material"}
					}
					json.NewEncoder(w).Encode(receipt)
				}))
				b, code, e := newUIBridge(context.Background(), socket, session.NewClock())
				if e != nil {
					t.Fatal(e)
				}
				defer b.auth.close()
				defer b.client.Close()
				b.host = "127.0.0.1:12345"
				b.origin = "http://" + b.host
				cookie, token := uiBootstrap(t, b, code)
				m := config.AdminMutation{Window: config.AdminWindow{Epoch: "0"}, OperationID: "retained-original", Kind: kind, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}
				if kind == "create_device" {
					m.Device = &domain.Device{ID: "new-device", ProjectID: "project", Enabled: true}
				} else {
					m.DeviceID = "new-device"
					m.ExpectedRevision = 1
				}
				body, _ := json.Marshal(uiMutation{Request: &m, Retry: true})
				r := uiRequest(b, "POST", "api/mutations", string(body))
				authorize(r, cookie, token)
				w := httptest.NewRecorder()
				b.ServeHTTP(w, r)
				if writes.Load() != 0 || lookups.Load() != 1 {
					t.Fatal("issuance retry was not read-only", writes.Load(), lookups.Load())
				}
				if mode == "retained" {
					if w.Code != 200 || !strings.Contains(w.Body.String(), "not_reissued") {
						t.Fatal("retained issuance receipt not resolved")
					}
				} else if w.Code == 200 {
					t.Fatal("unsafe issuance receipt accepted", mode)
				}
				if strings.Contains(w.Body.String(), "synthetic-unexpected-material") {
					t.Fatal("receipt material leaked")
				}
			})
		}
	}
}
