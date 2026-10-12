//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func onlineFixture(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	os.Mkdir(dir, 0700)
	path := filepath.Join(dir, "a.sock")
	endpoint, e := config.OpenAdminListener(path)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: handler}
	joined := make(chan struct{})
	go func() { defer close(joined); _ = server.Serve(endpoint.Listener) }()
	close := func() { server.Close(); <-joined; endpoint.Close() }
	t.Cleanup(close)
	return path, close
}
func TestOnlineProtectedIssuanceNeverAppearsOnStdout(t *testing.T) {
	secret := strings.Repeat("synthetic-", 4)
	calls := 0
	path, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(config.AdminResult{Saved: true, Cleanup: "complete", Window: config.AdminWindow{Lineage: "lineage", Epoch: "1"}, Kind: "create_device", RecordID: "device", Revision: 1, Issuance: &config.AdminIssuance{Kind: domain.CredentialKindKAPv1DeviceSecret, Credential: secret}})
	}))
	dir := filepath.Dir(path)
	input := filepath.Join(dir, "request.json")
	data, _ := json.Marshal(config.AdminMutation{Window: config.AdminWindow{Epoch: "0"}, OperationID: "op", Kind: "create_device", Device: &domain.Device{ID: "device", ProjectID: "project"}, CredentialKind: domain.CredentialKindKAPv1DeviceSecret})
	os.WriteFile(input, data, 0600)
	output := filepath.Join(dir, "credential.json")
	var out, diag bytes.Buffer
	args := []string{"--socket", path, "create-device", "--file", input, "--credential-output", output}
	if e := runOnline(args, &out, &diag); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(out.Bytes(), []byte(secret)) || bytes.Contains(diag.Bytes(), []byte(secret)) || bytes.Contains(out.Bytes(), []byte("issuance")) {
		t.Fatal("credential exposed outside protected file")
	}
	file, e := os.ReadFile(output)
	if e != nil || !bytes.Contains(file, []byte(secret)) {
		t.Fatal("protected output missing")
	}
	if e = runOnline(args, &out, &diag); e == nil || calls != 1 {
		t.Fatal("existing output overwritten or mutation sent before preflight")
	}
}
func TestOnlineRetryUsesOriginalWindowAndNeverReissues(t *testing.T) {
	calls := 0
	path, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == "GET" && r.URL.Query().Get("epoch") != "0" {
			t.Error("lookup did not preserve request epoch")
		}
		json.NewEncoder(w).Encode(config.AdminResult{Saved: true, Cleanup: "unknown", Window: config.AdminWindow{Lineage: "lineage", Epoch: "1"}, Kind: "create_user", RecordID: "user", Replay: true})
	}))
	input := filepath.Join(filepath.Dir(path), "request.json")
	data, _ := json.Marshal(config.AdminMutation{Window: config.AdminWindow{Epoch: "0"}, OperationID: "op", Kind: "create_user", User: &domain.User{ID: "user"}})
	os.WriteFile(input, data, 0600)
	var out, diag bytes.Buffer
	if e := runOnline([]string{"--socket", path, "retry", "--file", input}, &out, &diag); e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatal("explicit retry did not verify then resubmit exact request")
	}
	// An expired/unknown lookup stops before any mutation is sent.
	expiredCalls := 0
	other, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expiredCalls++
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(config.AdminError{Code: "operation_expired_or_unknown"})
	}))
	if e := runOnline([]string{"--socket", other, "retry", "--file", input}, &out, &diag); e == nil || expiredCalls != 1 {
		t.Fatal("expired operation reapplied")
	}
}
func TestOnlineRejectsBlockingRequestFilesAndRedactsErrors(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "request")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	var out, diag bytes.Buffer
	if e := runOnline([]string{"--socket", "/unused", "create-user", "--file", fifo}, &out, &diag); e == nil {
		t.Fatal("FIFO accepted")
	}
	path, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(config.AdminError{Code: "commit_uncertain"})
	}))
	if e := onlineHTTP(context.Background(), path, "GET", "/admin/v1/window", nil, &config.AdminWindow{}); e == nil || e.Error() != "administrator request: commit_uncertain" {
		t.Fatal("uncertainty semantics lost")
	}
}
