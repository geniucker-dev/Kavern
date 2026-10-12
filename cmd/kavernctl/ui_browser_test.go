//go:build linux && ui_browser_acceptance

package main

import (
	"context"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestUIActualBrowserReadOnlySecurityAndResponsiveShell(t *testing.T) {
	browser := os.Getenv("UI_BROWSER_BIN")
	if browser == "" {
		t.Fatal("ui_browser_acceptance requires UI_BROWSER_BIN (installed Chromium) and node")
	}
	artifactDir := os.Getenv("UI_BROWSER_ARTIFACT_DIR")
	if artifactDir == "" {
		artifactDir = t.TempDir()
	}
	if e := os.MkdirAll(artifactDir, 0700); e != nil {
		t.Fatal(e)
	}
	device := domain.Device{ID: "workstation", ProjectID: "studio", Name: `Desk <img src=x onerror="window.syntheticInjection=true">`, Enabled: true}
	configuration := domain.DeviceConfiguration{Device: device, Revision: 7, Policy: domain.DefaultNativePolicy(), Tunnels: []domain.Tunnel{{ID: "web", DeviceID: device.ID, Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:0", TargetAddr: "127.0.0.1:8080", Enabled: true}}}
	var fixtureMode atomic.Int64
	socket, _ := onlineFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Host != config.AdminHost || r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" {
			t.Error("fixture received unapproved administration")
		}
		currentDevice := device
		currentConfig := configuration
		if fixtureMode.Load() > 0 {
			currentDevice.Name = "Studio workstation"
			currentConfig.Device = currentDevice
		}
		var data any
		switch r.URL.Path {
		case "/admin/v1/status":
			data = config.AdminHealth{Health: "running"}
		case "/admin/v1/users":
			data = config.AdminPage{Users: []domain.User{{ID: "owner", Name: "Local owner"}}}
		case "/admin/v1/projects":
			data = config.AdminPage{Projects: []domain.Project{{ID: "studio", UserID: "owner", Name: "Studio"}}}
		case "/admin/v1/devices":
			data = config.AdminPage{Devices: []domain.Device{currentDevice, {ID: "travel", ProjectID: "studio", Name: "Travel device", Enabled: true}}}
		case "/admin/v1/devices/workstation/configuration":
			data = currentConfig
		case "/admin/v1/devices/workstation/status":
			data = config.AdminDeviceStatus{Device: currentDevice, UserID: "owner", DesiredRevision: 7, Ready: true, Session: domain.AgentRuntimeStatus{Present: true, Protocol: domain.AgentProtocolKAPv1, AppliedRevision: 7, Ready: true, Carriers: 2, RenewalCount: 3}, Listeners: []config.AdminListener{{TunnelID: "web", State: "bound", BoundAddress: "127.0.0.1:42351", Generation: "1"}}}
		case "/admin/v1/devices/travel/configuration":
			data = domain.DeviceConfiguration{Device: domain.Device{ID: "travel", ProjectID: "studio", Name: "Travel device", Enabled: true}, Revision: 3, Policy: domain.DefaultNativePolicy(), Tunnels: []domain.Tunnel{}}
		case "/admin/v1/devices/travel/status":
			data = config.AdminDeviceStatus{Device: domain.Device{ID: "travel", ProjectID: "studio", Name: "Travel device", Enabled: true}, UserID: "owner", DesiredRevision: 3, Session: domain.AgentRuntimeStatus{}, Listeners: []config.AdminListener{}}
		default:
			w.WriteHeader(404)
			data = config.AdminError{Code: "not_found"}
		}
		if fixtureMode.Load() == 2 {
			if status, ok := data.(config.AdminDeviceStatus); ok && status.Device.ID == "workstation" {
				status.Ready = false
				status.Listeners[0].State = "bind_failed"
				status.Listeners[0].BoundAddress = ""
				status.Listeners[0].RetryAt = "2030-01-01T00:00:00Z"
				data = status
			}
		}
		json.NewEncoder(w).Encode(data)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	b, code, e := newUIBridge(ctx, socket, session.NewClock())
	if e != nil {
		t.Fatal(e)
	}
	defer b.client.Close()
	defer b.auth.close()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	b.host = l.Addr().String()
	b.origin = "http://" + b.host
	launch := b.origin + b.base + "#launch=" + code
	served := make(chan error, 1)
	go func() { served <- serveUI(ctx, b, l, io.Discard, launch) }()
	defer func() {
		cancel()
		select {
		case e := <-served:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("browser fixture bridge not joined")
		}
	}()
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture/ready" {
			fixtureMode.Store(1)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/fixture/bind-failure" {
			fixtureMode.Store(2)
			w.WriteHeader(204)
			return
		}
		io.WriteString(w, "<!doctype html><title>Synthetic attacker</title>")
	}))
	defer attacker.Close()
	command := exec.Command("node", "testdata/ui_browser_acceptance.mjs", browser, filepath.Join(t.TempDir(), "profile"), launch, artifactDir, attacker.URL)
	data, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("browser acceptance failed: %v %s", e, data)
	}
	t.Log(string(data))
	t.Log("Browser used isolated synthetic profile and joined its process; fixture bridge/UDS/listeners are owned by test cleanup.")
}
