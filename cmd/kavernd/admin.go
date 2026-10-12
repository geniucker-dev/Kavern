package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type adminConnection struct {
	net.Conn
	joined sync.Once
}
type adminListener struct {
	net.Listener
	slots   chan struct{}
	workers sync.WaitGroup
	mu      sync.Mutex
	closing bool
	live    map[*adminConnection]struct{}
}

func (l *adminListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if config.CheckAdminPeer(c) != nil {
			c.Close()
			continue
		}
		l.mu.Lock()
		if l.closing {
			l.mu.Unlock()
			c.Close()
			return nil, net.ErrClosed
		}
		select {
		case l.slots <- struct{}{}:
			l.workers.Add(1)
			conn := &adminConnection{Conn: c}
			if l.live == nil {
				l.live = map[*adminConnection]struct{}{}
			}
			l.live[conn] = struct{}{}
			l.mu.Unlock()
			return conn, nil
		default:
			l.mu.Unlock()
			c.Close()
		}
	}
}

// Close also owns accepted sockets that have not reached HTTP StateNew yet.
// Marking closing before taking the snapshot prevents late Accept registration.
func (l *adminListener) Close() error {
	l.mu.Lock()
	l.closing = true
	peers := make([]net.Conn, 0, len(l.live))
	for c := range l.live {
		peers = append(peers, c)
	}
	l.mu.Unlock()
	e := l.Listener.Close()
	for _, c := range peers {
		_ = c.Close()
	}
	return e
}
func (l *adminListener) finish(c *adminConnection) {
	c.joined.Do(func() { l.mu.Lock(); delete(l.live, c); l.mu.Unlock(); <-l.slots; l.workers.Done() })
}
func (s *syncService) runAdmin(ctx context.Context, path string, started chan<- error) error {
	endpoint, e := config.OpenAdminListener(path)
	if e != nil {
		started <- e
		return e
	}
	listener := &adminListener{Listener: endpoint.Listener, slots: make(chan struct{}, config.AdminMaxConnections)}
	server := &http.Server{Handler: http.HandlerFunc(s.adminRequest), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }, ConnState: func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			if v, ok := c.(*adminConnection); ok {
				listener.finish(v)
			}
		}
	}}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	started <- nil
	var serveErr error
	joined := false
	select {
	case <-ctx.Done():
	case serveErr = <-served:
		joined = true
	}
	// Close idle/partial-header sockets immediately on shutdown. Accepted actor
	// work still returns its definitive result; StateClosed joins the actual HTTP
	// connection worker after the handler returns, not merely socket close.
	_ = server.Close()
	_ = listener.Close()

	if !joined {
		serveErr = <-served
	}
	listener.workers.Wait()
	closeErr := endpoint.Close()
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, closeErr)
}
func adminJSON(w http.ResponseWriter, status int, value any) {
	data, e := json.Marshal(value)
	if e != nil || len(data) > config.MaxJSONBytes {
		status = http.StatusInsufficientStorage
		data = []byte(`{"code":"response_capacity"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
func adminError(w http.ResponseWriter, e error) {
	code, status := "invalid_request", http.StatusUnprocessableEntity
	switch {
	case errors.Is(e, store.ErrCommitUncertain):
		code, status = "commit_uncertain", 503
	case errors.Is(e, store.ErrConfigOwnerClosed):
		code, status = "closed", 503
	case errors.Is(e, store.ErrConfigBusy):
		code, status = "capacity", 429
	case errors.Is(e, session.ErrWorkCapacity), errors.Is(e, store.ErrTombstoneCapacity):
		code, status = "capacity", 429
	case errors.Is(e, store.ErrRevisionConflict):
		code, status = "revision_conflict", 409
	case errors.Is(e, store.ErrOperationExpired):
		code, status = "operation_expired_or_unknown", 409
	case errors.Is(e, store.ErrOperationReuse):
		code, status = "operation_reuse", 409
	case errors.Is(e, store.ErrRecordConflict), errors.Is(e, store.ErrListenerConflict):
		code, status = "record_conflict", 409
	case errors.Is(e, store.ErrCascadeRequired):
		code, status = "cascade_required", 409
	case errors.Is(e, store.ErrNotFound):
		code, status = "not_found", 404
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		code, status = "request_expired", 408
	case errors.Is(e, store.ErrTunnelOwnership):
		code, status = "ownership_conflict", 409
	}
	adminJSON(w, status, config.AdminError{Code: code})
}
func adminWindow(w store.ManagementWindow) config.AdminWindow {
	return config.AdminWindow{Lineage: w.Lineage, Epoch: strconv.FormatUint(w.Epoch, 10)}
}
func adminResult(r store.MutationResult, kind domain.CredentialKind) config.AdminResult {
	v := config.AdminResult{Saved: r.Saved, Cleanup: r.Cleanup, Window: adminWindow(r.Window), Kind: r.Kind, RecordID: r.RecordID, Revision: r.Revision, Replay: r.Replay}
	if r.Credential != "" {
		v.Issuance = &config.AdminIssuance{Kind: kind, Credential: r.Credential}
	}
	return v
}
func (s *syncService) adminRequest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.Host != config.AdminHost || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Upgrade")) != 0 || r.ProtoMajor != 1 || r.URL.RawPath != "" || len(r.URL.RawQuery) > 1024 || len(r.URL.Path) > 512 {
		adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
		return
	}
	if r.Method == http.MethodGet {
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
			return
		}
		s.adminGet(ctx, w, r)
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || r.ContentLength > config.MaxJSONBytes {
		adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/admin/v1/recover" {
		var body *struct{}
		if config.DecodeJSON(r.Body, &body) != nil || body == nil {
			adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
			return
		}
		e := s.owner.Recover(ctx)
		if e != nil && !errors.Is(e, session.ErrWorkCleanupPending) {
			adminError(w, e)
			return
		}
		_, pending := s.owner.ManagementHealth(ctx)
		adminJSON(w, 200, config.AdminHealth{Health: "running", CleanupPending: pending})
		return
	}
	expected := ""
	id := domain.DeviceID("")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/v1/"), "/")
	if r.Method == http.MethodPost && len(parts) == 1 {
		switch parts[0] {
		case "users":
			expected = "create_user"
		case "projects":
			expected = "create_project"
		case "devices":
			expected = "create_device"
		}
	}
	if len(parts) == 3 && parts[0] == "devices" && config.ValidID(parts[1]) {
		id = domain.DeviceID(parts[1])
		if r.Method == http.MethodPut && parts[2] == "configuration" {
			expected = "put_device"
		}
		if r.Method == http.MethodPost && parts[2] == "rotate-credential" {
			expected = "rotate_credential"
		}
	}
	if r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "devices" && config.ValidID(parts[1]) {
		expected = "delete_device"
		id = domain.DeviceID(parts[1])
	}
	if expected == "" || !strings.HasPrefix(r.URL.Path, "/admin/v1/") {
		adminJSON(w, 404, config.AdminError{Code: "not_found"})
		return
	}
	var request config.AdminMutation
	if config.DecodeJSON(r.Body, &request) != nil || request.Kind != expected || (id != "" && request.DeviceID != id) {
		adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
		return
	}
	epoch, e := request.Window.EpochValue()
	if e != nil {
		adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
		return
	}
	result, e := s.owner.ApplyMutation(ctx, store.Mutation{Window: store.ManagementWindow{Lineage: request.Window.Lineage, Epoch: epoch}, OperationID: request.OperationID, Kind: request.Kind, User: request.User, Project: request.Project, Device: request.Device, Configuration: request.Configuration, DeviceID: request.DeviceID, ExpectedRevision: request.ExpectedRevision, CredentialKind: request.CredentialKind, Cascade: request.Cascade}, s.adminLegacyKey)
	if e != nil && !result.Saved {
		adminError(w, e)
		return
	}
	adminJSON(w, 200, adminResult(result, request.CredentialKind))
}
func queryOnly(r *http.Request, allowed ...string) bool {
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return false
	}
	set := map[string]bool{}
	for _, k := range allowed {
		if k != "" {
			set[k] = true
		}
	}
	for k, v := range q {
		if !set[k] || len(v) != 1 {
			return false
		}
	}
	return true
}

func (s *syncService) adminGet(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/admin/v1/status" && r.URL.RawQuery == "" {
		health, pending := s.owner.ManagementHealth(ctx)
		adminJSON(w, 200, config.AdminHealth{Health: health, CleanupPending: pending})
		return
	}
	if path == "/admin/v1/window" && r.URL.RawQuery == "" {
		v, e := s.owner.ManagementWindow(ctx)
		if e != nil {
			adminError(w, e)
			return
		}
		adminJSON(w, 200, adminWindow(v))
		return
	}
	if path == "/admin/v1/users" || path == "/admin/v1/projects" || path == "/admin/v1/devices" {
		kind := strings.TrimPrefix(path, "/admin/v1/")
		parentKey := ""
		if kind == "projects" {
			parentKey = "user_id"
		}
		if kind == "devices" {
			parentKey = "project_id"
		}
		if !queryOnly(r, "after", parentKey) {
			adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
			return
		}
		page, e := s.owner.ListRecords(ctx, kind, r.URL.Query().Get("after"), r.URL.Query().Get(parentKey))
		if e != nil {
			adminError(w, e)
			return
		}
		adminJSON(w, 200, config.AdminPage{Users: page.Users, Projects: page.Projects, Devices: page.Devices, Next: page.Next})
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/admin/v1/"), "/")
	if strings.HasPrefix(path, "/admin/v1/") && len(parts) == 2 && parts[0] == "operations" && config.ValidID(parts[1]) && queryOnly(r, "lineage", "epoch") {
		window := config.AdminWindow{Lineage: r.URL.Query().Get("lineage"), Epoch: r.URL.Query().Get("epoch")}
		epoch, e := window.EpochValue()
		if e != nil {
			adminJSON(w, 400, config.AdminError{Code: "invalid_request"})
			return
		}
		result, e := s.owner.LookupOperation(ctx, store.ManagementWindow{Lineage: window.Lineage, Epoch: epoch}, parts[1])
		if e != nil {
			adminError(w, e)
			return
		}
		adminJSON(w, 200, adminResult(result, ""))
		return
	}
	if len(parts) == 3 && parts[0] == "devices" && config.ValidID(parts[1]) && r.URL.RawQuery == "" {
		id := domain.DeviceID(parts[1])
		c, e := s.owner.DeviceConfiguration(ctx, id)
		if e != nil {
			adminError(w, e)
			return
		}
		switch parts[2] {
		case "configuration":
			adminJSON(w, 200, c)
			return
		case "status":
			user, e := s.owner.DeviceUser(ctx, id)
			if e != nil {
				adminError(w, e)
				return
			}
			runtime := s.auth.DeviceRuntimeStatus(ctx, id)
			listeners := []config.AdminListener{}
			allBound := true
			statuses := map[domain.TunnelID]config.AdminListener{}
			for _, v := range s.public.Status() {
				status := config.AdminListener{TunnelID: v.TunnelID, State: v.State, BoundAddress: v.BoundAddress}
				if v.Generation != 0 {
					status.Generation = strconv.FormatUint(v.Generation, 10)
				}
				if !v.RetryAt.IsZero() {
					status.RetryAt = v.RetryAt.UTC().Format(time.RFC3339Nano)
				}
				statuses[v.TunnelID] = status
			}
			for _, t := range c.Tunnels {
				v, ok := statuses[t.ID]
				if !ok {
					v = config.AdminListener{TunnelID: t.ID, State: "pending"}
				}
				if t.Enabled && v.State != "bound" {
					allBound = false
				}
				listeners = append(listeners, v)
			}
			latest, e := s.owner.DeviceConfiguration(ctx, id)
			if e != nil {
				adminError(w, e)
				return
			}
			if latest.Revision != c.Revision {
				runtime.Ready = false
				allBound = false
			}
			pending := s.owner.DeviceCleanupPending(id)
			adminJSON(w, 200, config.AdminDeviceStatus{Device: c.Device, UserID: user, DesiredRevision: c.Revision, Session: runtime, Listeners: listeners, Ready: c.Device.Enabled && runtime.Ready && runtime.AppliedRevision == c.Revision && allBound, CleanupPending: pending})
			return
		}
	}
	adminJSON(w, 404, config.AdminError{Code: "not_found"})
}
