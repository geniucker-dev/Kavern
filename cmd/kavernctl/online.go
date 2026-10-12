package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/config"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func onlineHTTP(ctx context.Context, socket, method, path string, body []byte, dst any) error {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return config.DialAdmin(ctx, socket) }, DisableKeepAlives: true, MaxConnsPerHost: 1, ResponseHeaderTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("administrator redirects forbidden") }}
	request, e := http.NewRequestWithContext(ctx, method, "http://"+config.AdminHost+path, bytes.NewReader(body))
	if e != nil {
		return errors.New("invalid administrator request")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, e := client.Do(request)
	if e != nil {
		return errors.New("administrator response unconfirmed; use the exact original request window and operation ID for lookup/retry")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, config.MaxJSONBytes+1))
	if e != nil || len(data) > config.MaxJSONBytes {
		return errors.New("administrator response invalid or unconfirmed")
	}
	if response.StatusCode != 200 {
		var failure config.AdminError
		if config.DecodeJSON(bytes.NewReader(data), &failure) != nil {
			return errors.New("administrator request failed")
		}
		switch failure.Code {
		case "commit_uncertain", "closed", "capacity", "revision_conflict", "operation_expired_or_unknown", "operation_reuse", "record_conflict", "cascade_required", "not_found", "request_expired", "ownership_conflict", "invalid_request", "response_capacity":
			return fmt.Errorf("administrator request: %s", failure.Code)
		default:
			return errors.New("administrator request failed")
		}
	}
	if config.DecodeJSON(bytes.NewReader(data), dst) != nil {
		return errors.New("administrator response invalid or unconfirmed")
	}
	return nil
}
func mutationEndpoint(kind, device string) (string, string, error) {
	switch kind {
	case "create_user":
		return "POST", "/admin/v1/users", nil
	case "create_project":
		return "POST", "/admin/v1/projects", nil
	case "create_device":
		return "POST", "/admin/v1/devices", nil
	case "put_device", "rotate_credential", "delete_device":
		if !config.ValidID(device) {
			break
		}
		base := "/admin/v1/devices/" + device
		switch kind {
		case "put_device":
			return "PUT", base + "/configuration", nil
		case "rotate_credential":
			return "POST", base + "/rotate-credential", nil
		case "delete_device":
			return "DELETE", base, nil
		}
	}
	return "", "", errors.New("invalid mutation kind or device")
}
func runOnline(args []string, out, diagnostics io.Writer) error {
	fs := flag.NewFlagSet("online", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	socket := fs.String("socket", "", "private daemon Unix socket")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	remaining := fs.Args()
	if *socket == "" || len(remaining) == 0 {
		return errors.New("online requires --socket PATH and command")
	}
	action := remaining[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	id := flags.String("id", "", "record ID")
	after := flags.String("after", "", "pagination cursor")
	parent := flags.String("parent", "", "owning user/project ID")
	file := flags.String("file", "", "strict mutation request JSON; preserve its exact window/operation ID for retry")
	lineage := flags.String("lineage", "", "original operation lineage")
	epoch := flags.String("epoch", "", "original operation epoch")
	credentialPath := flags.String("credential-output", "", "new file in a private directory for once-only issuance")
	if e := flags.Parse(remaining[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected online arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	emit := func(v any) error { return json.NewEncoder(out).Encode(v) }
	switch action {
	case "status":
		var v config.AdminHealth
		if e := onlineHTTP(ctx, *socket, "GET", "/admin/v1/status", nil, &v); e != nil {
			return e
		}
		return emit(v)
	case "window":
		var v config.AdminWindow
		if e := onlineHTTP(ctx, *socket, "GET", "/admin/v1/window", nil, &v); e != nil {
			return e
		}
		return emit(v)
	case "users", "projects", "devices":
		query := url.Values{}
		if *after != "" {
			query.Set("after", *after)
		}
		if *parent != "" {
			if action == "projects" {
				query.Set("user_id", *parent)
			} else if action == "devices" {
				query.Set("project_id", *parent)
			} else {
				return errors.New("users has no parent filter")
			}
		}
		var v config.AdminPage
		path := "/admin/v1/" + action
		if len(query) > 0 {
			path += "?" + query.Encode()
		}
		if e := onlineHTTP(ctx, *socket, "GET", path, nil, &v); e != nil {
			return e
		}
		return emit(v)
	case "get-device", "device-status":
		if !config.ValidID(*id) {
			return errors.New("valid --id required")
		}
		suffix := "configuration"
		if action == "device-status" {
			suffix = "status"
		}
		path := "/admin/v1/devices/" + *id + "/" + suffix
		if action == "device-status" {
			var v config.AdminDeviceStatus
			if e := onlineHTTP(ctx, *socket, "GET", path, nil, &v); e != nil {
				return e
			}
			return emit(v)
		}
		var v json.RawMessage
		if e := onlineHTTP(ctx, *socket, "GET", path, nil, &v); e != nil {
			return e
		}
		return emit(v)
	case "operation":
		if !config.ValidID(*id) {
			return errors.New("valid --id required")
		}
		window := config.AdminWindow{Lineage: *lineage, Epoch: *epoch}
		if _, e := window.EpochValue(); e != nil {
			return errors.New("original --lineage and canonical --epoch required")
		}
		v, e := lookupOnline(ctx, *socket, *id, window)
		if e != nil {
			return e
		}
		return emit(v)
	case "recover":
		var v config.AdminHealth
		if e := onlineHTTP(ctx, *socket, "POST", "/admin/v1/recover", []byte("{}"), &v); e != nil {
			return e
		}
		return emit(v)
	}
	kinds := map[string]string{"create-user": "create_user", "create-project": "create_project", "create-device": "create_device", "put-device": "put_device", "rotate-device": "rotate_credential", "delete-device": "delete_device"}
	expected, known := kinds[action]
	if !known && action != "retry" {
		return errors.New("unknown online command")
	}
	input, e := config.OpenAdminRequestFile(*file)
	if e != nil {
		return errors.New("mutation request file unavailable")
	}
	var request config.AdminMutation
	e = config.DecodeJSON(input, &request)
	input.Close()
	if e != nil || (!known && action != "retry") || (known && request.Kind != expected) {
		return errors.New("invalid mutation request")
	}
	if _, e = request.Window.EpochValue(); e != nil || !config.ValidID(request.OperationID) {
		return errors.New("original window and operation ID required")
	}
	method, path, e := mutationEndpoint(request.Kind, string(request.DeviceID))
	if e != nil {
		return e
	}
	if action == "retry" {
		if *credentialPath != "" {
			return errors.New("retry does not issue or recover credentials")
		}
		if _, e = lookupOnline(ctx, *socket, request.OperationID, request.Window); e != nil {
			return e
		}
	}
	var outputFile *os.File
	issuance := request.Kind == "create_device" || request.Kind == "rotate_credential"
	if issuance && action != "retry" {
		if *credentialPath == "" {
			return errors.New("issuance requires --credential-output in a private directory")
		}
		outputFile, e = config.CreatePrivateCredentialFile(*credentialPath)
		if e != nil {
			return errors.New("credential output must be a new file in a private owned directory")
		}
		defer outputFile.Close()
		if _, e = outputFile.Write([]byte("{\"delivery\":\"unconfirmed\"}\n")); e != nil || outputFile.Sync() != nil {
			return errors.New("credential destination could not be prepared")
		}
	}
	data, e := json.Marshal(request)
	if e != nil || len(data) > config.MaxJSONBytes {
		return errors.New("invalid mutation request")
	}
	var result config.AdminResult
	if e = onlineHTTP(ctx, *socket, method, path, data, &result); e != nil {
		return e
	}
	if result.Issuance != nil {
		if outputFile == nil || result.Replay || !result.Saved {
			return errors.New("unexpected issuance; credential delivery unconfirmed")
		}
		credential, _ := json.Marshal(struct {
			DeviceID string               `json:"device_id"`
			Issuance config.AdminIssuance `json:"issuance"`
		}{result.RecordID, *result.Issuance})
		if e = outputFile.Truncate(0); e == nil {
			_, e = outputFile.WriteAt(append(credential, '\n'), 0)
		}
		if e != nil || outputFile.Sync() != nil || config.VerifyPrivateCredentialFile(*credentialPath, outputFile) != nil {
			return errors.New("saved mutation; credential delivery unconfirmed, explicitly rotate again to obtain a new credential")
		}
	} else if outputFile != nil {
		marker := []byte("{\"delivery\":\"not_reissued\"}\n")
		if outputFile.Truncate(0) != nil {
			return errors.New("credential marker write failed")
		}
		if _, e = outputFile.WriteAt(marker, 0); e != nil || outputFile.Sync() != nil {
			return errors.New("credential marker write failed")
		}
	}
	result.Issuance = nil
	return emit(result)
}
func lookupOnline(ctx context.Context, socket, id string, w config.AdminWindow) (config.AdminResult, error) {
	query := url.Values{"lineage": {w.Lineage}, "epoch": {w.Epoch}}
	var r config.AdminResult
	e := onlineHTTP(ctx, socket, "GET", "/admin/v1/operations/"+id+"?"+query.Encode(), nil, &r)
	return r, e
}
