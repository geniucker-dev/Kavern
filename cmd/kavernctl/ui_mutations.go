package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"net/http"
	"os"
	"path/filepath"
)

type uiMutation struct {
	Request *config.AdminMutation `json:"request"`
	Retry   bool                  `json:"retry"`
}
type uiMutationResult struct {
	Result         config.AdminResult `json:"result"`
	Delivery       string             `json:"delivery"`
	CredentialPath string             `json:"credential_path,omitempty"`
}

func uiAdminFailure(w http.ResponseWriter, e error) {
	var failure *config.AdminRequestError
	code, outcome := "response_unconfirmed", config.AdminUnconfirmed
	if errors.As(e, &failure) {
		code, outcome = failure.Code, failure.Outcome
	}
	uiJSON(w, 502, struct {
		Code    string              `json:"code"`
		Outcome config.AdminOutcome `json:"outcome"`
	}{code, outcome})
}
func (b *uiBridge) mutate(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.ContentLength > config.MaxJSONBytes {
		uiMutationRejected(w, "invalid_request")
		return
	}
	select {
	case b.forwards <- struct{}{}:
		defer func() { <-b.forwards }()
	default:
		uiFailure(w, 429, "capacity")
		return
	}
	body := http.MaxBytesReader(w, r.Body, config.MaxJSONBytes)
	if path == "api/recover" {
		var empty *struct{}
		if config.DecodeJSON(body, &empty) != nil || empty == nil {
			uiMutationRejected(w, "invalid_request")
			return
		}
		var health config.AdminHealth
		if e := b.client.Request(r.Context(), "POST", "/admin/v1/recover", []byte("{}"), &health); e != nil {
			uiAdminFailure(w, e)
			return
		}
		uiJSON(w, 200, health)
		return
	}
	var envelope *uiMutation
	if config.DecodeJSON(body, &envelope) != nil || envelope == nil || envelope.Request == nil {
		uiMutationRejected(w, "invalid_request")
		return
	}
	m := envelope.Request
	if _, e := m.Window.EpochValue(); e != nil || !config.ValidID(m.OperationID) {
		uiMutationRejected(w, "invalid_request")
		return
	}
	method, endpoint, e := mutationEndpoint(m.Kind, string(m.DeviceID))
	if e != nil {
		uiMutationRejected(w, "invalid_request")
		return
	}
	if path == "api/lookup" {
		receipt, e := b.exactReceipt(r.Context(), m)
		if e != nil {
			uiAdminFailure(w, e)
			return
		}
		uiJSON(w, 200, receipt)
		return
	}
	issuance := m.Kind == "create_device" || m.Kind == "rotate_credential"
	if issuance && m.CredentialKind != domain.CredentialKindKAPv1DeviceSecret {
		uiMutationRejected(w, "invalid_request")
		return
	}
	// Issuance retry only resolves a retained exact receipt. It never forwards
	// a mutation, including after response loss, eviction, or a never-sent original.
	if issuance && envelope.Retry {
		receipt, e := b.exactReceipt(r.Context(), m)
		if e != nil {
			uiAdminFailure(w, e)
			return
		}
		uiJSON(w, 200, uiMutationResult{Result: receipt, Delivery: "not_reissued"})
		return
	}
	// The browser never controls a filename. Reserve before dispatch and never
	// overwrite, recover or deliver credentials on an explicit retained retry.
	var file *os.File
	destination := ""
	if issuance && !envelope.Retry {
		if b.credentialDir == "" {
			uiMutationRejected(w, "credential_directory_required")
			return
		}
		destination = filepath.Join(b.credentialDir, "kavern-"+m.OperationID+".json")
		file, e = config.CreatePrivateCredentialFile(destination)
		if e != nil {
			uiMutationRejected(w, "credential_destination_unavailable")
			return
		}
		defer file.Close()
		if _, e = file.Write([]byte("{\"delivery\":\"unconfirmed\"}\n")); e != nil || file.Sync() != nil || config.VerifyPrivateCredentialFile(destination, file) != nil {
			uiMutationRejected(w, "credential_destination_unavailable")
			return
		}
	}
	data, e := json.Marshal(m)
	if e != nil {
		uiMutationRejected(w, "invalid_request")
		return
	}
	var result config.AdminResult
	if e = b.client.Request(r.Context(), method, endpoint, data, &result); e != nil {
		uiAdminFailure(w, e)
		return
	}
	expectedID := string(m.DeviceID)
	if m.User != nil && m.Kind == "create_user" {
		expectedID = string(m.User.ID)
	}
	if m.Project != nil && m.Kind == "create_project" {
		expectedID = string(m.Project.ID)
	}
	if m.Device != nil && m.Kind == "create_device" {
		expectedID = string(m.Device.ID)
	}
	if !result.Saved || result.Kind != m.Kind || result.RecordID != expectedID || expectedID == "" {
		uiAdminFailure(w, &config.AdminRequestError{Code: "response_unconfirmed", Outcome: config.AdminUnconfirmed})
		return
	}
	delivery := "not_applicable"
	if issuance {
		delivery = "not_reissued"
	}
	if result.Issuance != nil {
		if !issuance || envelope.Retry || result.Replay || file == nil || result.Issuance.Kind != domain.CredentialKindKAPv1DeviceSecret {
			uiAdminFailure(w, &config.AdminRequestError{Code: "response_unconfirmed", Outcome: config.AdminUnconfirmed})
			return
		}
		if _, ok := uiDigest(result.Issuance.Credential); !ok {
			uiAdminFailure(w, &config.AdminRequestError{Code: "response_unconfirmed", Outcome: config.AdminUnconfirmed})
			return
		}
		delivery = "unconfirmed"
		payload, _ := json.Marshal(struct {
			DeviceID string               `json:"device_id"`
			Issuance config.AdminIssuance `json:"issuance"`
		}{result.RecordID, *result.Issuance})
		if e = file.Truncate(0); e == nil {
			_, e = file.WriteAt(append(payload, '\n'), 0)
		}
		if e == nil && file.Sync() == nil && config.VerifyPrivateCredentialFile(destination, file) == nil {
			delivery = "protected_file"
		}
	} else if file != nil {
		delivery = "unconfirmed"
	}
	result.Issuance = nil
	if !result.Saved || result.Kind != m.Kind {
		uiAdminFailure(w, &config.AdminRequestError{Code: "response_unconfirmed", Outcome: config.AdminUnconfirmed})
		return
	}
	uiJSON(w, 200, uiMutationResult{Result: result, Delivery: delivery, CredentialPath: destination})
}

func uiMutationRejected(w http.ResponseWriter, code string) {
	uiJSON(w, 400, struct {
		Code    string              `json:"code"`
		Outcome config.AdminOutcome `json:"outcome"`
	}{code, config.AdminRejected})
}

// exactReceipt is a bounded read, never an issuance or replay submission.
func (b *uiBridge) exactReceipt(ctx context.Context, m *config.AdminMutation) (config.AdminResult, error) {
	fail := func() (config.AdminResult, error) {
		return config.AdminResult{}, &config.AdminRequestError{Code: "response_unconfirmed", Outcome: config.AdminUnconfirmed}
	}
	data, e := json.Marshal(m)
	if e != nil || len(data) > config.MaxJSONBytes {
		return fail()
	}
	var receipt config.AdminResult
	if e = b.client.Request(ctx, "POST", "/admin/v1/operations/lookup", data, &receipt); e != nil {
		return config.AdminResult{}, e
	}
	expected := string(m.DeviceID)
	switch m.Kind {
	case "create_user":
		if m.User != nil {
			expected = string(m.User.ID)
		}
	case "create_project":
		if m.Project != nil {
			expected = string(m.Project.ID)
		}
	case "create_device":
		if m.Device != nil {
			expected = string(m.Device.ID)
		}
	}
	if receipt.Issuance != nil || !receipt.Saved || !receipt.Replay || receipt.Kind != m.Kind || expected == "" || receipt.RecordID != expected {
		return fail()
	}
	return receipt, nil
}
