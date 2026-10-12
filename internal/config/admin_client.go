package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type AdminOutcome string

const AdminRejected AdminOutcome = "rejected"
const AdminUnconfirmed AdminOutcome = "unconfirmed"

// AdminRequestError deliberately contains no upstream body, credential or URL.
// Only known precommit rejection codes certify that an attempted write was rejected.
type AdminRequestError struct {
	Code    string
	Outcome AdminOutcome
}

func (e *AdminRequestError) Error() string {
	if e.Code == "response_unconfirmed" {
		return "administrator response invalid or unconfirmed"
	}
	return fmt.Sprintf("administrator request: %s", e.Code)
}
func adminOutcome(code string, status int) AdminOutcome {
	expected := map[string][]int{"capacity": {429}, "revision_conflict": {409}, "operation_expired_or_unknown": {409}, "operation_reuse": {409}, "record_conflict": {409}, "cascade_required": {409}, "not_found": {404}, "ownership_conflict": {409}, "invalid_request": {400, 422}}
	matching := false
	for _, v := range expected[code] {
		if status == v {
			matching = true
		}
	}
	if !matching {
		return AdminUnconfirmed
	}
	switch code {
	case "capacity", "revision_conflict", "operation_expired_or_unknown", "operation_reuse", "record_conflict", "cascade_required", "not_found", "ownership_conflict", "invalid_request":
		return AdminRejected
	default:
		return AdminUnconfirmed
	}
}
func knownAdminCode(code string) bool {
	switch code {
	case "commit_uncertain", "closed", "capacity", "revision_conflict", "operation_expired_or_unknown", "operation_reuse", "record_conflict", "cascade_required", "not_found", "request_expired", "ownership_conflict", "invalid_request", "response_capacity":
		return true
	}
	return false
}

type AdminClient struct {
	client    *http.Client
	transport *http.Transport
}

func NewAdminClient(socket string, maxConnections int) *AdminClient {
	if maxConnections < 1 || maxConnections > 4 {
		maxConnections = 1
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return DialAdmin(ctx, socket) }, DisableKeepAlives: true, MaxConnsPerHost: maxConnections, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("administrator redirects forbidden") }}
	return &AdminClient{client, transport}
}
func (c *AdminClient) Close() { c.transport.CloseIdleConnections() }
func (c *AdminClient) Request(ctx context.Context, method, path string, body []byte, dst any) error {
	unconfirmed := func() error { return &AdminRequestError{Code: "response_unconfirmed", Outcome: AdminUnconfirmed} }
	if len(body) > MaxJSONBytes {
		return &AdminRequestError{Code: "invalid_request", Outcome: AdminRejected}
	}
	request, e := http.NewRequestWithContext(ctx, method, "http://"+AdminHost+path, bytes.NewReader(body))
	if e != nil {
		return &AdminRequestError{Code: "invalid_request", Outcome: AdminRejected}
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, e := c.client.Do(request)
	if e != nil {
		return unconfirmed()
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, MaxJSONBytes+1))
	if e != nil || len(data) > MaxJSONBytes {
		return unconfirmed()
	}
	if response.StatusCode != http.StatusOK {
		var failure AdminError
		if DecodeJSON(bytes.NewReader(data), &failure) != nil || !knownAdminCode(failure.Code) {
			return unconfirmed()
		}
		return &AdminRequestError{Code: failure.Code, Outcome: adminOutcome(failure.Code, response.StatusCode)}
	}
	if DecodeJSON(bytes.NewReader(data), dst) != nil {
		return unconfirmed()
	}
	return nil
}
