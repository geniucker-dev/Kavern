package config

import (
	"encoding/base64"
	"github.com/geniucker-dev/kavern/internal/domain"
	"strconv"
)

const AdminMaxConnections = 32
const AdminPageSize = 128
const AdminHost = "kavern-admin"

type AdminWindow struct {
	Lineage string `json:"lineage"`
	Epoch   string `json:"epoch"`
}

func (w AdminWindow) EpochValue() (uint64, error) {
	n, e := strconv.ParseUint(w.Epoch, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != w.Epoch {
		return 0, ErrInvalidJSON
	}
	if w.Lineage != "" {
		if len(w.Lineage) != 22 {
			return 0, ErrInvalidJSON
		}
		raw, e := base64.RawURLEncoding.DecodeString(w.Lineage)
		if e != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != w.Lineage {
			return 0, ErrInvalidJSON
		}
	}
	if w.Lineage == "" && n != 0 {
		return 0, ErrInvalidJSON
	}
	return n, nil
}

type AdminMutation struct {
	Window           AdminWindow                 `json:"window"`
	OperationID      string                      `json:"operation_id"`
	Kind             string                      `json:"kind"`
	User             *domain.User                `json:"user,omitempty"`
	Project          *domain.Project             `json:"project,omitempty"`
	Device           *domain.Device              `json:"device,omitempty"`
	Configuration    *domain.DeviceConfiguration `json:"configuration,omitempty"`
	DeviceID         domain.DeviceID             `json:"device_id,omitempty"`
	ExpectedRevision domain.ConfigRevision       `json:"expected_revision,omitempty"`
	CredentialKind   domain.CredentialKind       `json:"credential_kind,omitempty"`
	Cascade          bool                        `json:"cascade,omitempty"`
}
type AdminResult struct {
	Saved    bool                  `json:"saved"`
	Cleanup  string                `json:"cleanup"`
	Window   AdminWindow           `json:"window"`
	Kind     string                `json:"kind"`
	RecordID string                `json:"record_id"`
	Revision domain.ConfigRevision `json:"revision,omitempty"`
	Replay   bool                  `json:"replay"`
	// Issuance is present only on the original definite creation/rotation response.
	Issuance *AdminIssuance `json:"issuance,omitempty"`
}
type AdminIssuance struct {
	Kind       domain.CredentialKind `json:"kind"`
	Credential string                `json:"credential"`
}
type AdminError struct {
	Code string `json:"code"`
}
type AdminPage struct {
	Users    []domain.User    `json:"users,omitempty"`
	Projects []domain.Project `json:"projects,omitempty"`
	Devices  []domain.Device  `json:"devices,omitempty"`
	Next     string           `json:"next,omitempty"`
}
type AdminHealth struct {
	Health         string `json:"health"`
	CleanupPending bool   `json:"cleanup_pending"`
}
type AdminListener struct {
	TunnelID     domain.TunnelID `json:"tunnel_id"`
	State        string          `json:"state"`
	BoundAddress string          `json:"bound_address,omitempty"`
	Generation   string          `json:"generation,omitempty"`
	RetryAt      string          `json:"retry_at,omitempty"`
}
type AdminCredentialKinds struct {
	DeviceID domain.DeviceID         `json:"device_id"`
	Kinds    []domain.CredentialKind `json:"credential_kinds"`
}

type AdminDeviceStatus struct {
	Device          domain.Device             `json:"device"`
	UserID          domain.UserID             `json:"user_id"`
	DesiredRevision domain.ConfigRevision     `json:"desired_revision"`
	Session         domain.AgentRuntimeStatus `json:"session"`
	Listeners       []AdminListener           `json:"listeners"`
	Ready           bool                      `json:"ready"`
	CleanupPending  bool                      `json:"cleanup_pending"`
}
