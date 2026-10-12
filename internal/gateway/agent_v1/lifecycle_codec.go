package agent_v1

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"io"
	"strings"
)

const LifecycleVersion = 1
const MaxLifecycleFrameBytes = 1024
const LifecycleLeaseMillis = 90000
const LifecycleProofMillis = 15000
const LifecycleAuthMillis = 5000

var ErrLifecycle = errors.New("invalid or unsupported native lifecycle frame")
var ErrLifecycleExpired = errors.New("native lifecycle expired or revoked")
var ErrLifecycleStale = errors.New("stale native lifecycle frame")
var ErrLifecycleQuota = errors.New("native lifecycle frame quota exceeded")

type LifecycleFrame struct {
	Version          string                `json:"version"`
	SyncVersion      int                   `json:"config_sync_version"`
	LifecycleVersion int                   `json:"lifecycle_version"`
	Type             string                `json:"type"`
	Role             string                `json:"role"`
	DeviceID         domain.DeviceID       `json:"device_id"`
	SessionID        domain.SessionID      `json:"session_id,omitempty"`
	ClientNonce      string                `json:"client_nonce,omitempty"`
	ServerNonce      string                `json:"server_nonce,omitempty"`
	ChallengeID      string                `json:"auth_challenge_id,omitempty"`
	CarrierNonce     string                `json:"carrier_nonce,omitempty"`
	Generation       domain.ConfigRevision `json:"generation,omitempty"`
	Nonce            string                `json:"nonce,omitempty"`
	LeaseMillis      int                   `json:"lease_ms,omitempty"`
	ProofMillis      int                   `json:"proof_budget_ms,omitempty"`
	RemainingMillis  int                   `json:"remaining_ms,omitempty"`
	HMAC             string                `json:"hmac,omitempty"`
	Code             string                `json:"code,omitempty"`
}

func lifecycleFrame(kind string, id domain.DeviceID, session domain.SessionID) LifecycleFrame {
	return LifecycleFrame{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, LifecycleVersion: LifecycleVersion, Type: kind, Role: TransportRoleControl, DeviceID: id, SessionID: session}
}
func lifecycleToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, e := base64.RawURLEncoding.DecodeString(value)
	return e == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
func lifecycleMAC(value string) bool {
	if len(value) != 64 {
		return false
	}
	raw, e := hex.DecodeString(value)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}
func DecodeLifecycleFrame(data []byte) (LifecycleFrame, error) {
	var f LifecycleFrame
	if len(data) == 0 || len(data) > MaxLifecycleFrameBytes || config.DecodeJSON(bytes.NewReader(data), &f) != nil {
		return f, ErrLifecycle
	}
	keys := []string{"version", "config_sync_version", "lifecycle_version", "type", "role", "device_id"}
	auth := []string{"client_nonce", "server_nonce", "auth_challenge_id", "lease_ms", "proof_budget_ms"}
	switch f.Type {
	case "auth_start":
		keys = append(keys, "client_nonce")
		if f.Role != TransportRoleControl || !lifecycleToken(f.ClientNonce) {
			return f, ErrLifecycle
		}
	case "auth_challenge", "auth_finish", "auth_ok":
		keys = append(keys, auth...)
		if f.Type != "auth_challenge" {
			keys = append(keys, "hmac")
			if !lifecycleMAC(f.HMAC) {
				return f, ErrLifecycle
			}
		}
		if f.Role != TransportRoleControl || !lifecycleToken(f.ClientNonce) || !lifecycleToken(f.ServerNonce) || !lifecycleToken(f.ChallengeID) || f.LeaseMillis != LifecycleLeaseMillis || f.ProofMillis != LifecycleAuthMillis {
			return f, ErrLifecycle
		}
		if f.Type == "auth_ok" {
			keys = append(keys, "session_id", "generation", "remaining_ms")
			if f.Generation != 1 || !lifecycleToken(string(f.SessionID)) || f.RemainingMillis < 1 || f.RemainingMillis > LifecycleLeaseMillis {
				return f, ErrLifecycle
			}
		}
	case "carrier_bind", "carrier_ok":
		keys = append(keys, "session_id", "carrier_nonce", "hmac")
		if f.Role != TransportRoleDataCarrier || !lifecycleToken(string(f.SessionID)) || !lifecycleToken(f.CarrierNonce) || !lifecycleMAC(f.HMAC) {
			return f, ErrLifecycle
		}
	case "renew_challenge", "renew_response", "renew_ok":
		keys = append(keys, "session_id", "generation", "nonce", "lease_ms", "proof_budget_ms")
		if f.Type != "renew_challenge" {
			keys = append(keys, "hmac")
			if !lifecycleMAC(f.HMAC) {
				return f, ErrLifecycle
			}
		}
		if f.Type == "renew_ok" {
			keys = append(keys, "remaining_ms")
			if f.RemainingMillis < 1 || f.RemainingMillis > LifecycleLeaseMillis {
				return f, ErrLifecycle
			}
		}
		if f.Role != TransportRoleControl || !lifecycleToken(string(f.SessionID)) || f.Generation < 2 || !lifecycleToken(f.Nonce) || f.LeaseMillis != LifecycleLeaseMillis || f.ProofMillis != LifecycleProofMillis {
			return f, ErrLifecycle
		}
	case "auth_reject":
		keys = append(keys, "code")
		if f.Role != TransportRoleControl || f.Code != "upgrade_required" {
			return f, ErrLifecycle
		}
	default:
		return f, ErrLifecycle
	}
	if !exactKeys(data, keys...) || f.Version != ProtocolVersion || f.SyncVersion != ConfigSyncVersion || f.LifecycleVersion != LifecycleVersion || !config.ValidID(string(f.DeviceID)) {
		return f, ErrLifecycle
	}
	return f, nil
}
func EncodeLifecycleFrame(f LifecycleFrame) ([]byte, error) {
	data, e := json.Marshal(f)
	if e != nil {
		return nil, ErrLifecycle
	}
	if _, e = DecodeLifecycleFrame(data); e != nil {
		return nil, e
	}
	return data, nil
}
func ReadLifecycleFrame(r io.Reader) (LifecycleFrame, error) {
	var prefix [4]byte
	if _, e := io.ReadFull(r, prefix[:]); e != nil {
		return LifecycleFrame{}, e
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxLifecycleFrameBytes {
		return LifecycleFrame{}, ErrLifecycle
	}
	data := make([]byte, int(n))
	if _, e := io.ReadFull(r, data); e != nil {
		return LifecycleFrame{}, e
	}
	return DecodeLifecycleFrame(data)
}
func WriteLifecycleFrame(w io.Writer, f LifecycleFrame) error {
	data, e := EncodeLifecycleFrame(f)
	if e != nil {
		return e
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	if e = writeLifecycleBytes(w, prefix[:]); e != nil {
		return e
	}
	return writeLifecycleBytes(w, data)
}
func writeLifecycleBytes(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, e := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Transcripts authenticate negotiated versions and budgets as well as identity.
// Secret, MAC and timers are never part of the serialized grant cache/state file.
func CanonicalLifecycleTranscript(f LifecycleFrame) ([]byte, error) {
	kind := f.Type
	switch kind {
	case "auth_finish", "auth_ok", "carrier_bind", "carrier_ok", "renew_response", "renew_ok":
	default:
		return nil, ErrLifecycle
	}
	f.HMAC = strings.Repeat("0", 64)
	if _, e := EncodeLifecycleFrame(f); e != nil {
		return nil, e
	}
	purpose := map[string]string{"auth_finish": "authenticate", "auth_ok": "initial-grant", "carrier_bind": "carrier-bind", "carrier_ok": "carrier-bound", "renew_response": "renew-proof", "renew_ok": "renew-grant"}[kind]
	base := fmt.Sprintf("kapv1/%s/%s\nprotocol_version=%s\nconfig_sync_version=%d\nlifecycle_version=%d\ndevice_id=%s\n", f.Role, purpose, f.Version, f.SyncVersion, f.LifecycleVersion, f.DeviceID)
	switch kind {
	case "auth_finish", "auth_ok":
		base += fmt.Sprintf("client_nonce=%s\nserver_nonce=%s\nauth_challenge_id=%s\nlease_ms=%d\nproof_budget_ms=%d\n", f.ClientNonce, f.ServerNonce, f.ChallengeID, f.LeaseMillis, f.ProofMillis)
		if kind == "auth_ok" {
			base += fmt.Sprintf("session_id=%s\ngeneration=%d\nremaining_ms=%d\n", f.SessionID, f.Generation, f.RemainingMillis)
		}
	case "carrier_bind", "carrier_ok":
		base += fmt.Sprintf("session_id=%s\ncarrier_nonce=%s\n", f.SessionID, f.CarrierNonce)
	default:
		base += fmt.Sprintf("session_id=%s\ngeneration=%d\nnonce=%s\nlease_ms=%d\nproof_budget_ms=%d\n", f.SessionID, f.Generation, f.Nonce, f.LeaseMillis, f.ProofMillis)
		if kind == "renew_ok" {
			base += fmt.Sprintf("remaining_ms=%d\n", f.RemainingMillis)
		}
	}
	return []byte(base), nil
}
func SignLifecycleFrame(secret []byte, f LifecycleFrame) (LifecycleFrame, error) {
	if len(secret) != 32 {
		return LifecycleFrame{}, ErrAuthFailed
	}
	msg, e := CanonicalLifecycleTranscript(f)
	if e != nil {
		return LifecycleFrame{}, e
	}
	f.HMAC, e = signHMAC(secret, msg)
	return f, e
}
func VerifyLifecycleFrame(secret []byte, f LifecycleFrame) error {
	if len(secret) != 32 || !lifecycleMAC(f.HMAC) {
		return ErrAuthFailed
	}
	msg, e := CanonicalLifecycleTranscript(f)
	if e != nil {
		return e
	}
	return verifyHMAC(secret, f.HMAC, msg)
}

// Negotiated snapshot envelopes keep schema 1 and the existing byte ceiling.
// Integration must account these encoded bytes in transfer/staging totals.
func encodeLifecycleSyncPayload(f syncFrame) ([]byte, error) {
	data, e := encodeSyncPayload(f)
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	fields["lifecycle_version"] = json.RawMessage("1")
	data, e = json.Marshal(fields)
	if e != nil || len(data) > MaxControlFrameBytes {
		return nil, ErrSyncCapacity
	}
	return data, nil
}
func decodeLifecycleSyncPayload(data []byte) (syncFrame, error) {
	if len(data) == 0 || len(data) > MaxControlFrameBytes {
		return syncFrame{}, ErrSyncCapacity
	}
	var fields map[string]json.RawMessage
	if config.DecodeJSON(bytes.NewReader(data), &fields) != nil {
		return syncFrame{}, ErrSyncTransfer
	}
	var version int
	if json.Unmarshal(fields["lifecycle_version"], &version) != nil || version != LifecycleVersion {
		return syncFrame{}, ErrSyncSchema
	}
	delete(fields, "lifecycle_version")
	base, e := json.Marshal(fields)
	if e != nil {
		return syncFrame{}, ErrSyncTransfer
	}
	return decodeSyncPayload(base)
}
