package agent_v1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

type syncAuthFrame struct {
	Version     string           `json:"version"`
	Role        string           `json:"role"`
	Type        string           `json:"type"`
	SyncVersion *int             `json:"config_sync_version,omitempty"`
	DeviceID    domain.DeviceID  `json:"device_id,omitempty"`
	ClientNonce string           `json:"client_nonce,omitempty"`
	ServerNonce string           `json:"server_nonce,omitempty"`
	ChallengeID string           `json:"auth_challenge_id,omitempty"`
	Response    string           `json:"response_hmac,omitempty"`
	SessionID   domain.SessionID `json:"session_id,omitempty"`
	Code        string           `json:"code,omitempty"`
}

func authFrame(kind string) syncAuthFrame {
	version := ConfigSyncVersion
	return syncAuthFrame{Version: ProtocolVersion, Role: TransportRoleControl, Type: kind, SyncVersion: &version}
}
func decodeSyncAuth(data []byte) (syncAuthFrame, error) {
	var f syncAuthFrame
	if len(data) == 0 || len(data) > MaxControlFrameBytes || config.DecodeJSON(bytes.NewReader(data), &f) != nil {
		return f, ErrSyncTransfer
	}
	if f.Version != ProtocolVersion || f.Role != TransportRoleControl {
		return f, ErrSyncTransfer
	}
	if f.SyncVersion == nil || *f.SyncVersion != ConfigSyncVersion {
		return f, ErrSyncSchema
	}
	keys := []string{"version", "role", "type", "config_sync_version"}
	switch f.Type {
	case "auth_start":
		keys = append(keys, "device_id", "client_nonce")
	case "auth_challenge":
		keys = append(keys, "device_id", "server_nonce", "auth_challenge_id")
	case "auth_finish":
		keys = append(keys, "device_id", "auth_challenge_id", "response_hmac")
	case "auth_ok":
		keys = append(keys, "device_id", "session_id")
	case "auth_reject":
		keys = append(keys, "code")
	default:
		return f, ErrSyncTransfer
	}
	if !exactKeys(data, keys...) {
		return f, ErrSyncTransfer
	}
	if f.Type == "auth_reject" {
		if f.Code != "upgrade_required" && f.Code != "authentication_failed" {
			return f, ErrSyncTransfer
		}
		return f, nil
	}
	if !config.ValidID(string(f.DeviceID)) {
		return f, ErrSyncTransfer
	}
	switch f.Type {
	case "auth_start":
		if validateToken(f.ClientNonce) != nil {
			return f, ErrSyncTransfer
		}
	case "auth_challenge":
		if validateToken(f.ServerNonce) != nil || validateToken(f.ChallengeID) != nil {
			return f, ErrSyncTransfer
		}
	case "auth_finish":
		if validateToken(f.ChallengeID) != nil || f.Response == "" {
			return f, ErrSyncTransfer
		}
	case "auth_ok":
		if validateToken(string(f.SessionID)) != nil {
			return f, ErrSyncTransfer
		}
	}
	return f, nil
}
func readSyncAuth(r io.Reader) (syncAuthFrame, error) {
	data, err := readSyncTransportPayload(r)
	if err != nil {
		return syncAuthFrame{}, err
	}
	return decodeSyncAuth(data)
}
func readSyncTransportPayload(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxControlFrameBytes {
		return nil, ErrSyncTransfer
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
func writeSyncAuth(w io.Writer, f syncAuthFrame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return ErrSyncTransfer
	}
	if _, err = decodeSyncAuth(data); err != nil {
		return err
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	for _, part := range [][]byte{prefix[:], data} {
		n, err := w.Write(part)
		if err != nil {
			return err
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}
