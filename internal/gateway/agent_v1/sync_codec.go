package agent_v1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

const MaxSyncTransferBytes = 1 << 20

type syncPolicy struct {
	Carriers    int `json:"carriers"`
	MaxStreams  int `json:"max_streams"`
	MaxInflight int `json:"max_inflight"`
	MaxBuffer   int `json:"max_buffer"`
}

func wirePolicy(p domain.NativePolicy) *syncPolicy {
	return &syncPolicy{p.Carriers, p.MaxStreams, p.MaxInflight, p.MaxBuffer}
}
func (p syncPolicy) domain() domain.NativePolicy {
	return domain.NativePolicy{Carriers: p.Carriers, MaxStreams: p.MaxStreams, MaxInflight: p.MaxInflight, MaxBuffer: p.MaxBuffer}
}

type syncTunnel struct {
	ID         domain.TunnelID       `json:"tunnel_id"`
	Protocol   domain.TunnelProtocol `json:"protocol"`
	TargetAddr string                `json:"target_addr"`
}
type syncFrame struct {
	Version      string                 `json:"version"`
	SyncVersion  int                    `json:"config_sync_version"`
	Type         string                 `json:"type"`
	DeviceID     domain.DeviceID        `json:"device_id"`
	SessionID    domain.SessionID       `json:"session_id"`
	Revision     *domain.ConfigRevision `json:"revision,omitempty"`
	TransferID   *domain.ConfigRevision `json:"transfer_id,omitempty"`
	Count        *uint16                `json:"count,omitempty"`
	TotalBytes   *uint32                `json:"total_bytes,omitempty"`
	Index        *uint16                `json:"index,omitempty"`
	Policy       *syncPolicy            `json:"policy,omitempty"`
	Tunnel       *syncTunnel            `json:"tunnel,omitempty"`
	CarrierCount *uint8                 `json:"carrier_count,omitempty"`
	Code         string                 `json:"code,omitempty"`
}
type syncTuple struct {
	DeviceID             domain.DeviceID
	SessionID            domain.SessionID
	Revision, TransferID domain.ConfigRevision
}

func (f syncFrame) tuple() syncTuple {
	if f.Revision == nil || f.TransferID == nil {
		return syncTuple{}
	}
	return syncTuple{f.DeviceID, f.SessionID, *f.Revision, *f.TransferID}
}
func scopedFrame(kind string, tuple syncTuple) syncFrame {
	return syncFrame{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, Type: kind, DeviceID: tuple.DeviceID, SessionID: tuple.SessionID, Revision: &tuple.Revision, TransferID: &tuple.TransferID}
}
func heartbeatFrame(kind string, auth SyncAuthResult) syncFrame {
	return syncFrame{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, Type: kind, DeviceID: auth.DeviceID, SessionID: auth.SessionID}
}

func exactKeys(data []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
func decodeSyncPayload(data []byte) (syncFrame, error) {
	var f syncFrame
	if len(data) == 0 || len(data) > MaxControlFrameBytes || config.DecodeJSON(bytes.NewReader(data), &f) != nil {
		return f, ErrSyncTransfer
	}
	keys := []string{"version", "config_sync_version", "type", "device_id", "session_id"}
	switch f.Type {
	case "config_begin":
		keys = append(keys, "revision", "transfer_id", "count", "total_bytes", "policy")
	case "config_tunnel":
		keys = append(keys, "revision", "transfer_id", "index", "tunnel")
	case "config_end":
		keys = append(keys, "revision", "transfer_id", "count", "total_bytes")
	case "config_ack":
		keys = append(keys, "revision", "transfer_id")
	case "ready", "ready_ok":
		keys = append(keys, "revision", "transfer_id", "carrier_count")
	case "config_reject":
		keys = append(keys, "revision", "transfer_id", "code")
	case "ping", "pong":
	default:
		return f, ErrSyncTransfer
	}
	if !exactKeys(data, keys...) || f.Version != ProtocolVersion || f.SyncVersion != ConfigSyncVersion || !config.ValidID(string(f.DeviceID)) || validateToken(string(f.SessionID)) != nil {
		return f, ErrSyncTransfer
	}
	if f.Type == "ping" || f.Type == "pong" {
		return f, nil
	}
	if f.Revision == nil || f.TransferID == nil || *f.Revision == 0 || *f.TransferID == 0 {
		return f, ErrSyncTransfer
	}
	if f.Type == "config_begin" || f.Type == "config_end" {
		if f.Count == nil || *f.Count > config.MaxNativeTunnels || f.TotalBytes == nil || *f.TotalBytes == 0 || *f.TotalBytes > MaxSyncTransferBytes {
			return f, ErrSyncTransfer
		}
	}
	if f.Type == "ready" || f.Type == "ready_ok" {
		if f.CarrierCount == nil || *f.CarrierCount < 1 || *f.CarrierCount > 4 {
			return f, ErrSyncTransfer
		}
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	if f.Type == "config_begin" {
		if f.Policy == nil || !exactKeys(raw["policy"], "carriers", "max_streams", "max_inflight", "max_buffer") || config.ValidateNativePolicy(f.Policy.domain()) != nil {
			return f, ErrSyncTransfer
		}
	}
	if f.Type == "config_tunnel" {
		if f.Index == nil || *f.Index >= config.MaxNativeTunnels || f.Tunnel == nil || !exactKeys(raw["tunnel"], "tunnel_id", "protocol", "target_addr") {
			return f, ErrSyncTransfer
		}
		snapshot := domain.NativeSnapshot{DeviceID: f.DeviceID, Revision: *f.Revision, Policy: domain.DefaultNativePolicy(), Tunnels: []domain.NativeTunnel{{ID: f.Tunnel.ID, Protocol: f.Tunnel.Protocol, TargetAddr: f.Tunnel.TargetAddr}}}
		if config.ValidateNativeSnapshot(snapshot) != nil {
			return f, ErrSyncTransfer
		}
	}
	if f.Type == "config_reject" && f.Code != "invalid_config" && f.Code != "capacity" && f.Code != "unsupported" {
		return f, ErrSyncTransfer
	}
	return f, nil
}
func encodeSyncPayload(f syncFrame) ([]byte, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, ErrSyncTransfer
	}
	if _, err = decodeSyncPayload(data); err != nil {
		return nil, err
	}
	return data, nil
}
func readSyncFrame(r io.Reader) (syncFrame, int, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return syncFrame{}, 0, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxControlFrameBytes {
		return syncFrame{}, 0, ErrSyncTransfer
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return syncFrame{}, 0, err
	}
	f, err := decodeSyncPayload(data)
	return f, len(data), err
}
func writeSyncFrame(w io.Writer, f syncFrame) error {
	data, err := encodeSyncPayload(f)
	if err != nil {
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

// Only the snapshot is retained. Entries are generated one at a time; no
// transfer-sized frame queue is built. Total includes begin/entry/end payloads.
type syncPlan struct {
	tuple     syncTuple
	snapshot  domain.NativeSnapshot
	total     uint32
	lifecycle int
}

func newSyncPlan(auth SyncAuthResult, snapshot domain.NativeSnapshot, transfer domain.ConfigRevision) (*syncPlan, error) {
	if auth.ConfigSyncVersion != ConfigSyncVersion || snapshot.DeviceID != auth.DeviceID || validateToken(string(auth.SessionID)) != nil || transfer == 0 || config.ValidateNativeSnapshot(snapshot) != nil {
		return nil, ErrSyncTransfer
	}
	snapshot.Tunnels = append([]domain.NativeTunnel(nil), snapshot.Tunnels...)
	p := &syncPlan{tuple: syncTuple{auth.DeviceID, auth.SessionID, snapshot.Revision, transfer}, snapshot: snapshot, total: 1, lifecycle: auth.LifecycleVersion}
	for attempt := 0; attempt < 8; attempt++ {
		total := uint64(0)
		for i := 0; i < p.frames(); i++ {
			data, err := encodeNegotiatedSyncPayload(p.frame(i), p.lifecycle)
			if err != nil {
				return nil, err
			}
			total += uint64(len(data))
			if total > MaxSyncTransferBytes {
				return nil, ErrSyncCapacity
			}
		}
		if uint32(total) == p.total {
			return p, nil
		}
		p.total = uint32(total)
	}
	return nil, ErrSyncTransfer
}
func (p *syncPlan) frames() int { return len(p.snapshot.Tunnels) + 2 }
func (p *syncPlan) frame(i int) syncFrame {
	count := uint16(len(p.snapshot.Tunnels))
	total := p.total
	if i == 0 {
		f := scopedFrame("config_begin", p.tuple)
		f.Count = &count
		f.TotalBytes = &total
		f.Policy = wirePolicy(p.snapshot.Policy)
		return f
	}
	if i == p.frames()-1 {
		f := scopedFrame("config_end", p.tuple)
		f.Count = &count
		f.TotalBytes = &total
		return f
	}
	t := p.snapshot.Tunnels[i-1]
	index := uint16(i - 1)
	f := scopedFrame("config_tunnel", p.tuple)
	f.Index = &index
	f.Tunnel = &syncTunnel{t.ID, t.Protocol, t.TargetAddr}
	return f
}
