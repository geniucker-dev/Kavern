package agent_v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type SyncStreamMetadata struct {
	Version     string                `json:"version"`
	SyncVersion int                   `json:"config_sync_version"`
	Type        string                `json:"type"`
	DeviceID    domain.DeviceID       `json:"device_id"`
	SessionID   domain.SessionID      `json:"session_id"`
	Revision    domain.ConfigRevision `json:"revision"`
	TransferID  domain.ConfigRevision `json:"transfer_id"`
	TunnelID    domain.TunnelID       `json:"tunnel_id"`
	Protocol    domain.TunnelProtocol `json:"protocol"`
}

func (m SyncStreamMetadata) tuple() syncTuple {
	return syncTuple{m.DeviceID, m.SessionID, m.Revision, m.TransferID}
}
func decodeSyncMetadata(data []byte) (SyncStreamMetadata, error) {
	var m SyncStreamMetadata
	if len(data) == 0 || len(data) > MaxOpenStreamMetadataBytes || config.DecodeJSON(bytes.NewReader(data), &m) != nil || !exactKeys(data, "version", "config_sync_version", "type", "device_id", "session_id", "revision", "transfer_id", "tunnel_id", "protocol") {
		return m, ErrMalformedMetadata
	}
	if m.Version != ProtocolVersion || m.SyncVersion != ConfigSyncVersion || m.Type != OpenStreamMessageType || !config.ValidID(string(m.DeviceID)) || !config.ValidID(string(m.TunnelID)) || validateToken(string(m.SessionID)) != nil || m.Revision == 0 || m.TransferID == 0 {
		return m, ErrMalformedMetadata
	}
	if m.Protocol != domain.TunnelProtocolTCP {
		return m, ErrUnsupportedTunnelProtocol
	}
	return m, nil
}
func WriteSyncStreamMetadata(w io.Writer, m SyncStreamMetadata) error {
	data, err := json.Marshal(m)
	if err != nil {
		return ErrMalformedMetadata
	}
	if _, err = decodeSyncMetadata(data); err != nil {
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
func ReadSyncStreamMetadata(r io.Reader) (SyncStreamMetadata, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return SyncStreamMetadata{}, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 {
		return SyncStreamMetadata{}, ErrMalformedMetadata
	}
	if n > MaxOpenStreamMetadataBytes {
		return SyncStreamMetadata{}, ErrMetadataTooLarge
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return SyncStreamMetadata{}, err
	}
	return decodeSyncMetadata(data)
}

func (s *agentSession) openSyncStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	data := s.syncController()
	if data == nil {
		return nil, ErrSyncNotReady
	}
	data.mu.Lock()
	tuple := data.ready
	data.mu.Unlock()
	if tuple.Revision == 0 || req.Revision != tuple.Revision {
		return nil, ErrSyncNotReady
	}
	if req.Protocol == "" {
		req.Protocol = domain.TunnelProtocolTCP
	}
	if req.Protocol != domain.TunnelProtocolTCP {
		return nil, ErrUnsupportedTunnelProtocol
	}
	check := func() error {
		snapshot, err := data.current(ctx, tuple, true)
		if err != nil {
			return err
		}
		if s.pool.LiveCount() != snapshot.Policy.Carriers {
			return ErrSyncNotReady
		}
		for _, t := range snapshot.Tunnels {
			if t.ID == req.TunnelID {
				return nil
			}
		}
		return ErrUnknownTunnelTarget
	}
	if err := check(); err != nil {
		return nil, err
	}
	lease, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	// Opening the mux stream may wait. Never send old metadata after that wait.
	if err = check(); err != nil {
		_ = lease.Release()
		return nil, err
	}
	metadata := SyncStreamMetadata{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, Type: OpenStreamMessageType, DeviceID: tuple.DeviceID, SessionID: tuple.SessionID, Revision: tuple.Revision, TransferID: tuple.TransferID, TunnelID: req.TunnelID, Protocol: req.Protocol}
	if err = WriteSyncStreamMetadata(lease.Stream, metadata); err != nil {
		_ = lease.Release()
		return nil, err
	}
	return &leasedAgentStream{Lease: lease}, nil
}
func (r *ConfigReceiver) resolveSyncTarget(ctx context.Context, m SyncStreamMetadata) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.stage != nil || !r.ackDeadline.IsZero() || r.ready.Revision == 0 || m.tuple() != r.ready || m.tuple() != r.currentTupleLocked() || r.liveCarriersLocked() != r.applied.Policy.Carriers {
		return "", ErrSyncStale
	}
	for _, t := range r.applied.Tunnels {
		if t.ID == m.TunnelID {
			return t.TargetAddr, nil
		}
	}
	return "", ErrUnknownTunnelTarget
}
func HandleSyncAgentStream(ctx context.Context, stream mux.Stream, receiver *ConfigReceiver, dialer Dialer) error {
	stream = &ownedStream{Stream: stream}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = stream.Close() })
	defer func() {
		if !stop() {
			<-done
		}
		_ = stream.Close()
	}()
	if receiver == nil {
		return ErrInvalidInput
	}
	if dialer == nil {
		dialer = &TCPDialer{Dialer: net.Dialer{Timeout: 5 * time.Second}}
	}
	if d, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer d.SetReadDeadline(time.Time{})
	}
	m, err := ReadSyncStreamMetadata(stream)
	if err != nil {
		return err
	}
	if d, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Time{})
	}
	target, err := receiver.resolveSyncTarget(ctx, m)
	if err != nil {
		return err
	}
	connected, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer connected.Close()
	return session.ProxyBidirectional(ctx, stream, connected)
}
