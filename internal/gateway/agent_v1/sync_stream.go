package agent_v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
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
	var work *session.WorkLease
	transferred := false
	if owner, ok := data.service.store.(interface {
		AdmitTunnel(context.Context, domain.TunnelID, domain.ConfigRevision) (domain.RouteView, *session.WorkLease, error)
	}); ok {
		view, registered, err := owner.AdmitTunnel(ctx, req.TunnelID, req.Revision)
		if err != nil {
			return nil, err
		}
		work = registered
		if work != nil {
			ctx = work.Context
			// Session retirement also cancels a pending open or a returned stream that
			// the caller has not closed. This worker is bounded by the owner registry.
			go func() {
				select {
				case <-s.Done():
					work.Cancel()
				case <-work.Done():
				}
			}()
			defer func() {
				if !transferred {
					work.Finish()
				}
			}()
		}
		if view.Device.ID != s.deviceID {
			return nil, ErrUnknownTunnelTarget
		}
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
	openCtx := ctx
	stopPhase := func() {}
	if s.RenewableStreams() {
		openCtx, stopPhase = session.PhaseContext(ctx, s.StreamClock(), session.NativeOpenTimeout)
	}
	defer stopPhase()
	lease, err := s.pool.AcquireForLifetime(openCtx, ctx)
	if err != nil {
		return nil, errors.Join(err, context.Cause(openCtx))
	}
	callbackDone := make(chan struct{})
	stopClose := context.AfterFunc(openCtx, func() { defer close(callbackDone); _ = lease.Release() })
	defer func() {
		if !stopClose() {
			<-callbackDone
		}
	}()
	// Opening the mux stream may wait. Never send old metadata after that wait.
	if err = check(); err != nil {
		_ = lease.Release()
		return nil, err
	}
	metadata := SyncStreamMetadata{Version: ProtocolVersion, SyncVersion: ConfigSyncVersion, Type: OpenStreamMessageType, DeviceID: tuple.DeviceID, SessionID: tuple.SessionID, Revision: tuple.Revision, TransferID: tuple.TransferID, TunnelID: req.TunnelID, Protocol: req.Protocol}
	if err = WriteSyncStreamMetadata(lease.Stream, metadata); err != nil {
		_ = lease.Release()
		return nil, errors.Join(err, context.Cause(openCtx))
	}
	if err := openCtx.Err(); err != nil {
		_ = lease.Release()
		return nil, errors.Join(err, context.Cause(openCtx))
	}
	result := &leasedAgentStream{Lease: lease}
	if err := ctx.Err(); err != nil {
		_ = result.Close()
		return nil, err
	}
	if work != nil {
		owned := &admittedAgentStream{AgentStream: result, work: work}
		context.AfterFunc(ctx, func() { _ = owned.Close() })
		transferred = true
		return owned, nil
	}
	return result, nil
}

// Closing or revoking an independently admitted open releases both its carrier
// lease and work registration. Router-owned registrations stay with the proxy.
type admittedAgentStream struct {
	session.AgentStream
	work *session.WorkLease
	once sync.Once
	err  error
}

func (s *admittedAgentStream) Close() error {
	s.once.Do(func() { s.err = s.AgentStream.Close(); s.work.Finish() })
	return s.err
}
func (s *admittedAgentStream) CloseWrite() error {
	if cw, ok := s.AgentStream.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return ErrUnsupportedTunnelProtocol
}

func (r *ConfigReceiver) resolveSyncTarget(ctx context.Context, m SyncStreamMetadata) (string, error) {
	target, lease, err := r.admitSyncTarget(ctx, m)
	if lease != nil {
		lease.Finish()
	}
	return target, err
}
func (r *ConfigReceiver) admitSyncTarget(ctx context.Context, m SyncStreamMetadata) (string, *session.WorkLease, error) {
	if r.lifecycle != nil {
		if e := r.lifecycle.Valid(); e != nil {
			return "", nil, e
		}
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.stage != nil || !r.ackDeadline.IsZero() || r.ready.Revision == 0 || m.tuple() != r.ready || m.tuple() != r.currentTupleLocked() || r.liveCarriersLocked() != r.applied.Policy.Carriers {
		return "", nil, ErrSyncStale
	}
	for _, t := range r.applied.Tunnels {
		if t.ID == m.TunnelID {
			lease, err := r.work.Register(ctx, domain.WorkScope{DeviceID: m.DeviceID, TunnelID: t.ID, Revision: m.Revision, TargetAddr: t.TargetAddr, Protocol: t.Protocol})
			return t.TargetAddr, lease, err
		}
	}
	return "", nil, ErrUnknownTunnelTarget
}
func HandleSyncAgentStream(ctx context.Context, stream mux.Stream, receiver *ConfigReceiver, dialer Dialer) error {
	if receiver != nil && receiver.auth.LifecycleVersion == 0 {
		return handleSchemaSyncAgentStream(ctx, stream, receiver, dialer)
	}
	stream = &ownedStream{Stream: stream}
	var work *session.WorkLease
	defer func() {
		_ = stream.Close()
		if work != nil {
			work.Finish()
		}
	}()
	if receiver == nil {
		return ErrInvalidInput
	}
	if dialer == nil {
		dialer = &TCPDialer{Dialer: net.Dialer{Timeout: session.NativeOpenTimeout}}
	}
	lifetime := ctx
	clock := session.NewClock()
	renewable := receiver.auth.LifecycleVersion == LifecycleVersion
	if renewable {
		if receiver.lifecycle == nil {
			return ErrLifecycle
		}
		clock = receiver.lifecycle.clock
	}
	phaseCtx, stopPhase := session.PhaseContext(lifetime, clock, session.NativeOpenTimeout)
	defer stopPhase()
	phaseDone := make(chan struct{})
	stopPhaseIO := context.AfterFunc(phaseCtx, func() { defer close(phaseDone); _ = stream.Close() })
	joinPhaseIO := sync.OnceFunc(func() {
		if !stopPhaseIO() {
			<-phaseDone
		}
	})
	defer joinPhaseIO()
	lifeDone := make(chan struct{})
	stopLife := context.AfterFunc(lifetime, func() { defer close(lifeDone); _ = stream.Close() })
	defer func() {
		if !stopLife() {
			<-lifeDone
		}
	}()
	if d, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		if err := d.SetReadDeadline(time.Now().Add(session.NativeOpenTimeout)); err != nil {
			return err
		}
		defer d.SetReadDeadline(time.Time{})
	}
	m, err := ReadSyncStreamMetadata(stream)
	if err != nil {
		return errors.Join(err, context.Cause(phaseCtx))
	}
	if err := phaseCtx.Err(); err != nil {
		return errors.Join(err, context.Cause(phaseCtx))
	}
	if d, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		if err := d.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
	}
	target, registered, err := receiver.admitSyncTarget(lifetime, m)
	work = registered
	if err != nil {
		return err
	}
	ctx = work.Context
	revokedDone := make(chan struct{})
	stopRevoked := context.AfterFunc(ctx, func() { defer close(revokedDone); _ = stream.Close() })
	defer func() {
		if !stopRevoked() {
			<-revokedDone
		}
	}()
	dialCtx, cancelDial := context.WithCancel(phaseCtx)
	defer cancelDial()
	stopDial := context.AfterFunc(ctx, cancelDial)
	defer stopDial()
	connected, err := dialer.DialContext(dialCtx, "tcp", target)
	if connected != nil {
		defer connected.Close()
	}
	if err != nil {
		return errors.Join(err, context.Cause(phaseCtx))
	}
	if connected == nil {
		return ErrInvalidInput
	}
	if err = phaseCtx.Err(); err != nil {
		return errors.Join(err, context.Cause(phaseCtx))
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// No opening-phase context, timer or socket deadline survives into proxy I/O.
	joinPhaseIO()
	if err := phaseCtx.Err(); err != nil {
		return errors.Join(err, context.Cause(phaseCtx))
	}
	stopPhase()
	cancelDial()
	stopDial()
	if renewable {
		return session.ProxyNative(ctx, stream, connected, clock)
	}
	return session.ProxyBidirectional(ctx, stream, connected)
}

// Schema-only peers retain their historical phase and proxy behavior.
func handleSchemaSyncAgentStream(ctx context.Context, stream mux.Stream, receiver *ConfigReceiver, dialer Dialer) error {
	stream = &ownedStream{Stream: stream}
	var work *session.WorkLease
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = stream.Close() })
	defer func() {
		if !stop() {
			<-done
		}
		_ = stream.Close()
		if work != nil {
			work.Finish()
		}
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
	target, registered, err := receiver.admitSyncTarget(ctx, m)
	work = registered
	if err != nil {
		return err
	}
	ctx = work.Context
	revokedDone := make(chan struct{})
	stopRevoked := context.AfterFunc(ctx, func() { defer close(revokedDone); _ = stream.Close() })
	defer func() {
		if !stopRevoked() {
			<-revokedDone
		}
	}()
	connected, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer connected.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	return session.ProxyBidirectional(ctx, stream, connected)
}
