package agent_v1

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
)

type SyncCarrierRequest struct {
	Binding              CarrierBindRequest
	DeviceID             domain.DeviceID
	Revision, TransferID domain.ConfigRevision
}

func (r SyncCarrierRequest) tuple() syncTuple {
	return syncTuple{r.DeviceID, r.Binding.SessionID, r.Revision, r.TransferID}
}

type syncCarrierFrame struct {
	Version     string                `json:"version"`
	Role        string                `json:"role"`
	Type        string                `json:"type"`
	SyncVersion int                   `json:"config_sync_version"`
	DeviceID    domain.DeviceID       `json:"device_id"`
	SessionID   domain.SessionID      `json:"session_id"`
	Revision    domain.ConfigRevision `json:"revision"`
	TransferID  domain.ConfigRevision `json:"transfer_id"`
	Nonce       string                `json:"carrier_nonce,omitempty"`
	Response    string                `json:"response_hmac,omitempty"`
	Policy      *syncPolicy           `json:"policy,omitempty"`
}

func (f syncCarrierFrame) tuple() syncTuple {
	return syncTuple{f.DeviceID, f.SessionID, f.Revision, f.TransferID}
}
func decodeSyncCarrier(data []byte) (syncCarrierFrame, error) {
	var f syncCarrierFrame
	if len(data) == 0 || len(data) > MaxControlFrameBytes || config.DecodeJSON(bytes.NewReader(data), &f) != nil {
		return f, ErrSyncTransfer
	}
	keys := []string{"version", "role", "type", "config_sync_version", "device_id", "session_id", "revision", "transfer_id"}
	switch f.Type {
	case "carrier_bind":
		keys = append(keys, "carrier_nonce", "response_hmac")
	case "carrier_ok":
		keys = append(keys, "policy")
	default:
		return f, ErrSyncTransfer
	}
	if !exactKeys(data, keys...) || f.Version != ProtocolVersion || f.Role != TransportRoleDataCarrier || f.SyncVersion != ConfigSyncVersion || !config.ValidID(string(f.DeviceID)) || validateToken(string(f.SessionID)) != nil || f.Revision == 0 || f.TransferID == 0 {
		return f, ErrSyncTransfer
	}
	if f.Type == "carrier_bind" {
		if validateToken(f.Nonce) != nil || f.Response == "" {
			return f, ErrSyncTransfer
		}
	} else {
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(data, &raw)
		if f.Policy == nil || !exactKeys(raw["policy"], "carriers", "max_streams", "max_inflight", "max_buffer") || config.ValidateNativePolicy(f.Policy.domain()) != nil {
			return f, ErrSyncTransfer
		}
	}
	return f, nil
}
func writeSyncCarrier(w io.Writer, f syncCarrierFrame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return ErrSyncTransfer
	}
	if _, err = decodeSyncCarrier(data); err != nil {
		return err
	}
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(len(data)))
	for _, part := range [][]byte{p[:], data} {
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
func readSyncCarrier(r io.Reader) (syncCarrierFrame, error) {
	data, err := readSyncTransportPayload(r)
	if err != nil {
		return syncCarrierFrame{}, err
	}
	return decodeSyncCarrier(data)
}
func policyLimits(p domain.NativePolicy) config.Limits {
	return config.Limits{MaxStreams: p.MaxStreams, MaxInflight: p.MaxInflight, MaxBuffer: p.MaxBuffer}
}
func policyCarrier(p domain.NativePolicy) carrier.Config {
	return carrier.Config{MaxStreamsPerCarrier: p.MaxStreams, MaxInflight: p.MaxInflight, MaxBuffer: p.MaxBuffer}
}

func (s *AuthService) attachSyncBound(ctx context.Context, auth SyncAuthResult, tuple syncTuple, backend mux.Session) (*carrier.Carrier, error) {
	session, data, snapshot, err := s.waitSyncApplication(ctx, auth, tuple)
	if err != nil {
		return nil, err
	}
	c, err := carrier.New(backend, policyCarrier(snapshot.Policy))
	if err != nil {
		return nil, err
	}
	if _, err = data.current(ctx, tuple, false); err != nil {
		_ = c.Close()
		return nil, err
	}
	err = s.withSyncSession(ctx, auth, func() error {
		data.mu.Lock()
		defer data.mu.Unlock()
		if data.desired != tuple || data.applied != tuple || session.pool.LiveCount() >= snapshot.Policy.Carriers {
			return ErrSyncNotReady
		}
		if err := session.pool.Add(c); err != nil {
			return err
		}
		// A changed carrier set requires a fresh scoped ready exchange. Keep
		// the invalidation atomic with Add, and leave readiness on failure.
		data.ready = syncTuple{}
		data.notifyLocked()
		return nil
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// The backend/config is owned on entry. Caller-supplied limits cannot override
// the authenticated session snapshot; only its immutable policy is used.
func (s *AuthService) BindAndAttachSyncCarrier(ctx context.Context, req SyncCarrierRequest, backend mux.Session) error {
	if backend == nil {
		return ErrInvalidInput
	}
	attached := false
	defer func() {
		if !attached {
			_ = backend.Close()
		}
	}()
	if _, err := s.BindSyncCarrier(ctx, req.Binding, ConfigSyncVersion); err != nil {
		return err
	}
	auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: req.DeviceID, SessionID: req.Binding.SessionID, ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: ConfigSyncVersion}
	if _, err := s.attachSyncBound(ctx, auth, req.tuple(), backend); err != nil {
		return err
	}
	attached = true
	return nil
}
func (s *AuthService) serveSyncCarrier(ctx context.Context, conn *tls.Conn, first syncCarrierFrame) error {
	if first.Type != "carrier_bind" {
		return ErrSyncTransfer
	}
	request := CarrierBindRequest{SessionID: first.SessionID, CarrierNonce: first.Nonce, ResponseHMAC: first.Response}
	if _, err := s.BindSyncCarrier(ctx, request, ConfigSyncVersion); err != nil {
		return err
	}
	auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: first.DeviceID, SessionID: first.SessionID, ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: ConfigSyncVersion}
	session, _, snapshot, err := s.waitSyncApplication(ctx, auth, first.tuple())
	if err != nil {
		return err
	}
	reply := first
	reply.Type = "carrier_ok"
	reply.Nonce = ""
	reply.Response = ""
	reply.Policy = wirePolicy(snapshot.Policy)
	if err = writeSyncCarrier(conn, reply); err != nil {
		return err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	backend, err := mux.NewSmuxBackend().Client(syncTLSConnection{conn}, muxLimits(policyLimits(snapshot.Policy)))
	if err != nil {
		return err
	}
	defer backend.Close()
	c, err := s.attachSyncBound(ctx, auth, first.tuple(), backend)
	if err != nil {
		return err
	}
	defer c.Close()
	done := backend.(interface{ Done() <-chan struct{} }).Done()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-session.Done():
		return ErrSessionClosed
	case <-done:
		return io.EOF
	}
}

type SyncClientCarrier struct {
	receiver *ConfigReceiver
	backend  mux.Session
	carrier  *carrier.Carrier
	tuple    syncTuple
	policy   domain.NativePolicy
	once     sync.Once
	err      error
}

func (c *SyncClientCarrier) Close() error {
	c.once.Do(func() {
		c.err = c.carrier.Close()
		c.receiver.mu.Lock()
		delete(c.receiver.carriers, c)
		c.receiver.ready = syncTuple{}
		c.receiver.mu.Unlock()
	})
	return c.err
}
func (c *SyncClientCarrier) Run(ctx context.Context, dialer Dialer) error {
	defer c.Close()
	loop := &AgentDataLoop{Carrier: c.carrier, Session: c.backend, MaxHandlers: c.policy.MaxStreams, handleStream: func(ctx context.Context, stream mux.Stream) error {
		return HandleSyncAgentStream(ctx, stream, c.receiver, dialer)
	}}
	return loop.Run(ctx)
}
func (r *ConfigReceiver) BindSyncCarrierTLS(ctx context.Context, conn *tls.Conn, secret []byte) (*SyncClientCarrier, error) {
	if conn == nil || len(secret) != 32 {
		return nil, ErrInvalidInput
	}
	cleanup := ownSyncTLS(ctx, conn)
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(syncHandshakeTimeout)); err != nil {
		return nil, err
	}
	handshake, cancel := context.WithTimeout(ctx, syncHandshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(handshake); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
		return nil, ErrInvalidInput
	}
	r.mu.Lock()
	if r.closed || r.stage != nil || r.applied.Revision == 0 || !r.ackDeadline.IsZero() {
		r.mu.Unlock()
		return nil, ErrSyncNotReady
	}
	tuple, policy := r.currentTupleLocked(), r.applied.Policy
	r.mu.Unlock()
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	proof, err := SignSyncCarrierBind(secret, tuple.SessionID, tuple.DeviceID, nonce, ConfigSyncVersion)
	if err != nil {
		return nil, err
	}
	request := syncCarrierFrame{Version: ProtocolVersion, Role: TransportRoleDataCarrier, Type: "carrier_bind", SyncVersion: ConfigSyncVersion, DeviceID: tuple.DeviceID, SessionID: tuple.SessionID, Revision: tuple.Revision, TransferID: tuple.TransferID, Nonce: nonce, Response: proof}
	if err = writeSyncCarrier(conn, request); err != nil {
		return nil, err
	}
	reply, err := readSyncCarrier(conn)
	if err != nil {
		return nil, err
	}
	if reply.Type != "carrier_ok" || reply.tuple() != tuple || reply.Policy.domain() != policy {
		return nil, ErrSyncStale
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	owned := &ownedSyncTLS{syncTLSConnection: syncTLSConnection{conn}, cleanup: cleanup}
	backend, err := mux.NewSmuxBackend().Server(owned, muxLimits(policyLimits(policy)))
	if err != nil {
		return nil, err
	}
	c, err := carrier.New(backend, policyCarrier(policy))
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	client := &SyncClientCarrier{receiver: r, backend: backend, carrier: c, tuple: tuple, policy: policy}
	r.mu.Lock()
	if r.closed || r.stage != nil || tuple != r.currentTupleLocked() || r.liveCarriersLocked() >= policy.Carriers {
		r.mu.Unlock()
		_ = c.Close()
		return nil, ErrSyncStale
	}
	r.carriers[client] = struct{}{}
	r.mu.Unlock()
	success = true
	return client, nil
}
