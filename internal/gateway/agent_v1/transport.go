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
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
)

const MaxControlFrameBytes = 4096

type controlFrame struct {
	CarrierCount int              `json:"carrier_count,omitempty"`
	Version      string           `json:"version"`
	Role         string           `json:"role,omitempty"`
	Type         string           `json:"type"`
	DeviceID     domain.DeviceID  `json:"device_id,omitempty"`
	ClientNonce  string           `json:"client_nonce,omitempty"`
	ServerNonce  string           `json:"server_nonce,omitempty"`
	ChallengeID  string           `json:"auth_challenge_id,omitempty"`
	SessionID    domain.SessionID `json:"session_id,omitempty"`
	CarrierNonce string           `json:"carrier_nonce,omitempty"`
	Response     string           `json:"response_hmac,omitempty"`
	Limits       *config.Limits   `json:"limits,omitempty"`
}

func writeControl(w io.Writer, f controlFrame) error {
	f.Version = ProtocolVersion
	payload, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(payload) > MaxControlFrameBytes {
		return ErrInvalidInput
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	for _, p := range [][]byte{prefix[:], payload} {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n != len(p) {
			return io.ErrShortWrite
		}
	}
	return nil
}
func readControl(r io.Reader) (controlFrame, error) {
	var f controlFrame
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return f, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxControlFrameBytes {
		return f, ErrInvalidInput
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return f, err
	}
	if err := config.DecodeJSON(bytes.NewReader(data), &f); err != nil {
		return f, ErrInvalidInput
	}
	if f.Version != ProtocolVersion {
		return f, ErrInvalidInput
	}
	return f, nil
}
func muxLimits(l config.Limits) mux.Config {
	return mux.Config{MaxReceiveBuffer: l.MaxBuffer - l.MaxInflight, MaxStreamBuffer: min(65536, l.MaxBuffer-l.MaxInflight-65535), MaxFrameSize: 16384}
}

// ServeTransport handles one already verified TLS connection. Control lifetime
// owns the authenticated session; carriers use independent TLS connections.
func (s *AuthService) ServeTransport(ctx context.Context, conn net.Conn, limits config.Limits) error {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := limits.Validate(); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	first, err := readControl(conn)
	if err != nil {
		return err
	}
	switch first.Role {
	case TransportRoleControl:
		if first.Type != "auth_start" {
			return ErrInvalidInput
		}
		challenge, err := s.BeginAuth(ctx, AuthStartRequest{DeviceID: first.DeviceID, ClientNonce: first.ClientNonce})
		if err != nil {
			return err
		}
		if err = writeControl(conn, controlFrame{Type: "auth_challenge", ChallengeID: challenge.AuthChallengeID, ServerNonce: challenge.ServerNonce}); err != nil {
			return err
		}
		finish, err := readControl(conn)
		if err != nil {
			return err
		}
		if finish.Type != "auth_finish" || finish.ChallengeID != challenge.AuthChallengeID {
			return ErrInvalidInput
		}
		result, err := s.CompleteAuth(ctx, AuthFinishRequest{AuthChallengeID: finish.ChallengeID, ResponseHMAC: finish.Response})
		if err != nil {
			return err
		}
		defer s.CloseSession(context.Background(), result.SessionID)
		entry, ok := s.registry.lookup(result.SessionID)
		if !ok {
			return ErrSessionNotFound
		}
		retire := context.AfterFunc(ctx, func() { conn.Close() })
		defer retire()
		ended := make(chan struct{})
		monitorDone := make(chan struct{})
		defer func() { close(ended); <-monitorDone }()
		go func() {
			defer close(monitorDone)
			select {
			case <-entry.session.Done():
				conn.Close()
			case <-ended:
			}
		}()
		if err = writeControl(conn, controlFrame{Type: "auth_ok", SessionID: result.SessionID, DeviceID: result.DeviceID}); err != nil {
			return err
		}
		expiry := entry.session.expiresAt
		for time.Now().Before(expiry) {
			_ = conn.SetDeadline(minTime(time.Now().Add(30*time.Second), expiry))
			heartbeat, err := readControl(conn)
			if err != nil {
				return err
			}
			if heartbeat.Type == "ready" && heartbeat.SessionID == result.SessionID {
				wait, cancel := context.WithTimeout(ctx, 2*time.Second)
				err := entry.session.pool.WaitReady(wait, heartbeat.CarrierCount)
				cancel()
				if err != nil {
					return err
				}
				if err = writeControl(conn, controlFrame{Type: "ready_ok"}); err != nil {
					return err
				}
				continue
			}
			if heartbeat.Type != "ping" || heartbeat.SessionID != result.SessionID {
				return ErrInvalidInput
			}
			if _, _, err = s.store.ResolveKAPv1DeviceForAuth(ctx, result.DeviceID); err != nil {
				return err
			}
			if err = writeControl(conn, controlFrame{Type: "pong"}); err != nil {
				return err
			}
		}
		return ErrSessionClosed
	case TransportRoleDataCarrier:
		if first.Type != "carrier_bind" {
			return ErrInvalidInput
		}
		binding, err := s.BindCarrier(ctx, CarrierBindRequest{SessionID: first.SessionID, CarrierNonce: first.CarrierNonce, ResponseHMAC: first.Response})
		if err != nil {
			return err
		}
		if err = writeControl(conn, controlFrame{Type: "carrier_ok", Limits: &limits}); err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Time{})
		ms, err := mux.NewSmuxBackend().Client(conn, muxLimits(limits))
		if err != nil {
			return err
		}
		defer ms.Close()
		if err = s.attachBoundCarrier(ctx, binding, ms, carrier.Config{MaxStreamsPerCarrier: limits.MaxStreams, MaxInflight: limits.MaxInflight, MaxBuffer: limits.MaxBuffer}); err != nil {
			return err
		}
		entry, ok := s.registry.lookup(binding.SessionID)
		if !ok {
			return ErrSessionNotFound
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-entry.session.Done():
			return ErrSessionClosed
		case <-ms.(interface{ Done() <-chan struct{} }).Done():
			return io.EOF
		}
	default:
		return ErrInvalidInput
	}
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
