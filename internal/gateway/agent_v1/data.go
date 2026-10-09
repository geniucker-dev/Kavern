package agent_v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
)

const (
	MaxOpenStreamMetadataBytes = 4096
	OpenStreamMessageType      = "open_stream"
)

type OpenStreamMetadata struct {
	Version  string                `json:"version"`
	Type     string                `json:"type"`
	TunnelID domain.TunnelID       `json:"tunnel_id"`
	Protocol domain.TunnelProtocol `json:"protocol"`
}

func (s *AuthService) BindAndAttachCarrier(ctx context.Context, req CarrierBindRequest, muxSession mux.Session, cfg carrier.Config) error {
	if muxSession == nil {
		return ErrInvalidInput
	}
	attached := false
	defer func() {
		if !attached {
			_ = muxSession.Close()
		}
	}()
	binding, err := s.BindCarrier(ctx, req)
	if err != nil {
		return err
	}
	if err := s.attachBoundCarrier(ctx, binding, muxSession, cfg); err != nil {
		return err
	}
	attached = true
	return nil
}

func (s *AuthService) attachBoundCarrier(ctx context.Context, binding CarrierBinding, muxSession mux.Session, cfg carrier.Config) error {
	entry, ok := s.registry.lookup(binding.SessionID)
	if !ok {
		return ErrSessionNotFound
	}
	if !s.now().Before(entry.session.expiresAt) {
		_ = s.CloseSession(context.Background(), binding.SessionID)
		return ErrSessionClosed
	}
	if entry.session.closed() {
		s.registry.remove(binding.SessionID)
		return ErrSessionClosed
	}
	current, err := s.sessions.CurrentForDevice(ctx, entry.deviceID)
	if err != nil {
		return err
	}
	if current.ID() != binding.SessionID {
		s.registry.remove(binding.SessionID)
		return ErrSessionNotCurrent
	}
	if _, _, err := s.store.ResolveKAPv1DeviceForAuth(ctx, entry.deviceID); err != nil {
		return err
	}
	c, err := carrier.New(muxSession, cfg)
	if err != nil {
		return err
	}
	if err := entry.session.attachCarrier(c); err != nil {
		return err
	}
	return nil
}

func WriteOpenStreamMetadata(w io.Writer, metadata OpenStreamMetadata) error {
	if err := validateOpenStreamMetadata(metadata); err != nil {
		return err
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > MaxOpenStreamMetadataBytes {
		return ErrMetadataTooLarge
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if n, err := w.Write(prefix[:]); err != nil {
		return err
	} else if n != len(prefix) {
		return io.ErrShortWrite
	}
	n, err := w.Write(payload)
	if err == nil && n != len(payload) {
		return io.ErrShortWrite
	}
	return err
}

func ReadOpenStreamMetadata(r io.Reader) (OpenStreamMetadata, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return OpenStreamMetadata{}, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 {
		return OpenStreamMetadata{}, ErrMalformedMetadata
	}
	if size > MaxOpenStreamMetadataBytes {
		return OpenStreamMetadata{}, ErrMetadataTooLarge
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return OpenStreamMetadata{}, err
	}
	var metadata OpenStreamMetadata
	if err := config.DecodeJSON(bytes.NewReader(payload), &metadata); err != nil {
		return OpenStreamMetadata{}, ErrMalformedMetadata
	}
	if err := validateOpenStreamMetadata(metadata); err != nil {
		if errors.Is(err, ErrUnsupportedTunnelProtocol) || errors.Is(err, ErrInvalidInput) {
			return OpenStreamMetadata{}, err
		}
		return OpenStreamMetadata{}, ErrMalformedMetadata
	}
	return metadata, nil
}

func validateOpenStreamMetadata(metadata OpenStreamMetadata) error {
	if metadata.Version != ProtocolVersion || metadata.Type != OpenStreamMessageType || !config.ValidID(string(metadata.TunnelID)) {
		return ErrInvalidInput
	}
	if metadata.Protocol != domain.TunnelProtocolTCP {
		return ErrUnsupportedTunnelProtocol
	}
	return nil
}
