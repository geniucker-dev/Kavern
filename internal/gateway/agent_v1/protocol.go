package agent_v1

import (
	"encoding/base64"
	"errors"

	"github.com/geniucker-dev/kavern/internal/domain"
)

const (
	ProtocolVersion          = "kapv1"
	TransportRoleControl     = "control"
	TransportRoleDataCarrier = "data_carrier"

	randomTokenBytes = 32
)

var (
	ErrInvalidInput              = errors.New("invalid input")
	ErrAuthFailed                = errors.New("authentication failed")
	ErrChallengeNotFound         = errors.New("auth challenge not found")
	ErrChallengeExpired          = errors.New("auth challenge expired")
	ErrSessionNotFound           = errors.New("session not found")
	ErrSessionNotCurrent         = errors.New("session is not current")
	ErrSessionClosed             = errors.New("session is closed")
	ErrCarrierNonceReplay        = errors.New("carrier nonce replay")
	ErrInternalInvariant         = errors.New("internal invariant failure")
	ErrSessionIDCollision        = errors.New("session id collision")
	ErrRegistryReserve           = errors.New("session registry reserve failed")
	ErrUnsupportedTunnelProtocol = errors.New("unsupported tunnel protocol")
	ErrMetadataTooLarge          = errors.New("open stream metadata too large")
	ErrMalformedMetadata         = errors.New("malformed open stream metadata")
	ErrUnknownTunnelTarget       = errors.New("unknown tunnel target")
)

type AuthStartRequest struct {
	DeviceID    domain.DeviceID
	ClientNonce string
}

type AuthChallenge struct {
	AuthChallengeID string
	ServerNonce     string
	ProtocolVersion string
	ExpiresAtUnix   int64
}

type AuthFinishRequest struct {
	AuthChallengeID string
	ResponseHMAC    string
}

type AuthResult struct {
	SessionID       domain.SessionID
	DeviceID        domain.DeviceID
	ProtocolVersion string
}

type CarrierBindRequest struct {
	SessionID    domain.SessionID
	CarrierNonce string
	ResponseHMAC string
}

type CarrierBinding struct {
	SessionID    domain.SessionID
	DeviceID     domain.DeviceID
	CarrierNonce string
}

func GenerateSessionID() (domain.SessionID, error) {
	token, err := generateToken()
	return domain.SessionID(token), err
}

func GenerateNonce() (string, error) {
	return generateToken()
}

func GenerateChallengeID() (string, error) {
	return generateToken()
}

func validateToken(value string) error {
	if value == "" || len(value) > 512 {
		return ErrInvalidInput
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return ErrInvalidInput
	}
	if len(decoded) < randomTokenBytes {
		return ErrInvalidInput
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ErrInvalidInput
	}
	return nil
}
