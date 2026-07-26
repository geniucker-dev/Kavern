package legacy_npc

import "errors"

var (
	ErrInvalidConfig            = errors.New("invalid legacy npc gateway config")
	ErrInvalidHandshake         = errors.New("invalid legacy npc handshake")
	ErrUnsupportedConnection    = errors.New("unsupported legacy npc connection type")
	ErrLegacyDataNotImplemented = errors.New("legacy npc data forwarding is not implemented")
	ErrNoCurrentMainSession     = errors.New("no current legacy npc main session")
	ErrInvalidLegacyMuxConfig   = errors.New("invalid legacy npc mux config")
	ErrLegacyMuxClosed          = errors.New("legacy npc mux is closed")
	ErrLegacyStreamClosed       = errors.New("legacy npc stream is closed")
	ErrLegacyStreamRejected     = errors.New("legacy npc stream was rejected")
	ErrLegacyStreamLimit        = errors.New("legacy npc stream limit reached")
	ErrLegacyIDExhausted        = errors.New("legacy npc stream id space exhausted")
	ErrLegacyTombstoneLimit     = errors.New("legacy npc tombstone limit reached")
	ErrLegacyProtocol           = errors.New("invalid legacy npc mux protocol state")
	ErrLegacyReceiveLimit       = errors.New("legacy npc receive buffer limit exceeded")
	ErrLegacyPingTimeout        = errors.New("legacy npc ping timeout")
)
