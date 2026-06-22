package legacy_npc

import "errors"

var (
	ErrInvalidConfig            = errors.New("invalid legacy npc gateway config")
	ErrInvalidHandshake         = errors.New("invalid legacy npc handshake")
	ErrUnsupportedConnection    = errors.New("unsupported legacy npc connection type")
	ErrLegacyDataNotImplemented = errors.New("legacy npc data forwarding is not implemented")
	ErrNoCurrentMainSession     = errors.New("no current legacy npc main session")
)
