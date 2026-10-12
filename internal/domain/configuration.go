package domain

import (
	"encoding/json"
	"errors"
	"strconv"
)

// ConfigRevision identifies durable desired state, never session readiness.
type ConfigRevision uint64

var ErrInvalidConfigRevision = errors.New("invalid configuration revision")

func (r ConfigRevision) MarshalJSON() ([]byte, error) {
	if r == 0 {
		return nil, ErrInvalidConfigRevision
	}
	return json.Marshal(strconv.FormatUint(uint64(r), 10))
}

func (r *ConfigRevision) UnmarshalJSON(data []byte) error {
	var value string
	if json.Unmarshal(data, &value) != nil {
		return ErrInvalidConfigRevision
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
		return ErrInvalidConfigRevision
	}
	*r = ConfigRevision(n)
	return nil
}

type NativePolicy struct {
	Carriers    int
	MaxStreams  int
	MaxInflight int
	MaxBuffer   int
}

func DefaultNativePolicy() NativePolicy {
	return NativePolicy{Carriers: 2, MaxStreams: 64, MaxInflight: 1 << 20, MaxBuffer: 8 << 20}
}

// DeviceConfiguration is a complete desired tunnel set, including disabled
// records. Revision is the expected current revision in a CAS mutation.
type DeviceConfiguration struct {
	Device   Device
	Revision ConfigRevision
	Policy   NativePolicy
	Tunnels  []Tunnel
}

type NativeTunnel struct {
	ID         TunnelID
	Protocol   TunnelProtocol
	TargetAddr string
}

// NativeSnapshot is a secret-free projection. Producing it does not authenticate
// a device, establish an applied revision, or make any route ready.
type NativeSnapshot struct {
	DeviceID DeviceID
	Revision ConfigRevision
	Policy   NativePolicy
	Tunnels  []NativeTunnel
}
