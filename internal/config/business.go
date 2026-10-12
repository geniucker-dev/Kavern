package config

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/geniucker-dev/kavern/internal/domain"
)

const (
	MaxNativeTunnels       = 1024
	MaxPublicListeners     = 1024
	MaxNativeTargetBytes   = 512
	MaxNativeSnapshotBytes = 1 << 20
)

var ErrInvalidBusinessConfig = errors.New("invalid desired configuration")

func ValidateNativePolicy(p domain.NativePolicy) error {
	if p.Carriers < 1 || p.Carriers > 4 || p.MaxStreams < 1 || p.MaxStreams > 1024 ||
		p.MaxInflight < 16384 || p.MaxInflight > 16<<20 ||
		p.MaxBuffer < p.MaxInflight+131072 || p.MaxBuffer > 64<<20 {
		return ErrInvalidBusinessConfig
	}
	return nil
}

// ValidateDeviceConfiguration does not infer eligibility from enabled state.
// The store supplies eligibility from its existing native secret records.
func ValidateDeviceConfiguration(c domain.DeviceConfiguration, native bool) error {
	if !ValidID(string(c.Device.ID)) || !ValidID(string(c.Device.ProjectID)) || !utf8.ValidString(c.Device.Name) || c.Revision == 0 || ValidateNativePolicy(c.Policy) != nil {
		return ErrInvalidBusinessConfig
	}
	if native && len(c.Tunnels) > MaxNativeTunnels {
		return ErrInvalidBusinessConfig
	}
	ids := make(map[domain.TunnelID]bool, len(c.Tunnels))
	listeners := make(map[domain.ListenerRef]bool, len(c.Tunnels))
	for _, tunnel := range c.Tunnels {
		if !ValidID(string(tunnel.ID)) || tunnel.DeviceID != c.Device.ID || tunnel.Protocol != domain.TunnelProtocolTCP ||
			len(tunnel.TargetAddr) > MaxJSONBytes || len(tunnel.Listener) > MaxJSONBytes ||
			ValidateAddress(string(tunnel.Listener)) != nil || ValidateAddress(tunnel.TargetAddr) != nil ||
			!utf8.ValidString(string(tunnel.Listener)) || !utf8.ValidString(tunnel.TargetAddr) || ids[tunnel.ID] || listeners[tunnel.Listener] {
			return ErrInvalidBusinessConfig
		}
		ids[tunnel.ID], listeners[tunnel.Listener] = true, true
		if native {
			_, port, _ := net.SplitHostPort(tunnel.TargetAddr)
			p, _ := strconv.Atoi(port)
			if len(tunnel.TargetAddr) > MaxNativeTargetBytes || p == 0 {
				return ErrInvalidBusinessConfig
			}
		}
	}
	return nil
}

func ValidateNativeSnapshot(s domain.NativeSnapshot) error {
	if !ValidID(string(s.DeviceID)) || s.Revision == 0 || ValidateNativePolicy(s.Policy) != nil || len(s.Tunnels) > MaxNativeTunnels {
		return ErrInvalidBusinessConfig
	}
	seen := make(map[domain.TunnelID]bool, len(s.Tunnels))
	for i, t := range s.Tunnels {
		_, port, err := net.SplitHostPort(t.TargetAddr)
		p, _ := strconv.Atoi(port)
		if !ValidID(string(t.ID)) || t.Protocol != domain.TunnelProtocolTCP || seen[t.ID] || (i > 0 && s.Tunnels[i-1].ID >= t.ID) ||
			len(t.TargetAddr) > MaxNativeTargetBytes || !utf8.ValidString(t.TargetAddr) || err != nil || ValidateAddress(t.TargetAddr) != nil || p == 0 {
			return ErrInvalidBusinessConfig
		}
		seen[t.ID] = true
	}
	data, err := json.Marshal(s)
	if err != nil || len(data) > MaxNativeSnapshotBytes {
		return ErrInvalidBusinessConfig
	}
	return nil
}
