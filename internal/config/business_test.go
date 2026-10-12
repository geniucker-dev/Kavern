package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func businessFixture(count int, target string) domain.DeviceConfiguration {
	c := domain.DeviceConfiguration{Device: domain.Device{ID: "device", ProjectID: "project", Enabled: true}, Revision: 1, Policy: domain.DefaultNativePolicy()}
	for i := 0; i < count; i++ {
		c.Tunnels = append(c.Tunnels, domain.Tunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i)), DeviceID: "device", Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", i+1)), TargetAddr: target, Enabled: true})
	}
	return c
}

func TestNativeConfigurationBoundariesAndDisabledEligibility(t *testing.T) {
	target := strings.Repeat("x", MaxNativeTargetBytes-2) + ":1"
	c := businessFixture(MaxNativeTunnels, target)
	if err := ValidateDeviceConfiguration(c, true); err != nil {
		t.Fatal(err)
	}
	c.Tunnels = append(c.Tunnels, domain.Tunnel{ID: "extra", DeviceID: "device", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:65535", TargetAddr: target})
	if ValidateDeviceConfiguration(c, true) == nil {
		t.Fatal("over-count accepted")
	}
	for _, target := range []string{strings.Repeat("x", MaxNativeTargetBytes-1) + ":1", "127.0.0.1:0", "missing-port"} {
		c := businessFixture(1, target)
		c.Device.Enabled = false
		c.Tunnels[0].Enabled = false
		if ValidateDeviceConfiguration(c, true) == nil {
			t.Fatal("disabled native target bypassed bounds")
		}
	}
	c = businessFixture(1, strings.Repeat("x", 513)+":0")
	if err := ValidateDeviceConfiguration(c, false); err != nil {
		t.Fatal("legacy-only target was narrowed", err)
	}
	for _, mutate := range []func(*domain.DeviceConfiguration){
		func(c *domain.DeviceConfiguration) { c.Tunnels[0].DeviceID = "other" },
		func(c *domain.DeviceConfiguration) { c.Tunnels[0].Protocol = domain.TunnelProtocolHTTP },
		func(c *domain.DeviceConfiguration) { c.Tunnels[0].ID = "bad id" },
		func(c *domain.DeviceConfiguration) { c.Tunnels = append(c.Tunnels, c.Tunnels[0]) },
		func(c *domain.DeviceConfiguration) { c.Policy.Carriers = 5 },
		func(c *domain.DeviceConfiguration) { c.Policy.MaxBuffer = c.Policy.MaxInflight },
	} {
		c := businessFixture(1, "127.0.0.1:1")
		mutate(&c)
		if ValidateDeviceConfiguration(c, true) == nil {
			t.Fatal("invalid native candidate accepted")
		}
	}
}

func TestNativeSnapshotByteBudgetAndCanonicalOrder(t *testing.T) {
	s := domain.NativeSnapshot{DeviceID: "device", Revision: 1, Policy: domain.DefaultNativePolicy()}
	if err := ValidateNativeSnapshot(s); err != nil {
		t.Fatal("empty snapshot", err)
	}
	for i := 0; i < MaxNativeTunnels; i++ {
		s.Tunnels = append(s.Tunnels, domain.NativeTunnel{ID: domain.TunnelID(fmt.Sprintf("t%04d", i) + strings.Repeat("x", 123)), Protocol: domain.TunnelProtocolTCP, TargetAddr: strings.Repeat("x", 510) + ":1"})
	}
	if err := ValidateNativeSnapshot(s); err != nil {
		t.Fatal("valid maximum snapshot", err)
	}
	for i := range s.Tunnels {
		s.Tunnels[i].TargetAddr = strings.Repeat("\u2028", 160) + ":1"
	}
	if ValidateNativeSnapshot(s) == nil {
		t.Fatal("escaped JSON bypassed byte budget")
	}
	s.Tunnels = s.Tunnels[:2]
	s.Tunnels[0], s.Tunnels[1] = s.Tunnels[1], s.Tunnels[0]
	if ValidateNativeSnapshot(s) == nil {
		t.Fatal("unsorted snapshot accepted")
	}
}
