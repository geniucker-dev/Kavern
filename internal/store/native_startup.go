package store

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
)

// ValidateNativeStartup rejects legacy local-target assumptions before serving.
func (o *ConfigOwner) ValidateNativeStartup(ctx context.Context) error {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return ErrConfigOwnerClosed
	}
	if o.uncertain {
		return ErrCommitUncertain
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for id := range o.current.kapv1Secret {
		// Use the same complete projection preflight as synchronization, including
		// canonical encoded bytes (escaping can exceed bounds despite field sizes).
		if _, err := o.current.NativeSnapshot(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
func (o *ConfigOwner) GetDevice(ctx context.Context, id domain.DeviceID) (domain.Device, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.Device{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.Device{}, ErrCommitUncertain
	}
	return o.current.GetDevice(ctx, id)
}
func (o *ConfigOwner) GetTunnel(ctx context.Context, id domain.TunnelID) (domain.Tunnel, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.Tunnel{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.Tunnel{}, ErrCommitUncertain
	}
	return o.current.GetTunnel(ctx, id)
}
func (o *ConfigOwner) ResolveLegacyDeviceForAuth(ctx context.Context, key string) (domain.Device, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.Device{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.Device{}, ErrCommitUncertain
	}
	return o.current.ResolveLegacyDeviceForAuth(ctx, key)
}
