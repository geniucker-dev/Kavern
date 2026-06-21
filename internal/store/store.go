package store

import (
	"context"
	"errors"

	"github.com/geniucker-dev/kavern/internal/domain"
)

var (
	ErrNotFound         = errors.New("not found")
	ErrDisabledDevice   = errors.New("disabled device")
	ErrCredentialExists = errors.New("credential already exists")
	ErrMissingSecret    = errors.New("missing secret")
)

type IssuedLegacyCredential struct {
	Credential domain.DeviceCredential
	VKey       string
}

type Store interface {
	CreateUser(ctx context.Context, user domain.User) error
	GetUser(ctx context.Context, id domain.UserID) (domain.User, error)
	CreateProject(ctx context.Context, project domain.Project) error
	GetProject(ctx context.Context, id domain.ProjectID) (domain.Project, error)
	CreateDevice(ctx context.Context, device domain.Device) error
	GetDevice(ctx context.Context, id domain.DeviceID) (domain.Device, error)
	CreateTunnel(ctx context.Context, tunnel domain.Tunnel) error
	GetTunnel(ctx context.Context, id domain.TunnelID) (domain.Tunnel, error)
	FindTunnelByListener(ctx context.Context, listener domain.ListenerRef) (domain.Tunnel, error)
	IssueLegacyCredential(ctx context.Context, deviceID domain.DeviceID, serverSecret []byte) (IssuedLegacyCredential, error)
	RotateLegacyCredential(ctx context.Context, deviceID domain.DeviceID, serverSecret []byte) (IssuedLegacyCredential, error)
	FindDeviceByLegacyLookupKey(ctx context.Context, lookupKey string) (domain.Device, error)
	ResolveLegacyDeviceForAuth(ctx context.Context, lookupKey string) (domain.Device, error)
	SetKAPv1DeviceSecret(ctx context.Context, deviceID domain.DeviceID, secret []byte) error
	ResolveKAPv1DeviceForAuth(ctx context.Context, deviceID domain.DeviceID) (domain.Device, []byte, error)
}
