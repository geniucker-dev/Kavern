package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/store"
)

func TestMemoryStoreCreateAndGet(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	user := domain.User{ID: "user-1", Name: "owner"}
	project := domain.Project{ID: "project-1", UserID: user.ID, Name: "project"}
	device := domain.Device{ID: "device-1", ProjectID: project.ID, Name: "device", Enabled: true}
	tunnel := domain.Tunnel{ID: "tunnel-1", DeviceID: device.ID, Protocol: domain.TunnelProtocolTCP, Listener: "tcp:1000", Enabled: true}

	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := st.CreateProject(ctx, project); err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := st.CreateTunnel(ctx, tunnel); err != nil {
		t.Fatalf("CreateTunnel() error = %v", err)
	}

	gotTunnel, err := st.FindTunnelByListener(ctx, "tcp:1000")
	if err != nil {
		t.Fatalf("FindTunnelByListener() error = %v", err)
	}
	if gotTunnel.ID != tunnel.ID {
		t.Fatalf("tunnel = %q, want %q", gotTunnel.ID, tunnel.ID)
	}
}

func TestLegacyCredentialIssuanceIsShowOnceAndDoesNotPersistRawVKey(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	device := domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	issued, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret"))
	if err != nil {
		t.Fatalf("IssueLegacyCredential() error = %v", err)
	}
	if issued.VKey == "" {
		t.Fatalf("issued vkey is empty")
	}
	if issued.Credential.LegacyLookupKey == "" {
		t.Fatalf("legacy lookup key is empty")
	}
	if strings.Contains(issued.Credential.LegacyLookupKey, issued.VKey) {
		t.Fatalf("credential appears to contain raw vkey")
	}

	found, err := st.FindDeviceByLegacyLookupKey(ctx, issued.Credential.LegacyLookupKey)
	if err != nil {
		t.Fatalf("FindDeviceByLegacyLookupKey() error = %v", err)
	}
	if found.ID != device.ID {
		t.Fatalf("found device = %q, want %q", found.ID, device.ID)
	}
}

func TestIssueLegacyCredentialFailsWhenCredentialAlreadyExists(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	device := domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	if _, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret")); err != nil {
		t.Fatalf("first IssueLegacyCredential() error = %v", err)
	}
	if _, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret")); !errors.Is(err, store.ErrCredentialExists) {
		t.Fatalf("second IssueLegacyCredential() error = %v, want ErrCredentialExists", err)
	}
}

func TestLegacyCredentialRotationInvalidatesOldLookupKey(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	device := domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	first, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret"))
	if err != nil {
		t.Fatalf("IssueLegacyCredential() error = %v", err)
	}
	second, err := st.RotateLegacyCredential(ctx, device.ID, []byte("server-secret"))
	if err != nil {
		t.Fatalf("RotateLegacyCredential() error = %v", err)
	}
	if first.Credential.LegacyLookupKey == second.Credential.LegacyLookupKey {
		t.Fatalf("rotation reused lookup key")
	}
	if _, err := st.FindDeviceByLegacyLookupKey(ctx, first.Credential.LegacyLookupKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old lookup error = %v, want ErrNotFound", err)
	}
	if _, err := st.FindDeviceByLegacyLookupKey(ctx, second.Credential.LegacyLookupKey); err != nil {
		t.Fatalf("new lookup error = %v", err)
	}
}

func TestRotateLegacyCredentialAfterIssueCreatesExactlyOneActiveCredential(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	device := domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	first, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret"))
	if err != nil {
		t.Fatalf("IssueLegacyCredential() error = %v", err)
	}

	rotated, err := st.RotateLegacyCredential(ctx, device.ID, []byte("server-secret"))
	if err != nil {
		t.Fatalf("RotateLegacyCredential() error = %v", err)
	}
	if _, err := st.FindDeviceByLegacyLookupKey(ctx, first.Credential.LegacyLookupKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old lookup error = %v, want ErrNotFound", err)
	}
	found, err := st.FindDeviceByLegacyLookupKey(ctx, rotated.Credential.LegacyLookupKey)
	if err != nil {
		t.Fatalf("new lookup error = %v", err)
	}
	if found.ID != device.ID {
		t.Fatalf("new lookup device = %q, want %q", found.ID, device.ID)
	}
	if _, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret")); !errors.Is(err, store.ErrCredentialExists) {
		t.Fatalf("IssueLegacyCredential() after rotation error = %v, want ErrCredentialExists", err)
	}
}

func TestResolveLegacyDeviceForAuthRejectsDisabledDevice(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	device := domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: false}
	if err := st.CreateDevice(ctx, device); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	issued, err := st.IssueLegacyCredential(ctx, device.ID, []byte("server-secret"))
	if err != nil {
		t.Fatalf("IssueLegacyCredential() error = %v", err)
	}
	if _, err := st.FindDeviceByLegacyLookupKey(ctx, issued.Credential.LegacyLookupKey); err != nil {
		t.Fatalf("normal lookup should find disabled device: %v", err)
	}
	if _, err := st.ResolveLegacyDeviceForAuth(ctx, issued.Credential.LegacyLookupKey); !errors.Is(err, store.ErrDisabledDevice) {
		t.Fatalf("auth lookup error = %v, want ErrDisabledDevice", err)
	}
}
