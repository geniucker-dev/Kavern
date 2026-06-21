package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/session"
	"github.com/zhuhaoyu/kavern/internal/testutil"
)

func TestManagerAttachCurrentAndReplace(t *testing.T) {
	ctx := context.Background()
	manager := session.NewManager()
	first := testutil.NewFakeSession("session-1", "device-1")
	second := testutil.NewFakeSession("session-2", "device-1")

	if err := manager.Attach(ctx, first); err != nil {
		t.Fatalf("Attach(first) error = %v", err)
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	if current.ID() != first.ID() {
		t.Fatalf("current = %q, want %q", current.ID(), first.ID())
	}

	if err := manager.Attach(ctx, second); err != nil {
		t.Fatalf("Attach(second) error = %v", err)
	}
	if !first.Closed {
		t.Fatalf("replaced session was not closed")
	}
	current, err = manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	if current.ID() != second.ID() {
		t.Fatalf("current = %q, want %q", current.ID(), second.ID())
	}
}

func TestManagerRejectsDuplicateSessionIDForDifferentDevice(t *testing.T) {
	ctx := context.Background()
	manager := session.NewManager()
	original := testutil.NewFakeSession("session-1", "device-a")
	duplicate := testutil.NewFakeSession("session-1", "device-b")

	if err := manager.Attach(ctx, original); err != nil {
		t.Fatalf("Attach(original) error = %v", err)
	}
	if err := manager.Attach(ctx, duplicate); !errors.Is(err, session.ErrDuplicateSessionID) {
		t.Fatalf("Attach(duplicate) error = %v, want ErrDuplicateSessionID", err)
	}
	current, err := manager.CurrentForDevice(ctx, "device-a")
	if err != nil {
		t.Fatalf("CurrentForDevice(device-a) error = %v", err)
	}
	if current.ID() != original.ID() || current.DeviceID() != original.DeviceID() {
		t.Fatalf("device-a current changed after failed duplicate attach")
	}
	if _, err := manager.CurrentForDevice(ctx, "device-b"); !errors.Is(err, session.ErrNoCurrentSession) {
		t.Fatalf("CurrentForDevice(device-b) error = %v, want ErrNoCurrentSession", err)
	}
	if duplicate.Closed {
		t.Fatalf("failed duplicate session should not be closed by manager")
	}
}

func TestManagerRejectsDuplicateSessionIDForSameDeviceWithoutMutation(t *testing.T) {
	ctx := context.Background()
	manager := session.NewManager()
	original := testutil.NewFakeSession("session-1", "device-a")
	duplicate := testutil.NewFakeSession("session-1", "device-a")

	if err := manager.Attach(ctx, original); err != nil {
		t.Fatalf("Attach(original) error = %v", err)
	}
	if err := manager.Attach(ctx, duplicate); !errors.Is(err, session.ErrDuplicateSessionID) {
		t.Fatalf("Attach(duplicate) error = %v, want ErrDuplicateSessionID", err)
	}
	current, err := manager.CurrentForDevice(ctx, "device-a")
	if err != nil {
		t.Fatalf("CurrentForDevice(device-a) error = %v", err)
	}
	if current != original {
		t.Fatalf("device-a current changed after failed duplicate attach")
	}
	if duplicate.Closed {
		t.Fatalf("failed duplicate session should not be closed by manager")
	}
	infos, err := manager.ListForDevice(ctx, "device-a")
	if err != nil {
		t.Fatalf("ListForDevice(device-a) error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListForDevice(device-a) length = %d, want 1", len(infos))
	}
}

func TestManagerDetachOnlyMatchingCurrent(t *testing.T) {
	ctx := context.Background()
	manager := session.NewManager()
	first := testutil.NewFakeSession("session-1", "device-1")
	second := testutil.NewFakeSession("session-2", "device-1")

	if err := manager.Attach(ctx, first); err != nil {
		t.Fatalf("Attach(first) error = %v", err)
	}
	if err := manager.Attach(ctx, second); err != nil {
		t.Fatalf("Attach(second) error = %v", err)
	}
	if err := manager.Detach(ctx, first.ID()); err != nil {
		t.Fatalf("Detach(old) error = %v", err)
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatalf("CurrentForDevice() error = %v", err)
	}
	if current.ID() != second.ID() {
		t.Fatalf("old detach removed current session")
	}

	if err := manager.Detach(ctx, second.ID()); err != nil {
		t.Fatalf("Detach(current) error = %v", err)
	}
	if _, err := manager.CurrentForDevice(ctx, "device-1"); err != session.ErrNoCurrentSession {
		t.Fatalf("CurrentForDevice() error = %v, want ErrNoCurrentSession", err)
	}
}

func TestManagerListForDeviceIsObservabilityOnly(t *testing.T) {
	ctx := context.Background()
	manager := session.NewManager()
	if err := manager.Attach(ctx, testutil.NewFakeSession("session-1", "device-1")); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if err := manager.Attach(ctx, testutil.NewFakeSession("session-2", "device-1")); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	infos, err := manager.ListForDevice(ctx, domain.DeviceID("device-1"))
	if err != nil {
		t.Fatalf("ListForDevice() error = %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("ListForDevice() length = %d, want 2", len(infos))
	}
	if !infos[1].Current {
		t.Fatalf("latest session should be marked current")
	}
}

func TestManagerListForDeviceClearsCurrentAfterDetach(t *testing.T) {
	ctx := context.Background()
	manager := session.NewManager()
	first := testutil.NewFakeSession("session-1", "device-1")

	if err := manager.Attach(ctx, first); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if err := manager.Detach(ctx, first.ID()); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}

	infos, err := manager.ListForDevice(ctx, "device-1")
	if err != nil {
		t.Fatalf("ListForDevice() error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListForDevice() length = %d, want 1", len(infos))
	}
	if infos[0].Current {
		t.Fatalf("detached historical session is marked current")
	}
}
