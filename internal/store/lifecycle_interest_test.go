package store

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"sync/atomic"
	"testing"
)

func TestLifecycleInterestMarkedRevokedBeforeAsynchronousCancel(t *testing.T) {
	o, _, _ := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	lease, e := o.AuthenticatePublication(ctx, "a", func(domain.Device, []byte) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Finish()
	if e = o.WithNativeInterest(ctx, lease.Context, "a", func([]byte) error { return nil }); e != nil {
		t.Fatal(e)
	}
	o.mu.Lock()
	revoked := o.work.Collect(func(scope domain.WorkScope) bool { return scope.DeviceID == "a" })
	o.mu.Unlock()
	var called atomic.Bool
	if e = o.WithNativeInterest(ctx, lease.Context, "a", func([]byte) error { called.Store(true); return nil }); !errors.Is(e, domain.ErrStaleAdmission) || called.Load() {
		t.Fatal("marked interest renewed before cancellation", e)
	}
	if lease.Context.Err() != nil {
		t.Fatal("test barrier not before asynchronous cancel")
	}
	for _, l := range revoked {
		l.Cancel()
		l.Finish()
	}
}
func TestLifecycleInterestRejectsUncertainPublicationAndRecovery(t *testing.T) {
	files := defaultStateFiles()
	base := files
	var fail atomic.Bool
	files.openDir = func(p string) (stateDirectory, error) {
		if fail.Load() {
			return nil, faultError
		}
		return base.openDir(p)
	}
	o, _, _ := ownerFixture(t, files)
	ctx := context.Background()
	lease, e := o.AuthenticatePublication(ctx, "a", func(domain.Device, []byte) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	joined := make(chan struct{})
	go func() { <-lease.Context.Done(); lease.Finish(); close(joined) }()
	c := desired(t, o, "a")
	c.Device.Name = "changed"
	fail.Store(true)
	if _, e = o.Commit(ctx, []domain.DeviceConfiguration{c}); !errors.Is(e, ErrCommitUncertain) {
		t.Fatal(e)
	}
	await(t, joined)
	if e = o.WithNativeInterest(ctx, lease.Context, "a", func([]byte) error { t.Error("uncertain interest used"); return nil }); !errors.Is(e, ErrCommitUncertain) {
		t.Fatal(e)
	}
	fail.Store(false)
	if e = o.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	if e = o.WithNativeInterest(ctx, lease.Context, "a", func([]byte) error { t.Error("recovery revived old interest"); return nil }); !errors.Is(e, domain.ErrStaleAdmission) {
		t.Fatal(e)
	}
}
