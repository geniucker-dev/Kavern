package store

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"sync/atomic"
	"testing"
)

func TestOwnedAdmissionPublicationRevokesOnlyAffectedWork(t *testing.T) {
	for _, kind := range []string{"target", "listener", "disable-tunnel", "delete", "disable-device", "policy"} {
		t.Run(kind, func(t *testing.T) {
			o, _, _ := ownerFixture(t, defaultStateFiles())
			ctx := context.Background()
			a, work, err := o.AdmitTunnel(ctx, "a-tunnel", 1)
			if err != nil {
				t.Fatal(err)
			}
			_, other, err := o.AdmitTunnel(ctx, "b-tunnel", 1)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Finish()
			auth, err := o.AuthenticatePublication(ctx, "a", func(domain.Device, []byte) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer work.Finish()
			defer auth.Finish()
			c := desired(t, o, "a")
			switch kind {
			case "target":
				c.Tunnels[0].TargetAddr = "127.0.0.1:2222"
			case "listener":
				c.Tunnels[0].Listener = "127.0.0.1:3333"
			case "disable-tunnel":
				c.Tunnels[0].Enabled = false
			case "delete":
				c.Tunnels = nil
			case "disable-device":
				c.Device.Enabled = false
			case "policy":
				c.Policy.Carriers++
			}
			cleaned := make(chan struct{})
			go func() {
				defer close(cleaned)
				if kind == "policy" {
					<-auth.Context.Done()
					auth.Finish()
					<-work.Context.Done()
					work.Finish()
				} else {
					<-work.Context.Done()
					if _, err := o.RouteView(ctx, "b-tunnel"); err != nil {
						t.Error(err)
					}
					work.Finish()
					if kind == "disable-device" {
						<-auth.Context.Done()
						auth.Finish()
					}
				}
			}()
			if _, err = o.Commit(ctx, []domain.DeviceConfiguration{c}); err != nil {
				t.Fatal(err)
			}
			await(t, cleaned)
			if other.Context.Err() != nil {
				t.Fatal("unaffected route revoked")
			}
			if kind == "policy" && work.Context.Err() == nil {
				t.Fatal("policy retirement failed to cancel device route")
			}
			if kind != "policy" && kind != "disable-device" && auth.Context.Err() != nil {
				t.Fatal("tunnel edit revoked whole session")
			}
			if a.Device.ID != "a" || a.Tunnel.ID != "a-tunnel" || a.Revision != 1 {
				t.Fatal("incoherent admission")
			}
			if kind == "target" {
				if _, _, err = o.AdmitTunnel(ctx, "a-tunnel", 1); !errors.Is(err, domain.ErrStaleAdmission) {
					t.Fatal("stale generation admitted", err)
				}
			}
		})
	}
}
func TestOwnedAdmissionCleanupTimeoutKeepsDurableRevision(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	_, work, err := o.AdmitTunnel(context.Background(), "a-tunnel", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer work.Finish()
	c := desired(t, o, "a")
	c.Tunnels[0].TargetAddr = "127.0.0.1:2222"
	revisions, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c})
	if !errors.Is(err, session.ErrWorkCleanupPending) || revisions["a"] != 2 {
		t.Fatal("durable cleanup result lost", err)
	}
	loaded, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	view, err := loaded.RouteView(context.Background(), "a-tunnel")
	if err != nil || view.Revision != 2 || view.Tunnel.TargetAddr != c.Tunnels[0].TargetAddr {
		t.Fatal("durable state rolled back", err)
	}
	if work.Context.Err() == nil {
		t.Fatal("cleanup timeout failed to cancel work")
	}
	work.Finish()
}
func TestOwnedAdmissionBoundsAndClose(t *testing.T) {
	o, _, _ := ownerFixture(t, defaultStateFiles())
	o.work = session.NewWorkSet(1)
	_, work, err := o.AdmitTunnel(context.Background(), "a-tunnel", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = o.AdmitTunnel(context.Background(), "a-tunnel", 1); !errors.Is(err, session.ErrWorkCapacity) {
		t.Fatal("unbounded work", err)
	}
	_, shared, err := o.AdmitTunnel(work.Context, "a-tunnel", 1)
	if err != nil || shared != nil {
		t.Fatal("route-open double registration", err)
	}
	done := make(chan struct{})
	go func() {
		<-work.Context.Done()
		if _, err := o.RouteView(context.Background(), "a-tunnel"); !errors.Is(err, ErrConfigOwnerClosed) {
			t.Error(err)
		}
		work.Finish()
		close(done)
	}()
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	await(t, done)
	if o.work.Count() != 0 {
		t.Fatal("work retained")
	}
}

func TestOwnedUncertainPublicationRevokesAndRecoveryDoesNotResurrect(t *testing.T) {
	base := defaultStateFiles()
	files := base
	var fail atomic.Bool
	files.openDir = func(path string) (stateDirectory, error) {
		if fail.Load() {
			return nil, faultError
		}
		return base.openDir(path)
	}
	o, _, _ := ownerFixture(t, files)
	_, work, err := o.AdmitTunnel(context.Background(), "a-tunnel", 1)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		<-work.Context.Done()
		if _, err := o.RouteView(context.Background(), "a-tunnel"); !errors.Is(err, ErrCommitUncertain) {
			t.Error(err)
		}
		work.Finish()
		close(finished)
	}()
	c := desired(t, o, "a")
	c.Tunnels[0].TargetAddr = "127.0.0.1:2222"
	fail.Store(true)
	if _, err = o.Commit(context.Background(), []domain.DeviceConfiguration{c}); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain commit admitted", err)
	}
	await(t, finished)
	if _, _, err = o.AdmitTunnel(context.Background(), "a-tunnel", 0); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain route admitted", err)
	}
	fail.Store(false)
	if err = o.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	view, fresh, err := o.AdmitTunnel(context.Background(), "a-tunnel", 2)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Finish()
	if view.Tunnel.TargetAddr != c.Tunnels[0].TargetAddr || work.Context.Err() == nil || o.work.Count() != 0 {
		t.Fatal("recovery resurrected obsolete work")
	}
}
