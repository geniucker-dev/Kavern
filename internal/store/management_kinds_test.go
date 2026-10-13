package store

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"testing"
)

func TestCredentialKindsAreStoredFactsForDisabledDevices(t *testing.T) {
	o, _, _ := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	m := Mutation{Window: mutationWindow(t, o), OperationID: "create-disabled-native", Kind: "create_device", Device: &domain.Device{ID: "disabled-native", ProjectID: "project", Enabled: false}, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}
	applyMutation(t, o, m, nil)
	kinds, e := o.DeviceCredentialKinds(ctx, "disabled-native")
	if e != nil || len(kinds) != 1 || kinds[0] != domain.CredentialKindKAPv1DeviceSecret {
		t.Fatal("disabled stored native kind missing", e)
	}
	kinds[0] = "corrupted"
	kinds, e = o.DeviceCredentialKinds(ctx, "disabled-native")
	if e != nil || kinds[0] != domain.CredentialKindKAPv1DeviceSecret {
		t.Fatal("metadata aliases internal state")
	}
	if _, _, e = o.ResolveKAPv1DeviceForAuth(ctx, "disabled-native"); e == nil {
		t.Fatal("disabled device authenticated")
	}
	if _, e = o.DeviceCredentialKinds(ctx, "unknown"); !errors.Is(e, ErrNotFound) {
		t.Fatal("unknown device metadata", e)
	}
	o.mu.Lock()
	o.uncertain = true
	o.mu.Unlock()
	if _, e = o.DeviceCredentialKinds(ctx, "disabled-native"); !errors.Is(e, ErrCommitUncertain) {
		t.Fatal("uncertain metadata accepted")
	}
	o.mu.Lock()
	o.uncertain = false
	o.mu.Unlock()
}
