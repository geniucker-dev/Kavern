package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/session"
)

func mutationWindow(t *testing.T, o *ConfigOwner) ManagementWindow {
	t.Helper()
	w, e := o.ManagementWindow(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return w
}
func applyMutation(t *testing.T, o *ConfigOwner, m Mutation, key []byte) MutationResult {
	t.Helper()
	r, e := o.ApplyMutation(context.Background(), m, key)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestMutationCreationMigrationAndRedactedRetry(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	m := Mutation{Window: mutationWindow(t, o), OperationID: "create-user", Kind: "create_user", User: &domain.User{ID: "new-user", Name: "name"}}
	r := applyMutation(t, o, m, nil)
	if r.Replay || r.Window.Lineage == "" {
		t.Fatal("missing migrated result")
	}
	retry := applyMutation(t, o, m, nil)
	if !retry.Replay {
		t.Fatal("first migrated receipt did not recover")
	}
	m.OperationID = "another-create"
	m.Window = mutationWindow(t, o)
	if _, e := o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrRecordConflict) {
		t.Fatal("overwrite accepted", e)
	}
	m = Mutation{Window: mutationWindow(t, o), OperationID: "create-project", Kind: "create_project", Project: &domain.Project{ID: "new-project", UserID: "new-user"}}
	applyMutation(t, o, m, nil)
	m.Window = mutationWindow(t, o)
	m.OperationID = "reparent-project"
	m.Project.UserID = "user"
	if _, e := o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrRecordConflict) {
		t.Fatal("reparent accepted", e)
	}
	m = Mutation{Window: mutationWindow(t, o), OperationID: "create-native", Kind: "create_device", Device: &domain.Device{ID: "new-device", ProjectID: "new-project", Enabled: true}, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}
	r = applyMutation(t, o, m, nil)
	if r.Credential == "" || r.Revision != 1 {
		t.Fatal("issuance missing")
	}
	secret := r.Credential
	encoded, e := json.Marshal(r)
	if e != nil || bytes.Contains(encoded, []byte(secret)) {
		t.Fatal("credential serialized")
	}
	retry = applyMutation(t, o, m, nil)
	if !retry.Replay || retry.Credential != "" {
		t.Fatal("credential redelivered")
	}
	if bytes.Contains(readBytes(t, path), []byte(secret)) {
		t.Fatal("credential persisted raw")
	}
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
	o, e = OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	retry = applyMutation(t, o, m, nil)
	if !retry.Replay || retry.Credential != "" {
		t.Fatal("restart receipt lost")
	}
	m.Device.Name = "changed"
	if _, e = o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrOperationReuse) {
		t.Fatal("ID reuse accepted", e)
	}
}
func TestMutationNoopReceiptEvictionAndOfflineRewrite(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	c := desired(t, o, "a")
	first := Mutation{Window: mutationWindow(t, o), OperationID: "first-noop", Kind: "put_device", DeviceID: "a", ExpectedRevision: c.Revision, Configuration: &c}
	r := applyMutation(t, o, first, nil)
	if r.Revision != 1 {
		t.Fatal("no-op advanced revision")
	}
	for i := 0; i < MaxMutationReceipts; i++ {
		m := first
		m.Window = mutationWindow(t, o)
		m.OperationID = fmt.Sprintf("noop-%d", i)
		r = applyMutation(t, o, m, nil)
		if r.Revision != 1 {
			t.Fatal("no-op changed desired")
		}
	}
	if _, e := o.ApplyMutation(ctx, first, nil); !errors.Is(e, ErrOperationExpired) {
		t.Fatal("evicted no-op reapplied", e)
	}
	if _, e := o.LookupOperation(ctx, first.Window, first.OperationID); !errors.Is(e, ErrOperationExpired) {
		t.Fatal("expired lookup untruthful", e)
	}
	w := mutationWindow(t, o)
	if len(o.current.management.Receipts) != MaxMutationReceipts {
		t.Fatal("receipt bound")
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	disk, e := LoadState(path, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = disk.SaveState(path, key); e != nil {
		t.Fatal(e)
	}
	o, e = OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	fresh := first
	fresh.Window = w
	fresh.OperationID = "after-offline"
	if _, e = o.ApplyMutation(ctx, fresh, nil); !errors.Is(e, ErrOperationExpired) {
		t.Fatal("offline rewrite reused stale epoch", e)
	}
}
func TestMutationCASOwnershipCascadeAndTombstones(t *testing.T) {
	o, path, _ := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	before := desired(t, o, "b")
	c := desired(t, o, "a")
	m := Mutation{Window: mutationWindow(t, o), OperationID: "bad-owner", Kind: "put_device", DeviceID: "a", ExpectedRevision: 1, Configuration: &c}
	c.Tunnels[0].DeviceID = "b"
	if _, e := o.ApplyMutation(ctx, m, nil); e == nil {
		t.Fatal("target owner accepted")
	}
	c = desired(t, o, "a")
	c.Device.ProjectID = "other"
	if _, e := o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrTunnelOwnership) {
		t.Fatal("project move accepted", e)
	}
	c = desired(t, o, "a")
	c.Tunnels[0].TargetAddr = "127.0.0.1:2345"
	m.OperationID = "update"
	r := applyMutation(t, o, m, nil)
	if r.Revision != 2 {
		t.Fatal("CAS revision")
	}
	m.OperationID = "stale"
	m.Window = mutationWindow(t, o)
	if _, e := o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrRevisionConflict) {
		t.Fatal("stale revision accepted", e)
	}
	del := Mutation{Window: mutationWindow(t, o), OperationID: "delete", Kind: "delete_device", DeviceID: "a", ExpectedRevision: 2}
	file := readBytes(t, path)
	if _, e := o.ApplyMutation(ctx, del, nil); !errors.Is(e, ErrCascadeRequired) {
		t.Fatal("implicit cascade", e)
	}
	if !bytes.Equal(file, readBytes(t, path)) {
		t.Fatal("rejection wrote state")
	}
	del.Cascade = true
	applyMutation(t, o, del, nil)
	if _, e := o.DeviceConfiguration(ctx, "a"); !errors.Is(e, ErrNotFound) {
		t.Fatal("device retained", e)
	}
	if !bytes.Equal(mustJSON(t, before), mustJSON(t, desired(t, o, "b"))) {
		t.Fatal("unrelated changed")
	}
	recreate := Mutation{Window: mutationWindow(t, o), OperationID: "recreate", Kind: "create_device", Device: &domain.Device{ID: "a", ProjectID: "project"}, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}
	if _, e := o.ApplyMutation(ctx, recreate, nil); !errors.Is(e, ErrRecordConflict) {
		t.Fatal("device identity reused", e)
	}
	b := desired(t, o, "b")
	b.Tunnels = append(b.Tunnels, domain.Tunnel{ID: "a-tunnel", DeviceID: "b", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:1003", TargetAddr: "127.0.0.1:2003"})
	m = Mutation{Window: mutationWindow(t, o), OperationID: "reuse-tunnel", Kind: "put_device", DeviceID: "b", ExpectedRevision: b.Revision, Configuration: &b}
	if _, e := o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrRecordConflict) {
		t.Fatal("tunnel identity reused", e)
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestMutationUncertainReceiptRequiresRecovery(t *testing.T) {
	base := defaultStateFiles()
	files := base
	var fail atomic.Bool
	files.openDir = func(p string) (stateDirectory, error) {
		if fail.Load() {
			return nil, faultError
		}
		return base.openDir(p)
	}
	o, _, _ := ownerFixture(t, files)
	ctx := context.Background()
	m := Mutation{Window: mutationWindow(t, o), OperationID: "uncertain-create", Kind: "create_user", User: &domain.User{ID: "created"}}
	fail.Store(true)
	r, e := o.ApplyMutation(ctx, m, nil)
	if !errors.Is(e, ErrCommitUncertain) || r.Credential != "" || r.RecordID != "" {
		t.Fatal("uncertain output claimed success", e)
	}
	if _, e = o.LookupOperation(ctx, m.Window, m.OperationID); !errors.Is(e, ErrCommitUncertain) {
		t.Fatal("lookup inferred rollback", e)
	}
	if _, e = o.ManagementWindow(ctx); !errors.Is(e, ErrCommitUncertain) {
		t.Fatal("uncertain window")
	}
	if _, e = o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrCommitUncertain) {
		t.Fatal("uncertain retry")
	}
	fail.Store(false)
	if e = o.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	r = applyMutation(t, o, m, nil)
	if !r.Replay {
		t.Fatal("recovered receipt not found")
	}
}
func TestMutationRotationRevokesNativeAndLegacyInterests(t *testing.T) {
	for _, kind := range []domain.CredentialKind{domain.CredentialKindKAPv1DeviceSecret, domain.CredentialKindLegacyNPC} {
		t.Run(string(kind), func(t *testing.T) {
			o, path, masterKey := ownerFixture(t, defaultStateFiles())
			ctx := context.Background()
			legacyKey := bytes.Repeat([]byte{3}, 32)
			// Provision only a synthetic fixture while its owner is stopped.
			if e := o.Close(); e != nil {
				t.Fatal(e)
			}
			fixture, e := LoadState(path, masterKey)
			if e != nil {
				t.Fatal(e)
			}
			issued, e := fixture.IssueLegacyCredential(ctx, "a", legacyKey)
			if e != nil {
				t.Fatal(e)
			}
			if e = fixture.SaveState(path, masterKey); e != nil {
				t.Fatal(e)
			}
			o, e = OpenConfigOwner(path, masterKey, domain.DefaultNativePolicy())
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			if e != nil {
				t.Fatal(e)
			}
			token, e := security.LegacyWireTokenFromVKey(issued.VKey)
			if e != nil {
				t.Fatal(e)
			}
			lookup, e := security.LegacyLookupKey(legacyKey, token)
			if e != nil {
				t.Fatal(e)
			}
			native, e := o.AuthenticatePublication(ctx, "a", func(domain.Device, []byte) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			legacy, e := o.AcquireLegacyInterest(ctx, "a", lookup)
			if e != nil {
				t.Fatal(e)
			}
			_, route, e := o.AdmitTunnel(ctx, "a-tunnel", 1)
			if e != nil {
				t.Fatal(e)
			}
			joined := make(chan struct{})
			go func() {
				<-native.Context.Done()
				native.Finish()
				<-legacy.Context.Done()
				legacy.Finish()
				<-route.Context.Done()
				route.Finish()
				close(joined)
			}()
			oldSecret := append([]byte(nil), o.current.kapv1Secret["a"]...)
			m := Mutation{Window: mutationWindow(t, o), OperationID: "rotate", Kind: "rotate_credential", DeviceID: "a", ExpectedRevision: 1, CredentialKind: kind}
			r := applyMutation(t, o, m, legacyKey)
			await(t, joined)
			if r.Credential == "" || r.Revision != 2 {
				t.Fatal("rotation result")
			}
			called := false
			if e = o.WithLegacyPublication(legacy.Context, "a", lookup, func() error { called = true; return nil }); e == nil || called {
				t.Fatal("late legacy attachment accepted")
			}
			if kind == domain.CredentialKindKAPv1DeviceSecret && bytes.Equal(oldSecret, o.current.kapv1Secret["a"]) {
				t.Fatal("native secret unchanged")
			}
			if kind == domain.CredentialKindLegacyNPC {
				if _, e = o.ResolveLegacyDeviceForAuth(ctx, lookup); e == nil {
					t.Fatal("old legacy key authenticates")
				}
			}
		})
	}
}
func TestMutationReceiptAndConfigurationAtomicFaultMatrix(t *testing.T) {
	for _, stage := range []string{"create", "write", "short-write", "file-sync", "file-close", "rename", "directory-open", "directory-sync", "directory-close"} {
		t.Run(stage, func(t *testing.T) {
			base := defaultStateFiles()
			files := base
			var armed atomic.Bool
			files.createTemp = func(d, p string) (stateTemp, error) {
				if armed.Load() && stage == "create" {
					return nil, faultError
				}
				f, e := base.createTemp(d, p)
				if e != nil {
					return nil, e
				}
				s := ""
				if armed.Load() {
					s = stage
				}
				return faultTemp{f, s}, nil
			}
			files.rename = func(a, b string) error {
				if armed.Load() && stage == "rename" {
					return faultError
				}
				return base.rename(a, b)
			}
			files.openDir = func(p string) (stateDirectory, error) {
				if armed.Load() && stage == "directory-open" {
					return nil, faultError
				}
				f, e := base.openDir(p)
				if e != nil {
					return nil, e
				}
				s := ""
				if armed.Load() {
					s = stage
				}
				return faultDir{f, s}, nil
			}
			o, path, key := ownerFixture(t, files)
			ctx := context.Background()
			before := readBytes(t, path)
			c := desired(t, o, "a")
			c.Device.Name = "changed"
			m := Mutation{Window: mutationWindow(t, o), OperationID: "fault-mutation", Kind: "put_device", DeviceID: "a", ExpectedRevision: 1, Configuration: &c}
			armed.Store(true)
			result, e := o.ApplyMutation(ctx, m, nil)
			post := stage == "directory-open" || stage == "directory-sync"
			committed := post || stage == "directory-close"
			if stage == "directory-close" {
				if e != nil || result.Revision != 2 {
					t.Fatal("confirmed durability lost", e)
				}
			} else if e == nil || result.RecordID != "" {
				t.Fatal("fault reported definitive success", e)
			}
			if post {
				if !errors.Is(e, ErrCommitUncertain) {
					t.Fatal("post-rename uncertainty lost", e)
				}
			} else if !committed {
				if errors.Is(e, ErrCommitUncertain) || !bytes.Equal(before, readBytes(t, path)) {
					t.Fatal("pre-rename state changed", e)
				}
			}
			disk, e := LoadState(path, key)
			if e != nil {
				t.Fatal(e)
			}
			dc, e := disk.DeviceConfiguration(ctx, "a")
			if e != nil {
				t.Fatal(e)
			}
			if committed {
				if dc.Revision != 2 || len(disk.management.Receipts) != 1 {
					t.Fatal("receipt and config not atomic")
				}
			} else {
				if dc.Revision != 1 || len(disk.management.Receipts) != 0 {
					t.Fatal("partial mutation persisted")
				}
			}
			armed.Store(false)
			if e = o.Recover(ctx); e != nil {
				t.Fatal(e)
			}
			r := applyMutation(t, o, m, nil)
			if r.Replay != committed || r.Revision != 2 {
				t.Fatal("definitive retry outcome")
			}
		})
	}
}
func TestMutationRejectsMalformedAndOversizedBeforeWrite(t *testing.T) {
	o, path, _ := ownerFixture(t, defaultStateFiles())
	before := readBytes(t, path)
	ctx := context.Background()
	w := mutationWindow(t, o)
	for _, name := range []string{string([]byte{0xff}), string(bytes.Repeat([]byte{'x'}, (1<<20)+1))} {
		m := Mutation{Window: w, OperationID: "invalid", Kind: "create_user", User: &domain.User{ID: "invalid-user", Name: name}}
		if _, e := o.ApplyMutation(ctx, m, nil); e == nil {
			t.Fatal("malformed accepted")
		}
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("invalid wrote state")
	}
}
func TestMutationDeletionCapacityAndCompatibilityCommitTombstones(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	c := desired(t, o, "a")
	m := Mutation{Window: mutationWindow(t, o), OperationID: "migrate", Kind: "put_device", DeviceID: "a", ExpectedRevision: 1, Configuration: &c}
	applyMutation(t, o, m, nil)
	c.Tunnels = nil
	if _, e := o.Commit(ctx, []domain.DeviceConfiguration{c}); e != nil {
		t.Fatal(e)
	}
	c = desired(t, o, "a")
	c.Tunnels = []domain.Tunnel{{ID: "a-tunnel", DeviceID: "a", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:3001", TargetAddr: "127.0.0.1:3002"}}
	if _, e := o.Commit(ctx, []domain.DeviceConfiguration{c}); e == nil {
		t.Fatal("compatibility actor reused deleted identity")
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	fixture, e := LoadState(path, key)
	if e != nil {
		t.Fatal(e)
	}
	for i := len(fixture.management.Tombstones); i < MaxMutationTombstones; i++ {
		fixture.management.Tombstones = append(fixture.management.Tombstones, tombstone{"tunnel", fmt.Sprintf("deleted-%d", i)})
	}
	if e = fixture.SaveState(path, key); e != nil {
		t.Fatal(e)
	}
	o, e = OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	before := readBytes(t, path)
	m = Mutation{Window: mutationWindow(t, o), OperationID: "full-delete", Kind: "delete_device", DeviceID: "b", ExpectedRevision: 1, Cascade: true}
	if _, e = o.ApplyMutation(ctx, m, nil); !errors.Is(e, ErrTombstoneCapacity) {
		t.Fatal("capacity silently pruned", e)
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("capacity rejection wrote")
	}
}
func TestMutationSchemaRejectsCorruptManagementMetadata(t *testing.T) {
	o, _, key := ownerFixture(t, defaultStateFiles())
	m := Mutation{Window: mutationWindow(t, o), OperationID: "migrate", Kind: "create_user", User: &domain.User{ID: "new-user"}}
	applyMutation(t, o, m, nil)
	for name, mutate := range map[string]func(*MemoryStore){
		"lineage":             func(s *MemoryStore) { s.management.Lineage = "invalid" },
		"zero-epoch":          func(s *MemoryStore) { s.management.Epoch = 0 },
		"receipt-digest":      func(s *MemoryStore) { s.management.Receipts[0].Digest = "invalid" },
		"request-window":      func(s *MemoryStore) { s.management.Receipts[0].RequestWindow.Epoch = 100 },
		"receipt-revision":    func(s *MemoryStore) { s.management.Receipts[0].Revision = 1 },
		"duplicate-operation": func(s *MemoryStore) { s.management.Receipts = append(s.management.Receipts, s.management.Receipts[0]) },
		"live-tombstone":      func(s *MemoryStore) { s.management.Tombstones = []tombstone{{"device", "a"}} },
		"unknown-tombstone":   func(s *MemoryStore) { s.management.Tombstones = []tombstone{{"user", "old"}} },
	} {
		t.Run(name, func(t *testing.T) {
			o.current.mu.RLock()
			candidate := o.current.cloneLocked()
			o.current.mu.RUnlock()
			mutate(candidate)
			if _, e := candidate.encodeState(key); !errors.Is(e, ErrInvalidState) {
				t.Fatal("corrupt metadata accepted", e)
			}
		})
	}
}
func TestManagementSavedCleanupPendingDoesNotRedeliverCredential(t *testing.T) {
	o, _, _ := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	lease, e := o.AuthenticatePublication(ctx, "a", func(domain.Device, []byte) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Finish()
	m := Mutation{Window: mutationWindow(t, o), OperationID: "pending-cleanup", Kind: "rotate_credential", DeviceID: "a", ExpectedRevision: 1, CredentialKind: domain.CredentialKindKAPv1DeviceSecret}
	r, e := o.ApplyMutation(ctx, m, nil)
	if !errors.Is(e, session.ErrWorkCleanupPending) || !r.Saved || r.Cleanup != "pending" || r.Credential == "" || r.Revision != 2 {
		t.Fatal("durable pending result lost", e)
	}
	if lease.Context.Err() == nil {
		t.Fatal("revocation not requested")
	}
	lease.Finish()
	retry := applyMutation(t, o, m, nil)
	if !retry.Saved || !retry.Replay || retry.Cleanup != "unknown" || retry.Credential != "" {
		t.Fatal("receipt invented runtime or secret state")
	}
}

func TestMutationLookupRequiresExactRequestWindowAcrossIDReuseAndRestart(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	c := desired(t, o, "a")
	applyMutation(t, o, Mutation{Window: mutationWindow(t, o), OperationID: "lookup-bootstrap", Kind: "put_device", DeviceID: "a", ExpectedRevision: c.Revision, Configuration: &c}, nil)
	old := Mutation{Window: mutationWindow(t, o), OperationID: "lookup-reused", Kind: "create_user", User: &domain.User{ID: "lookup-old-user"}}
	applyMutation(t, o, old, nil)
	for i := 0; i < MaxMutationReceipts; i++ {
		applyMutation(t, o, Mutation{Window: mutationWindow(t, o), OperationID: fmt.Sprintf("lookup-noop-%d", i), Kind: "put_device", DeviceID: "a", ExpectedRevision: c.Revision, Configuration: &c}, nil)
	}
	if _, e := o.LookupOperation(ctx, old.Window, old.OperationID); !errors.Is(e, ErrOperationExpired) {
		t.Fatal("old receipt not evicted", e)
	}
	fresh := Mutation{Window: mutationWindow(t, o), OperationID: old.OperationID, Kind: "create_user", User: &domain.User{ID: "lookup-new-user"}}
	applyMutation(t, o, fresh, nil)
	check := func() {
		t.Helper()
		if r, e := o.LookupOperation(ctx, old.Window, old.OperationID); !errors.Is(e, ErrOperationExpired) || r.Saved {
			t.Fatal("old request resolved a reused ID", e)
		}
		r, e := o.LookupOperation(ctx, fresh.Window, fresh.OperationID)
		if e != nil || !r.Saved || !r.Replay || r.RecordID != "lookup-new-user" {
			t.Fatal("exact new request lookup failed", e)
		}
		wrongEpoch := fresh.Window
		wrongEpoch.Epoch++
		if _, e = o.LookupOperation(ctx, wrongEpoch, fresh.OperationID); !errors.Is(e, ErrOperationExpired) {
			t.Fatal("different epoch accepted", e)
		}
	}
	check()
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	o, e = OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	check()
}
func TestExactMutationLookupNeverExecutesOrAcceptsChangedContent(t *testing.T) {
	o, _, _ := ownerFixture(t, defaultStateFiles())
	m := Mutation{Window: mutationWindow(t, o), OperationID: "exact-read", Kind: "create_user", User: &domain.User{ID: "exact-user", Name: "original"}}
	if _, e := o.LookupMutation(context.Background(), m); !errors.Is(e, ErrOperationExpired) {
		t.Fatal("lookup executed unknown request", e)
	}
	before := mutationWindow(t, o)
	applyMutation(t, o, m, nil)
	after := mutationWindow(t, o)
	r, e := o.LookupMutation(context.Background(), m)
	if e != nil || !r.Saved || !r.Replay || r.Credential != "" {
		t.Fatal("exact lookup result", e)
	}
	if mutationWindow(t, o) != after || before == after {
		t.Fatal("lookup mutated ledger")
	}
	changed := m
	changed.User = &domain.User{ID: "exact-user", Name: "tampered"}
	if _, e = o.LookupMutation(context.Background(), changed); !errors.Is(e, ErrOperationReuse) {
		t.Fatal("changed request claimed receipt", e)
	}
	changed = m
	changed.Window.Epoch++
	if _, e = o.LookupMutation(context.Background(), changed); !errors.Is(e, ErrOperationExpired) {
		t.Fatal("changed original window accepted", e)
	}
}
