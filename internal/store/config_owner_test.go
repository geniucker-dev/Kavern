package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

var faultError = errors.New("injected persistence failure")

func ownerFixture(t *testing.T, files stateFiles) (*ConfigOwner, string, []byte) {
	t.Helper()
	s := NewMemoryStore()
	ctx := context.Background()
	_ = s.CreateUser(ctx, domain.User{ID: "user"})
	_ = s.CreateProject(ctx, domain.Project{ID: "project", UserID: "user"})
	for i, id := range []domain.DeviceID{"a", "b"} {
		_ = s.CreateDevice(ctx, domain.Device{ID: id, ProjectID: "project", Enabled: true})
		_ = s.CreateTunnel(ctx, domain.Tunnel{ID: domain.TunnelID(string(id) + "-tunnel"), DeviceID: id, Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 1001+i)), TargetAddr: fmt.Sprintf("127.0.0.1:%d", 2001+i), Enabled: true})
	}
	_ = s.SetKAPv1DeviceSecret(ctx, "a", bytes.Repeat([]byte{0x51}, 32))
	key := bytes.Repeat([]byte{0x62}, 32)
	path := filepath.Join(t.TempDir(), "private", "state.json")
	if err := s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	o, err := openConfigOwner(path, key, domain.DefaultNativePolicy(), files)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o, path, key
}

func desired(t *testing.T, o *ConfigOwner, id domain.DeviceID) domain.DeviceConfiguration {
	t.Helper()
	c, err := o.DeviceConfiguration(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("barrier did not complete")
	}
}

func TestConfigOwnerCASIsolationNoopAndIndexes(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	ctx := context.Background()
	a, b := desired(t, o, "a"), desired(t, o, "b")
	before := readBytes(t, path)
	if _, err := o.Commit(ctx, []domain.DeviceConfiguration{a}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("no-op rewrote file")
	}
	a.Tunnels[0].Listener = "127.0.0.1:1003"
	a.Tunnels[0].TargetAddr = "127.0.0.1:2003"
	a.Policy.Carriers = 3
	r, err := o.Commit(ctx, []domain.DeviceConfiguration{a})
	if err != nil || r["a"] != 2 {
		t.Fatal("CAS commit failed", err)
	}
	if !reflect.DeepEqual(b, desired(t, o, "b")) {
		t.Fatal("unrelated device changed")
	}
	if _, err = o.Commit(ctx, []domain.DeviceConfiguration{a}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatal("stale CAS accepted", err)
	}
	loaded, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loaded.FindTunnelByListener(ctx, "127.0.0.1:1001"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old index retained")
	}
	if tnl, err := loaded.FindTunnelByListener(ctx, "127.0.0.1:1003"); err != nil || tnl.ID != "a-tunnel" {
		t.Fatal("new index missing")
	}
	snap, err := o.NativeSnapshot(ctx, "a")
	if err != nil || len(snap.Tunnels) != 1 || snap.Tunnels[0].TargetAddr != "127.0.0.1:2003" || snap.Policy.Carriers != 3 || snap.Revision != 2 {
		t.Fatal("wrong device projection", err)
	}
	if _, err = o.NativeSnapshot(ctx, "b"); !errors.Is(err, ErrNativeIneligible) {
		t.Fatal("legacy record became native")
	}
	a = desired(t, o, "a")
	a.Tunnels = nil
	if _, err = o.Commit(ctx, []domain.DeviceConfiguration{a}); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loaded.FindTunnelByListener(ctx, "127.0.0.1:1003"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted listener retained")
	}
	if snap, err = o.NativeSnapshot(ctx, "a"); err != nil || len(snap.Tunnels) != 0 {
		t.Fatal("empty projection failed", err)
	}
}

func TestConfigOwnerConcurrentSameAndDifferentDeviceWrites(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same", false: "different"}[same], func(t *testing.T) {
			o, path, key := ownerFixture(t, defaultStateFiles())
			a := desired(t, o, "a")
			b := desired(t, o, "b")
			if same {
				b = desired(t, o, "a")
			}
			a.Device.Enabled = false
			b.Tunnels[0].TargetAddr = "127.0.0.1:2010"
			start := make(chan struct{})
			results := make(chan error, 2)
			for _, c := range []domain.DeviceConfiguration{a, b} {
				go func(c domain.DeviceConfiguration) {
					<-start
					_, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c})
					results <- err
				}(c)
			}
			close(start)
			success, conflict := 0, 0
			for i := 0; i < 2; i++ {
				err := <-results
				if err == nil {
					success++
				} else if errors.Is(err, ErrRevisionConflict) {
					conflict++
				} else {
					t.Fatal(err)
				}
			}
			if same && (success != 1 || conflict != 1) || !same && success != 2 {
				t.Fatal("lost concurrent CAS isolation")
			}
			loaded, err := LoadState(path, key)
			if err != nil {
				t.Fatal(err)
			}
			if !same {
				ca, _ := loaded.DeviceConfiguration(context.Background(), "a")
				cb, _ := loaded.DeviceConfiguration(context.Background(), "b")
				if ca.Device.Enabled || cb.Tunnels[0].TargetAddr != "127.0.0.1:2010" || ca.Revision != 2 || cb.Revision != 2 {
					t.Fatal("cross-device whole-file update lost")
				}
			}
		})
	}
}

func TestConfigOwnerRejectsNewTunnelIDCollisionAcrossBatch(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%t", reverse), func(t *testing.T) {
			o, path, key := ownerFixture(t, defaultStateFiles())
			ctx := context.Background()
			beforeFile := readBytes(t, path)
			beforeA, beforeB := desired(t, o, "a"), desired(t, o, "b")
			a, b := desired(t, o, "a"), desired(t, o, "b")
			for i, c := range []*domain.DeviceConfiguration{&a, &b} {
				c.Tunnels = append(c.Tunnels, domain.Tunnel{
					ID: "new-shared-id", DeviceID: c.Device.ID, Protocol: domain.TunnelProtocolTCP,
					Listener:   domain.ListenerRef(fmt.Sprintf("127.0.0.1:%d", 4001+i)),
					TargetAddr: "127.0.0.1:5001", Enabled: true,
				})
			}
			changes := []domain.DeviceConfiguration{a, b}
			if reverse {
				changes[0], changes[1] = changes[1], changes[0]
			}
			revisions, err := o.Commit(ctx, changes)
			if !errors.Is(err, config.ErrInvalidBusinessConfig) || revisions != nil {
				t.Fatalf("duplicate new tunnel ID accepted: revisions=%v error=%v", revisions, err)
			}
			if !bytes.Equal(beforeFile, readBytes(t, path)) {
				t.Fatal("rejected batch changed persistent file")
			}
			if !reflect.DeepEqual(beforeA, desired(t, o, "a")) || !reflect.DeepEqual(beforeB, desired(t, o, "b")) {
				t.Fatal("rejected batch changed live configurations or revisions")
			}
			loaded, err := LoadState(path, key)
			if err != nil {
				t.Fatal(err)
			}
			diskA, err := loaded.DeviceConfiguration(ctx, "a")
			if err != nil {
				t.Fatal(err)
			}
			diskB, err := loaded.DeviceConfiguration(ctx, "b")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(beforeA, diskA) || !reflect.DeepEqual(beforeB, diskB) {
				t.Fatal("rejected batch changed persisted configurations or revisions")
			}
		})
	}
}

func TestConfigOwnerRejectsInvalidCandidatesBeforeWriting(t *testing.T) {
	for name, mutate := range map[string]func(*domain.DeviceConfiguration){
		"ownership": func(c *domain.DeviceConfiguration) { c.Tunnels[0].DeviceID = "b" },
		"project":   func(c *domain.DeviceConfiguration) { c.Device.ProjectID = "missing" },
		"target":    func(c *domain.DeviceConfiguration) { c.Tunnels[0].TargetAddr = "127.0.0.1:0" },
		"disabled-native-target": func(c *domain.DeviceConfiguration) {
			c.Device.Enabled = false
			c.Tunnels[0].Enabled = false
			c.Tunnels[0].TargetAddr = strings.Repeat("x", 513) + ":1"
		},
		"listener-conflict": func(c *domain.DeviceConfiguration) { c.Tunnels[0].Listener = "127.0.0.1:1002" },
		"duplicate":         func(c *domain.DeviceConfiguration) { c.Tunnels = append(c.Tunnels, c.Tunnels[0]) },
		"policy":            func(c *domain.DeviceConfiguration) { c.Policy.MaxStreams = 0 },
		"oversized-state":   func(c *domain.DeviceConfiguration) { c.Device.Name = strings.Repeat("x", config.MaxJSONBytes) },
	} {
		t.Run(name, func(t *testing.T) {
			o, path, _ := ownerFixture(t, defaultStateFiles())
			before := readBytes(t, path)
			c := desired(t, o, "a")
			mutate(&c)
			if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err == nil {
				t.Fatal("invalid candidate accepted")
			}
			if !bytes.Equal(before, readBytes(t, path)) || desired(t, o, "a").Revision != 1 {
				t.Fatal("invalid candidate changed state")
			}
		})
	}
	o, path, _ := ownerFixture(t, defaultStateFiles())
	before := readBytes(t, path)
	a, b := desired(t, o, "a"), desired(t, o, "b")
	a.Tunnels = nil
	b.Tunnels = append(b.Tunnels, domain.Tunnel{ID: "a-tunnel", DeviceID: "b", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:1004", TargetAddr: "127.0.0.1:2004"})
	if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{a, b}); !errors.Is(err, ErrTunnelOwnership) {
		t.Fatal("batch deletion allowed ownership transfer", err)
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("failed batch partially wrote")
	}
}

type faultTemp struct {
	stateTemp
	stage string
}

func (f faultTemp) Write(p []byte) (int, error) {
	if f.stage == "write" {
		return 0, faultError
	}
	if f.stage == "short-write" {
		return f.stateTemp.Write(p[:len(p)-1])
	}
	return f.stateTemp.Write(p)
}
func (f faultTemp) Sync() error {
	if f.stage == "file-sync" {
		return faultError
	}
	return f.stateTemp.Sync()
}
func (f faultTemp) Close() error {
	err := f.stateTemp.Close()
	if f.stage == "file-close" {
		return faultError
	}
	return err
}

type faultDir struct {
	stateDirectory
	stage string
}

func (f faultDir) Sync() error {
	if f.stage == "directory-sync" {
		return faultError
	}
	return f.stateDirectory.Sync()
}
func (f faultDir) Close() error {
	err := f.stateDirectory.Close()
	if f.stage == "directory-close" {
		return faultError
	}
	return err
}

func TestConfigOwnerPersistenceFailuresAndRecovery(t *testing.T) {
	for _, stage := range []string{"create", "write", "short-write", "file-sync", "file-close", "rename", "directory-open", "directory-sync", "directory-close"} {
		t.Run(stage, func(t *testing.T) {
			base, files := defaultStateFiles(), defaultStateFiles()
			var armed atomic.Bool
			files.createTemp = func(d, p string) (stateTemp, error) {
				if armed.Load() && stage == "create" {
					return nil, faultError
				}
				f, err := base.createTemp(d, p)
				if err != nil {
					return nil, err
				}
				return faultTemp{f, stage}, nil
			}
			files.rename = func(a, b string) error {
				if armed.Load() && stage == "rename" {
					return faultError
				}
				return base.rename(a, b)
			}
			files.openDir = func(d string) (stateDirectory, error) {
				if armed.Load() && stage == "directory-open" {
					return nil, faultError
				}
				f, err := base.openDir(d)
				if err != nil {
					return nil, err
				}
				s := ""
				if armed.Load() {
					s = stage
				}
				return faultDir{f, s}, nil
			}
			o, path, key := ownerFixture(t, files)
			before := readBytes(t, path)
			c := desired(t, o, "a")
			c.Tunnels[0].TargetAddr = "127.0.0.1:2011"
			armed.Store(true)
			_, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c})
			post := stage == "directory-open" || stage == "directory-sync"
			if stage == "directory-close" {
				if err != nil || desired(t, o, "a").Revision != 2 {
					t.Fatal("confirmed durability relabeled failed", err)
				}
			} else if post {
				if !errors.Is(err, ErrCommitUncertain) {
					t.Fatal("post-rename failure not uncertain", err)
				}
				if _, err = o.Commit(context.Background(), []domain.DeviceConfiguration{c}); !errors.Is(err, ErrCommitUncertain) {
					t.Fatal("uncertain owner admitted write")
				}
				if _, err = o.NativeSnapshot(context.Background(), "a"); !errors.Is(err, ErrCommitUncertain) {
					t.Fatal("uncertain snapshot admitted")
				}
				loaded, err := LoadState(path, key)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := loaded.DeviceConfiguration(context.Background(), "a")
				if got.Revision != 2 || got.Tunnels[0].TargetAddr != "127.0.0.1:2011" {
					t.Fatal("actual renamed candidate lost")
				}
				if err = o.Recover(context.Background()); !errors.Is(err, ErrCommitUncertain) {
					t.Fatal("failed recovery cleared uncertainty")
				}
				armed.Store(false)
				if err = o.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
				if desired(t, o, "a").Revision != 2 {
					t.Fatal("recovery ignored actual file")
				}
				c = desired(t, o, "a")
				c.Device.Enabled = false
				if _, err = o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err != nil {
					t.Fatal("recovered owner stayed blocked", err)
				}
			} else {
				if err == nil || errors.Is(err, ErrCommitUncertain) {
					t.Fatal("pre-rename outcome wrong", err)
				}
				if !bytes.Equal(before, readBytes(t, path)) || desired(t, o, "a").Revision != 1 {
					t.Fatal("pre-rename failure changed state")
				}
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".state-") {
					t.Fatal("temporary state leaked")
				}
			}
		})
	}
}

type barrierTemp struct {
	stateTemp
	afterClose func()
}

func (f barrierTemp) Close() error { err := f.stateTemp.Close(); f.afterClose(); return err }

type barrierDir struct {
	stateDirectory
	afterSync func()
}

func (f barrierDir) Sync() error {
	err := f.stateDirectory.Sync()
	if err == nil {
		f.afterSync()
	}
	return err
}

func TestConfigOwnerCancellationAndShutdownCommitBoundary(t *testing.T) {
	for _, stage := range []string{"before-rename", "after-rename", "after-directory-sync"} {
		for _, shutdown := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/cancel", true: "/shutdown"}[shutdown], func(t *testing.T) {
				base, files := defaultStateFiles(), defaultStateFiles()
				var armed atomic.Bool
				reached, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				barrier := func() {
					if armed.Load() {
						once.Do(func() { close(reached); <-release })
					}
				}
				if stage == "before-rename" {
					files.createTemp = func(d, p string) (stateTemp, error) {
						f, e := base.createTemp(d, p)
						if e != nil {
							return nil, e
						}
						return barrierTemp{f, barrier}, nil
					}
				}
				if stage == "after-rename" {
					files.rename = func(a, b string) error {
						err := base.rename(a, b)
						if err == nil {
							barrier()
						}
						return err
					}
				}
				if stage == "after-directory-sync" {
					files.openDir = func(d string) (stateDirectory, error) {
						f, e := base.openDir(d)
						if e != nil {
							return nil, e
						}
						return barrierDir{f, barrier}, nil
					}
				}
				o, path, key := ownerFixture(t, files)
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				before := readBytes(t, path)
				c := desired(t, o, "a")
				c.Device.Enabled = false
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				armed.Store(true)
				result := make(chan error, 1)
				go func() { _, err := o.Commit(ctx, []domain.DeviceConfiguration{c}); result <- err }()
				await(t, reached)
				closed := make(chan struct{})
				if shutdown {
					go func() { _ = o.Close(); close(closed) }()
					deadline := time.After(3 * time.Second)
					for {
						o.mu.RLock()
						done := o.closed
						o.mu.RUnlock()
						if done {
							break
						}
						select {
						case <-deadline:
							t.Fatal("shutdown not initiated")
						default:
							runtime.Gosched()
						}
					}
				} else {
					cancel()
				}
				unblock()
				err := <-result
				if stage == "before-rename" {
					if !errors.Is(err, context.Canceled) || !bytes.Equal(before, readBytes(t, path)) {
						t.Fatal("pre-rename cancellation committed", err)
					}
				} else {
					if err != nil {
						t.Fatal("durable commit mislabeled cancellation", err)
					}
					loaded, e := LoadState(path, key)
					if e != nil {
						t.Fatal(e)
					}
					got, _ := loaded.DeviceConfiguration(context.Background(), "a")
					if got.Revision != 2 || got.Device.Enabled {
						t.Fatal("durable canceled commit lost")
					}
				}
				if shutdown {
					await(t, closed)
					unlock, e := LockState(path)
					if e != nil {
						t.Fatal("shutdown retained state lock", e)
					}
					_ = unlock()
				}
			})
		}
	}
}

func TestConfigOwnerQueueBoundAndShutdownJoinsPending(t *testing.T) {
	base, files := defaultStateFiles(), defaultStateFiles()
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	files.rename = func(a, b string) error {
		err := base.rename(a, b)
		if err == nil {
			once.Do(func() { close(reached); <-release })
		}
		return err
	}
	o, path, key := ownerFixture(t, files)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	a := desired(t, o, "a")
	a.Device.Enabled = false
	result := make(chan error, 1)
	go func() { _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{a}); result <- err }()
	await(t, reached)
	queued := make([]chan configResult, MaxQueuedConfigMutations)
	for i := range queued {
		queued[i] = make(chan configResult, 1)
		o.queue <- configRequest{ctx: context.Background(), migrate: true, result: queued[i]}
	}
	if _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{a}); !errors.Is(err, ErrConfigBusy) {
		t.Fatal("queue overflow accepted", err)
	}
	closed := make(chan struct{})
	go func() { _ = o.Close(); close(closed) }()
	deadline := time.After(3 * time.Second)
	for {
		o.mu.RLock()
		isClosed := o.closed
		o.mu.RUnlock()
		if isClosed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("shutdown not initiated")
		default:
			runtime.Gosched()
		}
	}
	unblock()
	if err := <-result; err != nil {
		t.Fatal("durable active request lost", err)
	}
	await(t, closed)
	for _, ch := range queued {
		if r := <-ch; !errors.Is(r.err, ErrConfigOwnerClosed) {
			t.Fatal("queued request committed after shutdown", r.err)
		}
	}
	loaded, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := loaded.DeviceConfiguration(context.Background(), "a")
	if c.Revision != 2 || c.Device.Enabled {
		t.Fatal("shutdown changed durable result")
	}
}

func TestConfigOwnerV1FixtureMigrationFaithfulAndDeviceBound(t *testing.T) {
	raw := readBytes(t, "testdata/config-v1.json")
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x62}, 32)
	defaults := domain.DefaultNativePolicy()
	defaults.Carriers = 3
	o, err := OpenConfigOwner(path, key, defaults)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	a, b := desired(t, o, "a"), desired(t, o, "b")
	if a.Revision != 1 || b.Revision != 1 || a.Policy != defaults || a.Device.Enabled {
		t.Fatal("v1 metadata defaults/flags lost")
	}
	if !bytes.Equal(raw, readBytes(t, path)) {
		t.Fatal("opening v1 rewrote file")
	}
	if _, err = o.NativeSnapshot(context.Background(), "a"); !errors.Is(err, config.ErrInvalidBusinessConfig) {
		t.Fatal("disabled native eligibility bypassed target validation", err)
	}
	if _, err = o.NativeSnapshot(context.Background(), "b"); !errors.Is(err, ErrNativeIneligible) {
		t.Fatal("legacy device became native", err)
	}
	if err = o.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := loaded.DeviceConfiguration(context.Background(), "a")
	cb, _ := loaded.DeviceConfiguration(context.Background(), "b")
	if !reflect.DeepEqual(ca, a) || !reflect.DeepEqual(cb, b) {
		t.Fatal("migration altered desired records")
	}
	if !bytes.Equal(loaded.kapv1Secret["a"], bytes.Repeat([]byte{0x51}, 32)) || len(loaded.kapv1Secret) != 1 || loaded.credentials["fixture-legacy"].DeviceID != "b" {
		t.Fatal("migration lost credential ownership")
	}
	var disk stateFile
	if err = json.Unmarshal(readBytes(t, path), &disk); err != nil {
		t.Fatal(err)
	}
	if disk.Version != 2 || len(disk.Configurations) != 2 {
		t.Fatal("v2 metadata missing")
	}
	for _, c := range disk.Configurations {
		if c.Revision != 1 || c.Policy != defaults {
			t.Fatal("v2 policy/revision changed")
		}
	}
	disk.Secrets[0].DeviceID = "b"
	tampered, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadState(path, key); err == nil {
		t.Fatal("v2 encryption lost device-bound AAD")
	}
}

func TestConfigOwnerRevisionOverflowAndCorruptMetadata(t *testing.T) {
	o, path, key := ownerFixture(t, defaultStateFiles())
	_ = o.Close()
	s, err := LoadState(path, key)
	if err != nil {
		t.Fatal(err)
	}
	s.stateVersion = 2
	s.revisions["a"] = domain.ConfigRevision(math.MaxUint64)
	if err = s.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	o, err = OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	c := desired(t, o, "a")
	before := readBytes(t, path)
	if _, err = o.Commit(context.Background(), []domain.DeviceConfiguration{c}); err != nil {
		t.Fatal("maximum-revision no-op", err)
	}
	c.Device.Enabled = false
	if _, err = o.Commit(context.Background(), []domain.DeviceConfiguration{c}); !errors.Is(err, ErrRevisionOverflow) {
		t.Fatal("revision wrapped", err)
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("overflow wrote state")
	}
	_ = o.Close()
	var original stateFile
	if err = json.Unmarshal(before, &original); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"version", "missing", "duplicate", "unknown-device", "bad-policy", "orphan-project"} {
		t.Run(kind, func(t *testing.T) {
			var bad stateFile
			if err := json.Unmarshal(before, &bad); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "version":
				bad.Version = 3
			case "missing":
				bad.Configurations = bad.Configurations[:1]
			case "duplicate":
				bad.Configurations = append(bad.Configurations, bad.Configurations[0])
			case "unknown-device":
				bad.Configurations[0].DeviceID = "missing"
			case "bad-policy":
				bad.Configurations[0].Policy.Carriers = 5
			case "orphan-project":
				bad.Projects[0].UserID = "missing"
			}
			data, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadState(path, key); err == nil {
				t.Fatal("corrupt complete state accepted")
			}
		})
	}
}
