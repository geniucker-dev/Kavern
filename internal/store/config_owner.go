package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sort"
	"sync"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

const MaxQueuedConfigMutations = 8

var (
	ErrConfigBusy        = errors.New("configuration mutation queue full")
	ErrConfigOwnerClosed = errors.New("configuration owner closed")
)

type configRequest struct {
	ctx              context.Context
	changes          []domain.DeviceConfiguration
	migrate, recover bool
	result           chan configResult
}
type configResult struct {
	revisions map[domain.DeviceID]domain.ConfigRevision
	err       error
}

// Shutdown's abort check must be synchronous. AfterFunc closes the combined
// Done channel, but its callback can lag the owner's cancellation at a barrier.
type ownerCommitContext struct {
	context.Context
	owner context.Context
}

func (c ownerCommitContext) Err() error {
	if err := c.owner.Err(); err != nil {
		return err
	}
	return c.Context.Err()
}

// ConfigOwner owns the state lock and serializes full-file commits. It is not
// wired into daemon/CLI commands in Slice A, and exposes no mutable live store.
type ConfigOwner struct {
	mu                sync.RWMutex
	current           *MemoryStore
	uncertain, closed bool
	path              string
	key               []byte
	defaults          domain.NativePolicy
	files             stateFiles
	queue             chan configRequest
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	unlock            func() error
	closeErr          error
}

func OpenConfigOwner(path string, key []byte, defaults domain.NativePolicy) (*ConfigOwner, error) {
	return openConfigOwner(path, key, defaults, defaultStateFiles())
}

func openConfigOwner(path string, key []byte, defaults domain.NativePolicy, files stateFiles) (*ConfigOwner, error) {
	unlock, err := LockState(path)
	if err != nil {
		return nil, err
	}
	current, err := LoadStateWithNativePolicy(path, key, defaults)
	if err == nil {
		err = syncStateDirectory(path, files)
	}
	if err != nil {
		_ = unlock()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := &ConfigOwner{current: current, path: path, key: append([]byte(nil), key...), defaults: defaults, files: files, queue: make(chan configRequest, MaxQueuedConfigMutations), ctx: ctx, cancel: cancel, done: make(chan struct{}), unlock: unlock}
	go o.run()
	return o, nil
}

func (o *ConfigOwner) Close() error {
	o.mu.Lock()
	o.closed = true
	o.cancel()
	o.mu.Unlock()
	<-o.done
	return o.closeErr
}

func (o *ConfigOwner) DeviceConfiguration(ctx context.Context, id domain.DeviceID) (domain.DeviceConfiguration, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.DeviceConfiguration{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.DeviceConfiguration{}, ErrCommitUncertain
	}
	return o.current.DeviceConfiguration(ctx, id)
}

func (o *ConfigOwner) NativeSnapshot(ctx context.Context, id domain.DeviceID) (domain.NativeSnapshot, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.NativeSnapshot{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.NativeSnapshot{}, ErrCommitUncertain
	}
	return o.current.NativeSnapshot(ctx, id)
}

// ResolveKAPv1DeviceForAuth exposes the same device-bound credential view as
// the desired snapshot source, without granting access to mutable live state.
func (o *ConfigOwner) ResolveKAPv1DeviceForAuth(ctx context.Context, id domain.DeviceID) (domain.Device, []byte, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		return domain.Device{}, nil, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return domain.Device{}, nil, ErrCommitUncertain
	}
	return o.current.ResolveKAPv1DeviceForAuth(ctx, id)
}

// Commit atomically replaces the listed devices' complete desired tunnel sets.
// Once accepted, it waits for the definitive persistence result even if ctx is
// canceled, so a durable rename/fsync cannot be misreported as an abort.
func (o *ConfigOwner) Commit(ctx context.Context, changes []domain.DeviceConfiguration) (map[domain.DeviceID]domain.ConfigRevision, error) {
	// Bound retained request payload before copying caller-owned slices.
	bytes := 0
	if len(changes) == 0 || len(changes) > config.MaxJSONBytes/128 {
		return nil, config.ErrInvalidBusinessConfig
	}
	for _, c := range changes {
		if len(c.Tunnels) > config.MaxJSONBytes/16 {
			return nil, config.ErrInvalidBusinessConfig
		}
		bytes += len(c.Device.ID) + len(c.Device.ProjectID) + len(c.Device.Name)
		for _, t := range c.Tunnels {
			bytes += len(t.ID) + len(t.DeviceID) + len(t.Protocol) + len(t.Listener) + len(t.TargetAddr)
			if bytes > config.MaxJSONBytes {
				return nil, config.ErrInvalidBusinessConfig
			}
		}
		if bytes > config.MaxJSONBytes {
			return nil, config.ErrInvalidBusinessConfig
		}
	}
	data, err := json.Marshal(changes)
	if err != nil || len(data) > config.MaxJSONBytes {
		return nil, config.ErrInvalidBusinessConfig
	}
	owned := append([]domain.DeviceConfiguration(nil), changes...)
	for i := range owned {
		owned[i].Tunnels = append([]domain.Tunnel(nil), changes[i].Tunnels...)
	}
	result := o.submit(configRequest{ctx: ctx, changes: owned, result: make(chan configResult, 1)})
	return result.revisions, result.err
}

// Migrate persists v2 metadata without trimming or synchronizing old targets.
func (o *ConfigOwner) Migrate(ctx context.Context) error {
	return o.submit(configRequest{ctx: ctx, migrate: true, result: make(chan configResult, 1)}).err
}

// Recover validates the actual file and confirms directory durability before
// replacing the uncertain view and admitting another mutation.
func (o *ConfigOwner) Recover(ctx context.Context) error {
	return o.submit(configRequest{ctx: ctx, recover: true, result: make(chan configResult, 1)}).err
}

func (o *ConfigOwner) submit(req configRequest) configResult {
	if err := req.ctx.Err(); err != nil {
		return configResult{err: err}
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return configResult{err: ErrConfigOwnerClosed}
	}
	if o.uncertain && !req.recover {
		o.mu.Unlock()
		return configResult{err: ErrCommitUncertain}
	}
	select {
	case o.queue <- req:
		o.mu.Unlock()
		return <-req.result
	default:
		o.mu.Unlock()
		return configResult{err: ErrConfigBusy}
	}
}

func (o *ConfigOwner) run() {
	defer func() {
		for {
			select {
			case req := <-o.queue:
				req.result <- configResult{err: ErrConfigOwnerClosed}
			default:
				o.closeErr = o.unlock()
				clear(o.key)
				close(o.done)
				return
			}
		}
	}()
	for {
		if o.ctx.Err() != nil {
			return
		}
		select {
		case <-o.ctx.Done():
			return
		case req := <-o.queue:
			ctx, cancel := context.WithCancel(req.ctx)
			stop := context.AfterFunc(o.ctx, cancel)
			if o.ctx.Err() != nil {
				cancel()
			}
			result := o.process(ownerCommitContext{Context: ctx, owner: o.ctx}, req)
			stop()
			cancel()
			req.result <- result
		}
	}
}

func (o *ConfigOwner) process(ctx context.Context, req configRequest) configResult {
	if err := ctx.Err(); err != nil {
		return configResult{err: err}
	}
	o.mu.RLock()
	uncertain, current := o.uncertain, o.current
	o.mu.RUnlock()
	if req.recover {
		if !uncertain {
			return configResult{}
		}
		loaded, err := LoadStateWithNativePolicy(o.path, o.key, o.defaults)
		if err == nil {
			err = syncStateDirectory(o.path, o.files)
		}
		if err != nil {
			return configResult{err: errors.Join(ErrCommitUncertain, err)}
		}
		o.mu.Lock()
		o.current, o.uncertain = loaded, false
		o.mu.Unlock()
		return configResult{}
	}
	if uncertain {
		return configResult{err: ErrCommitUncertain}
	}
	// Validate the whole request before inserting into the candidate map: an ID
	// absent from current state can still collide across requested devices.
	requestedTunnels := make(map[domain.TunnelID]struct{})
	for _, c := range req.changes {
		for _, tunnel := range c.Tunnels {
			if _, exists := requestedTunnels[tunnel.ID]; exists {
				return configResult{err: config.ErrInvalidBusinessConfig}
			}
			requestedTunnels[tunnel.ID] = struct{}{}
		}
	}
	current.mu.RLock()
	next := current.cloneLocked()
	current.mu.RUnlock()
	revisions := make(map[domain.DeviceID]domain.ConfigRevision, len(req.changes))
	changed := false
	seen := make(map[domain.DeviceID]bool, len(req.changes))
	for _, c := range req.changes {
		id := c.Device.ID
		old, err := next.configurationLocked(id)
		if err != nil {
			return configResult{err: err}
		}
		if seen[id] {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		seen[id] = true
		if c.Revision != old.Revision {
			return configResult{err: ErrRevisionConflict}
		}
		if c.Device.ProjectID != old.Device.ProjectID {
			return configResult{err: ErrTunnelOwnership}
		}
		_, native := next.kapv1Secret[id]
		if err := config.ValidateDeviceConfiguration(c, native); err != nil {
			return configResult{err: err}
		}
		sort.Slice(c.Tunnels, func(i, j int) bool { return c.Tunnels[i].ID < c.Tunnels[j].ID })
		same := c.Device == old.Device && c.Policy == old.Policy && len(c.Tunnels) == len(old.Tunnels) && (len(c.Tunnels) == 0 || reflect.DeepEqual(c.Tunnels, old.Tunnels))
		if !same {
			if c.Revision == domain.ConfigRevision(math.MaxUint64) {
				return configResult{err: ErrRevisionOverflow}
			}
			for _, t := range c.Tunnels {
				if oldTunnel, ok := current.tunnels[t.ID]; ok && oldTunnel.DeviceID != id {
					return configResult{err: ErrTunnelOwnership}
				}
			}
			for tunnelID, t := range next.tunnels {
				if t.DeviceID == id {
					delete(next.tunnels, tunnelID)
				}
			}
			for _, t := range c.Tunnels {
				next.tunnels[t.ID] = t
			}
			next.devices[id], next.policies[id], next.revisions[id] = c.Device, c.Policy, c.Revision+1
			changed = true
		}
		revisions[id] = next.revisions[id]
	}
	if !changed && (!req.migrate || next.stateVersion == 2) {
		return configResult{revisions: revisions}
	}
	next.listeners = make(map[domain.ListenerRef]domain.TunnelID, len(next.tunnels))
	for id, tunnel := range next.tunnels {
		if _, ok := next.listeners[tunnel.Listener]; ok {
			return configResult{err: ErrListenerConflict}
		}
		next.listeners[tunnel.Listener] = id
	}
	if err := next.validateState(!req.migrate); err != nil {
		return configResult{err: err}
	}
	next.stateVersion = 2
	data, err := next.encodeState(o.key)
	if err == nil {
		err = writeState(ctx, o.path, data, o.files)
	}
	if err != nil {
		if errors.Is(err, ErrCommitUncertain) {
			o.mu.Lock()
			o.uncertain = true
			o.mu.Unlock()
		}
		return configResult{err: err}
	}
	// Durability is confirmed. Do not turn cancellation/shutdown into rollback.
	o.mu.Lock()
	o.current = next
	o.mu.Unlock()
	return configResult{revisions: revisions}
}
