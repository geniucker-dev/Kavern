package agent_v1

import (
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

const MaxSyncStagingBytes = 16 << 20
const SyncTransferTimeout = 10 * time.Second
const SyncWriteTimeout = 5 * time.Second

// One budget is shared by all sync peers in a process. It measures retained
// transfer payload, not object, TLS, socket or total RSS overhead.
type SyncStagingBudget struct {
	mu   sync.Mutex
	used uint32
}

var processSyncBudget = &SyncStagingBudget{}

func (b *SyncStagingBudget) reserve(n uint32) (func(), error) {
	if n == 0 || n > MaxSyncTransferBytes {
		return nil, ErrSyncCapacity
	}
	b.mu.Lock()
	if b.used > MaxSyncStagingBytes-n {
		b.mu.Unlock()
		return nil, ErrSyncCapacity
	}
	b.used += n
	b.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { b.mu.Lock(); b.used -= n; b.mu.Unlock() }) }, nil
}
func (b *SyncStagingBudget) Used() uint32 { b.mu.Lock(); defer b.mu.Unlock(); return b.used }

type syncStage struct {
	tuple           syncTuple
	count           uint16
	total, received uint32
	deadline        time.Time
	snapshot        domain.NativeSnapshot
	release         func()
}

// ConfigReceiver owns only session-local protocol application facts. It is not
// wired into AgentDataLoop or readiness/routing in this checkpoint.
type ConfigReceiver struct {
	mu           sync.Mutex
	auth         SyncAuthResult
	budget       *SyncStagingBudget
	stage        *syncStage
	applied      domain.NativeSnapshot
	lastTransfer domain.ConfigRevision
	ackDeadline  time.Time
	closed       bool
	running      bool
	now          func() time.Time
	timeout      time.Duration
}

func NewConfigReceiver(auth SyncAuthResult, budget *SyncStagingBudget) (*ConfigReceiver, error) {
	if auth.ConfigSyncVersion != ConfigSyncVersion || auth.ProtocolVersion != ProtocolVersion || !config.ValidID(string(auth.DeviceID)) || validateToken(string(auth.SessionID)) != nil {
		return nil, ErrSyncSchema
	}
	if budget == nil {
		budget = processSyncBudget
	}
	return &ConfigReceiver{auth: auth, budget: budget, now: time.Now, timeout: SyncTransferTimeout}, nil
}
func (r *ConfigReceiver) Close() { r.mu.Lock(); defer r.mu.Unlock(); r.closeLocked() }
func (r *ConfigReceiver) closeLocked() {
	if r.stage != nil {
		r.stage.release()
		r.stage = nil
	}
	r.applied = domain.NativeSnapshot{}
	r.ackDeadline = time.Time{}
	r.closed = true
}
func (r *ConfigReceiver) Snapshot() (domain.NativeSnapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.applied.Revision == 0 {
		return domain.NativeSnapshot{}, false
	}
	s := r.applied
	s.Tunnels = append([]domain.NativeTunnel(nil), s.Tunnels...)
	return s, true
}
func (r *ConfigReceiver) deadline() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stage != nil {
		return r.stage.deadline
	}
	return r.ackDeadline
}
func (r *ConfigReceiver) ackSent() { r.mu.Lock(); r.ackDeadline = time.Time{}; r.mu.Unlock() }

func minimumTransferBytes(begin syncFrame, actual int) (uint64, error) {
	end := scopedFrame("config_end", begin.tuple())
	end.Count = begin.Count
	end.TotalBytes = begin.TotalBytes
	endBytes, err := encodeSyncPayload(end)
	if err != nil {
		return 0, err
	}
	entry := scopedFrame("config_tunnel", begin.tuple())
	index := uint16(0)
	entry.Index = &index
	entry.Tunnel = &syncTunnel{ID: "a", Protocol: domain.TunnelProtocolTCP, TargetAddr: "a:1"}
	entryBytes, err := encodeSyncPayload(entry)
	if err != nil {
		return 0, err
	}
	return uint64(actual+len(endBytes)) + uint64(*begin.Count)*uint64(len(entryBytes)), nil
}
func (r *ConfigReceiver) accept(f syncFrame, size int) (ack *syncFrame, err error) {
	return r.acceptAt(f, size, time.Time{})
}
func (r *ConfigReceiver) acceptAt(f syncFrame, size int, started time.Time) (ack *syncFrame, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		if err != nil {
			r.closeLocked()
		}
	}()
	if r.closed {
		return nil, ErrSessionClosed
	}
	if f.DeviceID != r.auth.DeviceID || f.SessionID != r.auth.SessionID {
		return nil, ErrSyncStale
	}
	if size <= 0 || size > MaxControlFrameBytes {
		return nil, ErrSyncTransfer
	}
	now := r.now()
	if (r.stage != nil && !now.Before(r.stage.deadline)) || (!r.ackDeadline.IsZero() && !now.Before(r.ackDeadline)) {
		return nil, ErrSyncDeadline
	}
	if f.Type == "config_begin" {
		if r.stage != nil || !r.ackDeadline.IsZero() || f.tuple().TransferID <= r.lastTransfer || f.tuple().Revision <= r.applied.Revision {
			return nil, ErrSyncStale
		}
		minimum, e := minimumTransferBytes(f, size)
		if e != nil || minimum > uint64(*f.TotalBytes) {
			return nil, ErrSyncTransfer
		}
		if started.IsZero() {
			started = now
		}
		deadline := started.Add(r.timeout)
		if !now.Before(deadline) {
			return nil, ErrSyncDeadline
		}
		release, e := r.budget.reserve(*f.TotalBytes)
		if e != nil {
			return nil, e
		}
		r.stage = &syncStage{tuple: f.tuple(), count: *f.Count, total: *f.TotalBytes, received: uint32(size), deadline: deadline, snapshot: domain.NativeSnapshot{DeviceID: f.DeviceID, Revision: *f.Revision, Policy: f.Policy.domain(), Tunnels: make([]domain.NativeTunnel, 0, int(*f.Count))}, release: release}
		return nil, nil
	}
	stage := r.stage
	if stage == nil || f.tuple() != stage.tuple {
		return nil, ErrSyncStale
	}
	if uint64(stage.received)+uint64(size) > uint64(stage.total) {
		return nil, ErrSyncTransfer
	}
	stage.received += uint32(size)
	switch f.Type {
	case "config_tunnel":
		if len(stage.snapshot.Tunnels) >= int(stage.count) || int(*f.Index) != len(stage.snapshot.Tunnels) {
			return nil, ErrSyncTransfer
		}
		if len(stage.snapshot.Tunnels) > 0 && stage.snapshot.Tunnels[len(stage.snapshot.Tunnels)-1].ID >= f.Tunnel.ID {
			return nil, ErrSyncTransfer
		}
		stage.snapshot.Tunnels = append(stage.snapshot.Tunnels, domain.NativeTunnel{ID: f.Tunnel.ID, Protocol: f.Tunnel.Protocol, TargetAddr: f.Tunnel.TargetAddr})
		return nil, nil
	case "config_end":
		if *f.Count != stage.count || *f.TotalBytes != stage.total || len(stage.snapshot.Tunnels) != int(stage.count) || stage.received != stage.total || config.ValidateNativeSnapshot(stage.snapshot) != nil {
			return nil, ErrSyncTransfer
		}
		r.applied = stage.snapshot
		r.lastTransfer = stage.tuple.TransferID
		r.ackDeadline = stage.deadline
		r.stage = nil
		stage.release()
		result := scopedFrame("config_ack", stage.tuple)
		return &result, nil
	default:
		return nil, ErrSyncTransfer
	}
}
