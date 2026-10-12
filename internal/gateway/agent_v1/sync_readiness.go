package agent_v1

import (
	"context"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

const syncReadyTimeout = 2 * time.Second

type syncSessionData struct {
	mu                      sync.Mutex
	service                 *AuthService
	auth                    SyncAuthResult
	source                  NativeSnapshotSource
	desired, applied, ready syncTuple
	snapshot                domain.NativeSnapshot
	changed                 chan struct{}
}

func (s *agentSession) syncController() *syncSessionData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncData
}
func (d *syncSessionData) notifyLocked() { close(d.changed); d.changed = make(chan struct{}) }
func (d *syncSessionData) install(tuple syncTuple, snapshot domain.NativeSnapshot) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.desired = tuple
	d.snapshot = snapshot
	d.ready = syncTuple{}
	d.notifyLocked()
}
func (d *syncSessionData) ack(tuple syncTuple) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if tuple != d.desired {
		return ErrSyncStale
	}
	d.applied = tuple
	d.ready = syncTuple{}
	d.notifyLocked()
	return nil
}

func (d *syncSessionData) current(ctx context.Context, tuple syncTuple, requireReady bool) (domain.NativeSnapshot, error) {
	latest, err := d.source.NativeSnapshot(ctx, d.auth.DeviceID)
	if err != nil {
		return domain.NativeSnapshot{}, err
	}
	var snapshot domain.NativeSnapshot
	err = d.service.withSyncSession(ctx, d.auth, func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if tuple != d.desired || tuple != d.applied || !sameSnapshot(latest, d.snapshot) {
			return ErrSyncStale
		}
		if requireReady && d.ready != tuple {
			return ErrSyncNotReady
		}
		snapshot = d.snapshot
		return nil
	})
	return snapshot, err
}
func (s *AuthService) syncDataFor(ctx context.Context, auth SyncAuthResult) (*agentSession, *syncSessionData, error) {
	var session *agentSession
	var data *syncSessionData
	err := s.withSyncSession(ctx, auth, func() error {
		entry, ok := s.registry.lookup(auth.SessionID)
		if !ok {
			return ErrSessionNotFound
		}
		session = entry.session
		data = session.syncController()
		if data == nil {
			return ErrSyncNotReady
		}
		return nil
	})
	return session, data, err
}
func (s *AuthService) waitSyncApplication(ctx context.Context, auth SyncAuthResult, tuple syncTuple) (*agentSession, *syncSessionData, domain.NativeSnapshot, error) {
	wait, cancel := context.WithTimeout(ctx, syncReadyTimeout)
	defer cancel()
	for {
		session, data, err := s.syncDataFor(wait, auth)
		if err != nil {
			return nil, nil, domain.NativeSnapshot{}, err
		}
		data.mu.Lock()
		desired, applied, changed := data.desired, data.applied, data.changed
		data.mu.Unlock()
		if desired != tuple {
			return nil, nil, domain.NativeSnapshot{}, ErrSyncStale
		}
		if applied == tuple {
			snapshot, err := data.current(wait, tuple, false)
			return session, data, snapshot, err
		}
		select {
		case <-wait.Done():
			return nil, nil, domain.NativeSnapshot{}, wait.Err()
		case <-session.Done():
			return nil, nil, domain.NativeSnapshot{}, ErrSessionClosed
		case <-changed:
		}
	}
}
func (s *AuthService) markSyncReady(ctx context.Context, auth SyncAuthResult, tuple syncTuple, count int) error {
	session, data, snapshot, err := s.waitSyncApplication(ctx, auth, tuple)
	if err != nil {
		return err
	}
	if count != snapshot.Policy.Carriers {
		return ErrSyncNotReady
	}
	wait, cancel := context.WithTimeout(ctx, syncReadyTimeout)
	defer cancel()
	if err = session.pool.WaitReady(wait, count); err != nil {
		return err
	}
	if _, err = data.current(wait, tuple, false); err != nil {
		return err
	}
	return s.withSyncSession(wait, auth, func() error {
		data.mu.Lock()
		defer data.mu.Unlock()
		if data.desired != tuple || data.applied != tuple || session.pool.LiveCount() != count {
			return ErrSyncNotReady
		}
		data.ready = tuple
		data.notifyLocked()
		return nil
	})
}

type syncReadyRequest struct {
	ctx    context.Context
	tuple  syncTuple
	count  int
	result chan error
}

func (r *ConfigReceiver) currentTupleLocked() syncTuple {
	return syncTuple{r.auth.DeviceID, r.auth.SessionID, r.applied.Revision, r.lastTransfer}
}
func (r *ConfigReceiver) RequestReady(ctx context.Context) error {
	r.mu.Lock()
	if r.closed || r.applied.Revision == 0 || r.stage != nil || !r.ackDeadline.IsZero() {
		r.mu.Unlock()
		return ErrSyncNotReady
	}
	tuple := r.currentTupleLocked()
	count := r.liveCarriersLocked()
	required := r.applied.Policy.Carriers
	r.mu.Unlock()
	if count != required {
		return ErrSyncNotReady
	}
	wait, cancel := context.WithTimeout(ctx, syncReadyTimeout)
	defer cancel()
	req := syncReadyRequest{ctx: wait, tuple: tuple, count: count, result: make(chan error, 1)}
	select {
	case r.readyRequests <- req:
	case <-wait.Done():
		return wait.Err()
	}
	select {
	case err := <-req.result:
		return err
	case <-wait.Done():
		return wait.Err()
	}
}
func (r *ConfigReceiver) acceptReady(tuple syncTuple, count int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.stage != nil || !r.ackDeadline.IsZero() || tuple != r.currentTupleLocked() || count != r.applied.Policy.Carriers || r.liveCarriersLocked() != count {
		return ErrSyncStale
	}
	r.ready = tuple
	return nil
}
func (r *ConfigReceiver) liveCarriersLocked() int {
	count := 0
	for c := range r.carriers {
		if !c.carrier.Closed() {
			count++
		}
	}
	return count
}
