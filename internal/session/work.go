package session

import (
	"context"
	"errors"
	"sync"

	"github.com/geniucker-dev/kavern/internal/domain"
)

var ErrWorkCapacity = errors.New("admission work capacity exhausted")
var ErrWorkCleanupPending = errors.New("revoked work cleanup pending")

// WorkSet is a bounded lifecycle registry. Publication selects work under the
// admission guard; cancellation and worker joins are performed outside it.
type WorkSet struct {
	mu   sync.Mutex
	max  int
	live map[*WorkLease]struct{}
}
type WorkLease struct {
	scope   domain.WorkScope
	Context context.Context
	set     *WorkSet
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
	revoked bool
}
type workContextKey struct{}

func NewWorkSet(max int) *WorkSet { return &WorkSet{max: max, live: make(map[*WorkLease]struct{})} }
func (s *WorkSet) Register(parent context.Context, scope domain.WorkScope) (*WorkLease, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.live) >= s.max {
		return nil, ErrWorkCapacity
	}
	ctx, cancel := context.WithCancel(parent)
	lease := &WorkLease{scope: scope, set: s, cancel: cancel, done: make(chan struct{})}
	lease.Context = context.WithValue(ctx, workContextKey{}, lease)
	s.live[lease] = struct{}{}
	return lease, nil
}
func (s *WorkSet) Existing(ctx context.Context, scope domain.WorkScope) *WorkLease {
	lease, _ := ctx.Value(workContextKey{}).(*WorkLease)
	if lease == nil || lease.set != s || lease.scope != scope || ctx.Err() != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.live[lease]; !ok || lease.revoked {
		return nil
	}
	return lease
}
func (l *WorkLease) Finish() {
	l.once.Do(func() { l.cancel(); l.set.mu.Lock(); delete(l.set.live, l); close(l.done); l.set.mu.Unlock() })
}

// Cancel requests revocation; the worker still owns Finish after resource cleanup.
func (l *WorkLease) Cancel()               { l.cancel() }
func (l *WorkLease) Done() <-chan struct{} { return l.done }
func (s *WorkSet) Count() int              { s.mu.Lock(); defer s.mu.Unlock(); return len(s.live) }
func (s *WorkSet) Collect(predicate func(domain.WorkScope) bool) []*WorkLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected []*WorkLease
	for lease := range s.live {
		if predicate(lease.scope) {
			lease.revoked = true
			selected = append(selected, lease)
		}
	}
	return selected
}
func CancelAndJoin(ctx context.Context, leases []*WorkLease) error {
	for _, lease := range leases {
		lease.cancel()
	}
	for _, lease := range leases {
		select {
		case <-lease.Done():
		case <-ctx.Done():
			return ErrWorkCleanupPending
		}
	}
	return nil
}

func (s *WorkSet) RevokedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for l := range s.live {
		if l.revoked {
			n++
		}
	}
	return n
}

func (s *WorkSet) RevokedDeviceCount(id domain.DeviceID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for l := range s.live {
		if l.revoked && l.scope.DeviceID == id {
			n++
		}
	}
	return n
}
