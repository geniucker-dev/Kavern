package agent_v1

import (
	"context"
	"errors"
	"sync"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/session"
)

type agentSession struct {
	id       domain.SessionID
	deviceID domain.DeviceID

	done chan struct{}
	mu   sync.Mutex
}

func newAgentSession(id domain.SessionID, deviceID domain.DeviceID) *agentSession {
	return &agentSession{id: id, deviceID: deviceID, done: make(chan struct{})}
}

func (s *agentSession) ID() domain.SessionID {
	return s.id
}

func (s *agentSession) DeviceID() domain.DeviceID {
	return s.deviceID
}

func (s *agentSession) Protocol() domain.AgentProtocol {
	return domain.AgentProtocolKAPv1
}

func (s *agentSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("agent_v1 streams are not implemented in Gate 2")
}

func (s *agentSession) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

func (s *agentSession) Done() <-chan struct{} {
	return s.done
}

func (s *agentSession) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

type registryEntry struct {
	session   *agentSession
	deviceID  domain.DeviceID
	active    bool
	usedNonce map[string]struct{}
}

type sessionRegistry struct {
	mu          sync.Mutex
	byID        map[domain.SessionID]*registryEntry
	byDevice    map[domain.DeviceID]domain.SessionID
	failReserve bool
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		byID:     make(map[domain.SessionID]*registryEntry),
		byDevice: make(map[domain.DeviceID]domain.SessionID),
	}
}

func (r *sessionRegistry) reserve(id domain.SessionID, sess *agentSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failReserve {
		return ErrRegistryReserve
	}
	if _, ok := r.byID[id]; ok {
		return ErrSessionIDCollision
	}
	r.byID[id] = &registryEntry{session: sess, deviceID: sess.DeviceID(), usedNonce: make(map[string]struct{})}
	return nil
}

func (r *sessionRegistry) activate(id domain.SessionID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byID[id]
	if !ok {
		return ErrInternalInvariant
	}
	oldID, hadOld := r.byDevice[entry.deviceID]
	if hadOld && oldID != id {
		delete(r.byID, oldID)
	}
	r.byDevice[entry.deviceID] = id
	entry.active = true
	return nil
}

func (r *sessionRegistry) remove(id domain.SessionID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byID[id]
	if !ok {
		return
	}
	if r.byDevice[entry.deviceID] == id {
		delete(r.byDevice, entry.deviceID)
	}
	delete(r.byID, id)
}

func (r *sessionRegistry) lookup(id domain.SessionID) (*registryEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byID[id]
	if !ok || !entry.active {
		return nil, false
	}
	return entry, true
}

func (r *sessionRegistry) markNonceUsed(id domain.SessionID, nonce string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byID[id]
	if !ok || !entry.active {
		return ErrSessionNotFound
	}
	if _, ok := entry.usedNonce[nonce]; ok {
		return ErrCarrierNonceReplay
	}
	entry.usedNonce[nonce] = struct{}{}
	return nil
}

func (r *sessionRegistry) nonceUsed(id domain.SessionID, nonce string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byID[id]
	if !ok || !entry.active {
		return false
	}
	_, ok = entry.usedNonce[nonce]
	return ok
}
