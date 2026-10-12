package agent_v1

import (
	"context"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type agentSession struct {
	id               domain.SessionID
	deviceID         domain.DeviceID
	syncVersion      int
	lifecycleVersion int
	lifecycle        *ServerLease
	lifecycleGrant   LifecycleFrame
	syncData         *syncSessionData
	expiresAt        time.Time
	now              func() time.Time

	pool *carrier.Pool
	done chan struct{}
	mu   sync.Mutex
}

func newAgentSession(id domain.SessionID, deviceID domain.DeviceID) *agentSession {
	pool, err := carrier.NewPool()
	if err != nil {
		panic(err)
	}
	return &agentSession{id: id, deviceID: deviceID, pool: pool, done: make(chan struct{}), expiresAt: time.Now().Add(time.Hour), now: time.Now}
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
	if s.closed() || (s.lifecycleVersion == 0 && !s.now().Before(s.expiresAt)) {
		_ = s.Close(context.Background())
		return nil, ErrSessionClosed
	}
	if s.lifecycleVersion != 0 {
		lease := s.serverLease()
		if lease == nil {
			return nil, ErrSessionClosed
		}
		if err := lease.Valid(ctx); err != nil {
			return nil, err
		}
	}
	if s.syncVersion != 0 {
		return s.openSyncStream(ctx, req)
	}
	if req.TunnelID == "" {
		return nil, ErrInvalidInput
	}
	if req.Protocol == "" {
		req.Protocol = domain.TunnelProtocolTCP
	}
	if req.Protocol != domain.TunnelProtocolTCP {
		return nil, ErrUnsupportedTunnelProtocol
	}
	lease, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if err := WriteOpenStreamMetadata(lease.Stream, OpenStreamMetadata{
		Version:  ProtocolVersion,
		Type:     OpenStreamMessageType,
		TunnelID: req.TunnelID,
		Protocol: req.Protocol,
	}); err != nil {
		_ = lease.Release()
		return nil, err
	}
	return &leasedAgentStream{Lease: lease}, nil
}

func (s *agentSession) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return s.pool.Close()
}

func (s *agentSession) Done() <-chan struct{} {
	return s.done
}

func (s *agentSession) attachCarrier(c *carrier.Carrier) error {
	if s.closed() {
		return ErrSessionClosed
	}
	return s.pool.Add(c)
}

type leasedAgentStream struct {
	*carrier.Lease
}

func (s *leasedAgentStream) Read(p []byte) (int, error) {
	return s.Stream.Read(p)
}

func (s *leasedAgentStream) Write(p []byte) (int, error) {
	return s.Stream.Write(p)
}

func (s *leasedAgentStream) Close() error {
	return s.Release()
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
	if len(r.byID) >= 4096 {
		return ErrRegistryReserve
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
	if len(entry.usedNonce) >= 4096 {
		return ErrInvalidInput
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

func (s *leasedAgentStream) CloseWrite() error {
	if cw, ok := s.Stream.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return ErrUnsupportedTunnelProtocol
}

func (s *agentSession) serverLease() *ServerLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lifecycle
}

func (s *agentSession) RenewableStreams() bool { return s.lifecycleVersion == LifecycleVersion }

func (s *agentSession) StreamClock() session.Clock {
	if lease := s.serverLease(); lease != nil {
		return lease.clock
	}
	return session.NewClock()
}
