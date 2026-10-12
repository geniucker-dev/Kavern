package session

import (
	"context"
	"errors"
	"sync"

	"github.com/geniucker-dev/kavern/internal/domain"
)

var (
	ErrNoCurrentSession   = errors.New("no current session for device")
	ErrDuplicateSessionID = errors.New("duplicate active session id")
)

// MaxSessionHistory bounds process-wide observability records. Routing never
// depends on history, which may evict records for still-current sessions.
const MaxSessionHistory = 1024

type Manager struct {
	mu      sync.RWMutex
	current map[domain.DeviceID]AgentSession
	byID    map[domain.SessionID]AgentSession
	history []AgentSessionInfo
}

func NewManager() *Manager {
	return &Manager{
		current: make(map[domain.DeviceID]AgentSession),
		byID:    make(map[domain.SessionID]AgentSession),
		history: make([]AgentSessionInfo, 0, MaxSessionHistory),
	}
}

func (m *Manager) Attach(ctx context.Context, next AgentSession) error {
	replaced, err := m.Publish(ctx, next)
	if err != nil {
		return err
	}
	if replaced != nil {
		_ = replaced.Close(context.Background())
	}
	return nil
}

// Publish performs only the in-memory attachment. A caller composing desired-
// state admission must close the returned predecessor outside its guard.
func (m *Manager) Publish(ctx context.Context, next AgentSession) (AgentSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var replaced AgentSession
	m.mu.Lock()
	// Cancellation linearizes here, before any publication state is accessed.
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if existing := m.byID[next.ID()]; existing != nil {
		m.mu.Unlock()
		return nil, ErrDuplicateSessionID
	}
	if old := m.current[next.DeviceID()]; old != nil && old.ID() != next.ID() {
		replaced = old
		delete(m.byID, old.ID())
	}
	m.current[next.DeviceID()] = next
	m.byID[next.ID()] = next
	info := AgentSessionInfo{ID: next.ID(), DeviceID: next.DeviceID(), Protocol: next.Protocol()}
	if len(m.history) == MaxSessionHistory {
		copy(m.history, m.history[1:])
		m.history[len(m.history)-1] = info
	} else {
		m.history = append(m.history, info)
	}
	m.mu.Unlock()

	return replaced, nil
}

func (m *Manager) Detach(ctx context.Context, sessionID domain.SessionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.byID[sessionID]
	if !ok {
		return nil
	}
	delete(m.byID, sessionID)
	if m.current[current.DeviceID()] != nil && m.current[current.DeviceID()].ID() == sessionID {
		delete(m.current, current.DeviceID())
	}
	return nil
}

func (m *Manager) CurrentForDevice(ctx context.Context, deviceID domain.DeviceID) (AgentSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	current := m.current[deviceID]
	if current == nil {
		return nil, ErrNoCurrentSession
	}
	return current, nil
}

func (m *Manager) ListForDevice(ctx context.Context, deviceID domain.DeviceID) ([]AgentSessionInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var infos []AgentSessionInfo
	for _, info := range m.history {
		if info.DeviceID == deviceID {
			infos = append(infos, info)
		}
	}
	var currentID domain.SessionID
	if current := m.current[deviceID]; current != nil {
		currentID = current.ID()
	}
	for i := range infos {
		infos[i].Current = currentID != "" && infos[i].ID == currentID
	}
	return infos, nil
}
