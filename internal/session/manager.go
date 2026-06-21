package session

import (
	"context"
	"errors"
	"sync"

	"github.com/zhuhaoyu/kavern/internal/domain"
)

var (
	ErrNoCurrentSession   = errors.New("no current session for device")
	ErrDuplicateSessionID = errors.New("duplicate active session id")
)

type Manager struct {
	mu      sync.RWMutex
	current map[domain.DeviceID]AgentSession
	byID    map[domain.SessionID]AgentSession
	history map[domain.DeviceID][]AgentSessionInfo
}

func NewManager() *Manager {
	return &Manager{
		current: make(map[domain.DeviceID]AgentSession),
		byID:    make(map[domain.SessionID]AgentSession),
		history: make(map[domain.DeviceID][]AgentSessionInfo),
	}
}

func (m *Manager) Attach(ctx context.Context, next AgentSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var replaced AgentSession
	m.mu.Lock()
	if existing := m.byID[next.ID()]; existing != nil {
		m.mu.Unlock()
		return ErrDuplicateSessionID
	}
	if old := m.current[next.DeviceID()]; old != nil && old.ID() != next.ID() {
		replaced = old
		delete(m.byID, old.ID())
	}
	m.current[next.DeviceID()] = next
	m.byID[next.ID()] = next
	m.history[next.DeviceID()] = append(m.history[next.DeviceID()], AgentSessionInfo{
		ID: next.ID(), DeviceID: next.DeviceID(), Protocol: next.Protocol(), Current: true,
	})
	m.mu.Unlock()

	if replaced != nil {
		return replaced.Close(ctx)
	}
	return nil
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

	infos := append([]AgentSessionInfo(nil), m.history[deviceID]...)
	var currentID domain.SessionID
	if current := m.current[deviceID]; current != nil {
		currentID = current.ID()
	}
	for i := range infos {
		infos[i].Current = currentID != "" && infos[i].ID == currentID
	}
	return infos, nil
}
