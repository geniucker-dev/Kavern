package session

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

type attachCheckContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *attachCheckContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

type attachLockSession struct {
	AgentSession
	id     domain.SessionID
	closed bool
}

func (s *attachLockSession) ID() domain.SessionID           { return s.id }
func (s *attachLockSession) DeviceID() domain.DeviceID      { return "device" }
func (s *attachLockSession) Protocol() domain.AgentProtocol { return domain.AgentProtocolLegacyNPC }
func (s *attachLockSession) Close(context.Context) error    { s.closed = true; return nil }

func TestManagerAttachCancelWhileWaitingForLock(t *testing.T) {
	m := NewManager()
	prior := &attachLockSession{id: "prior"}
	next := &attachLockSession{id: "next"}
	if err := m.Attach(context.Background(), prior); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &attachCheckContext{Context: base, checked: make(chan struct{})}
	m.mu.Lock()
	history := append([]AgentSessionInfo(nil), m.history[prior.DeviceID()]...)
	done := make(chan error, 1)
	go func() { done <- m.Attach(ctx, next) }()
	select {
	case <-ctx.checked:
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("initial cancellation check did not run")
	}
	cancel()
	m.mu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Attach = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Attach did not finish")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current[prior.DeviceID()] != prior || m.byID[prior.ID()] != prior || m.byID[next.ID()] != nil ||
		len(m.byID) != 1 || len(m.current) != 1 || !reflect.DeepEqual(history, m.history[prior.DeviceID()]) ||
		prior.closed || next.closed {
		t.Fatal("canceled Attach mutated publication state or closed a session")
	}
}
