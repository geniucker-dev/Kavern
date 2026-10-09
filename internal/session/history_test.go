package session

import (
	"context"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/domain"
	"testing"
)

func TestSessionHistoryGloballyBoundedAcrossReconnectsAndDevices(t *testing.T) {
	m := NewManager()
	ctx := context.Background()
	var previous *attachLockSession
	for i := 0; i < 20000; i++ {
		next := &attachLockSession{id: domain.SessionID(fmt.Sprintf("session-%d", i))}
		if err := m.Attach(ctx, next); err != nil {
			t.Fatal(err)
		}
		if previous != nil && !previous.closed {
			t.Fatal("replaced session retained")
		}
		previous = next
	}
	if len(m.history) != MaxSessionHistory || cap(m.history) != MaxSessionHistory || len(m.current) != 1 || len(m.byID) != 1 {
		t.Fatal("reconnection resources unbounded")
	}
	infos, err := m.ListForDevice(ctx, "device")
	if err != nil || len(infos) != MaxSessionHistory || !infos[len(infos)-1].Current {
		t.Fatal("bounded history current marker invalid")
	}
	if infos[0].ID != "session-18976" {
		t.Fatal("history did not evict oldest")
	}
	infos[0].ID = "mutated"
	if m.history[0].ID == "mutated" {
		t.Fatal("history aliases caller")
	}
	if err := m.Detach(ctx, previous.ID()); err != nil {
		t.Fatal(err)
	}
	if len(m.current) != 0 || len(m.byID) != 0 {
		t.Fatal("current indexes retained")
	}
	// Distinct, detached device IDs must not accumulate map keys in history.
	for i := 0; i < 5000; i++ {
		s := &historyDeviceSession{attachLockSession: attachLockSession{id: domain.SessionID(fmt.Sprintf("other-%d", i))}, device: domain.DeviceID(fmt.Sprintf("device-%d", i))}
		if err := m.Attach(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := m.Detach(ctx, s.ID()); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.history) != MaxSessionHistory || cap(m.history) != MaxSessionHistory || len(m.current) != 0 || len(m.byID) != 0 {
		t.Fatal("distinct-device resources unbounded")
	}
	if old, _ := m.ListForDevice(ctx, "device"); len(old) != 0 {
		t.Fatal("old history retained")
	}
}

type historyDeviceSession struct {
	attachLockSession
	device domain.DeviceID
}

func (s *historyDeviceSession) DeviceID() domain.DeviceID { return s.device }
