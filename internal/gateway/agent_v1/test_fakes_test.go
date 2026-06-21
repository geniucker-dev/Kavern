package agent_v1

import (
	"context"
	"errors"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/session"
)

var errAttachFailed = errors.New("attach failed")

type failingSessionManager struct {
	session.SessionManager
	failAttach bool
}

func (m *failingSessionManager) Attach(ctx context.Context, sess session.AgentSession) error {
	if m.failAttach {
		return errAttachFailed
	}
	return m.SessionManager.Attach(ctx, sess)
}

func (m *failingSessionManager) CurrentForDevice(ctx context.Context, deviceID domain.DeviceID) (session.AgentSession, error) {
	return m.SessionManager.CurrentForDevice(ctx, deviceID)
}
