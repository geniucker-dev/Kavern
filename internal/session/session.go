package session

import (
	"context"
	"io"

	"github.com/zhuhaoyu/kavern/internal/domain"
)

type AgentStream interface {
	io.Reader
	io.Writer
	Close() error
}

type AgentSession interface {
	ID() domain.SessionID
	DeviceID() domain.DeviceID
	Protocol() domain.AgentProtocol
	OpenStream(ctx context.Context, req domain.StreamOpenRequest) (AgentStream, error)
	Close(ctx context.Context) error
	Done() <-chan struct{}
}

type AgentSessionInfo struct {
	ID       domain.SessionID
	DeviceID domain.DeviceID
	Protocol domain.AgentProtocol
	Current  bool
}

type SessionManager interface {
	Attach(ctx context.Context, session AgentSession) error
	Detach(ctx context.Context, sessionID domain.SessionID) error
	CurrentForDevice(ctx context.Context, deviceID domain.DeviceID) (AgentSession, error)
	ListForDevice(ctx context.Context, deviceID domain.DeviceID) ([]AgentSessionInfo, error)
}
