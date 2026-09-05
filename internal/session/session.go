package session

import (
	"context"
	"io"

	"github.com/geniucker-dev/kavern/internal/domain"
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
	// Attach returning an error guarantees that this call did not publish the
	// new session, change current/byID/history, or close the prior session.
	// After successful publication, errors closing the replaced session are ignored.
	Attach(ctx context.Context, session AgentSession) error
	Detach(ctx context.Context, sessionID domain.SessionID) error
	CurrentForDevice(ctx context.Context, deviceID domain.DeviceID) (AgentSession, error)
	ListForDevice(ctx context.Context, deviceID domain.DeviceID) ([]AgentSessionInfo, error)
}
