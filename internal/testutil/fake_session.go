package testutil

import (
	"bytes"
	"context"
	"sync"

	"github.com/zhuhaoyu/kavern/internal/domain"
	"github.com/zhuhaoyu/kavern/internal/session"
)

type FakeSession struct {
	IDValue       domain.SessionID
	DeviceIDValue domain.DeviceID
	ProtocolValue domain.AgentProtocol

	mu           sync.Mutex
	OpenRequests []domain.StreamOpenRequest
	Closed       bool
	done         chan struct{}
}

func NewFakeSession(id domain.SessionID, deviceID domain.DeviceID) *FakeSession {
	return &FakeSession{
		IDValue:       id,
		DeviceIDValue: deviceID,
		ProtocolValue: domain.AgentProtocolKAPv1,
		done:          make(chan struct{}),
	}
}

func (s *FakeSession) ID() domain.SessionID {
	return s.IDValue
}

func (s *FakeSession) DeviceID() domain.DeviceID {
	return s.DeviceIDValue
}

func (s *FakeSession) Protocol() domain.AgentProtocol {
	return s.ProtocolValue
}

func (s *FakeSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OpenRequests = append(s.OpenRequests, req)
	return &FakeStream{}, nil
}

func (s *FakeSession) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Closed {
		s.Closed = true
		close(s.done)
	}
	return nil
}

func (s *FakeSession) Done() <-chan struct{} {
	return s.done
}

func (s *FakeSession) OpenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.OpenRequests)
}

type FakeStream struct {
	bytes.Buffer
}

func (s *FakeStream) Close() error {
	return nil
}
