package legacy_npc

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type LegacyNpcSession struct {
	id       domain.SessionID
	deviceID domain.DeviceID
	main     net.Conn

	mu    sync.Mutex
	chans map[net.Conn]struct{}
	done  chan struct{}
}

func newSession(id domain.SessionID, deviceID domain.DeviceID, main net.Conn) *LegacyNpcSession {
	return &LegacyNpcSession{
		id:       id,
		deviceID: deviceID,
		main:     main,
		chans:    make(map[net.Conn]struct{}),
		done:     make(chan struct{}),
	}
}

func (s *LegacyNpcSession) ID() domain.SessionID {
	return s.id
}

func (s *LegacyNpcSession) DeviceID() domain.DeviceID {
	return s.deviceID
}

func (s *LegacyNpcSession) Protocol() domain.AgentProtocol {
	return domain.AgentProtocolLegacyNPC
}

func (s *LegacyNpcSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrLegacyDataNotImplemented
}

func (s *LegacyNpcSession) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil
	default:
		close(s.done)
	}
	main := s.main
	chans := make([]net.Conn, 0, len(s.chans))
	for ch := range s.chans {
		chans = append(chans, ch)
	}
	s.chans = make(map[net.Conn]struct{})
	s.mu.Unlock()

	if main != nil {
		_ = main.Close()
	}
	for _, ch := range chans {
		_ = ch.Close()
	}
	return nil
}

func (s *LegacyNpcSession) Done() <-chan struct{} {
	return s.done
}

func (s *LegacyNpcSession) addChan(conn net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return ErrNoCurrentMainSession
	default:
	}
	s.chans[conn] = struct{}{}
	return nil
}

func (s *LegacyNpcSession) removeChan(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.chans, conn)
}

func (s *LegacyNpcSession) waitMainEOF() {
	var buf [1]byte
	for {
		if _, err := s.main.Read(buf[:]); err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}

var _ session.AgentSession = (*LegacyNpcSession)(nil)
