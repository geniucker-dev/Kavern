package mux

import (
	"context"
	"net"

	"github.com/xtaci/smux"
)

type SmuxBackend struct{}

func NewSmuxBackend() SmuxBackend {
	return SmuxBackend{}
}

func (SmuxBackend) Name() string {
	return "smux"
}

func (SmuxBackend) Client(conn net.Conn, cfg Config) (Session, error) {
	session, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {
		return nil, err
	}
	return smuxSession{session: session}, nil
}

func (SmuxBackend) Server(conn net.Conn, cfg Config) (Session, error) {
	session, err := smux.Server(conn, smux.DefaultConfig())
	if err != nil {
		return nil, err
	}
	return smuxSession{session: session}, nil
}

type smuxSession struct {
	session *smux.Session
}

func (s smuxSession) OpenStream(ctx context.Context) (Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.session.OpenStream()
}

func (s smuxSession) AcceptStream(ctx context.Context) (Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.session.AcceptStream()
}

func (s smuxSession) Close() error {
	return s.session.Close()
}
