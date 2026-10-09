package mux

import (
	"context"
	"errors"
	"io"
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
	settings, limit, err := smuxConfig(cfg)
	if err != nil {
		return nil, err
	}
	session, err := smux.Client(conn, settings)
	if err != nil {
		return nil, err
	}
	return smuxSession{session: session, receiveLimit: limit}, nil
}

func (SmuxBackend) Server(conn net.Conn, cfg Config) (Session, error) {
	settings, limit, err := smuxConfig(cfg)
	if err != nil {
		return nil, err
	}
	session, err := smux.Server(conn, settings)
	if err != nil {
		return nil, err
	}
	return smuxSession{session: session, receiveLimit: limit}, nil
}

type smuxSession struct {
	session      *smux.Session
	receiveLimit int
}

func (s smuxSession) OpenStream(ctx context.Context) (Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.operation(ctx, s.session.OpenStream)
}

func (s smuxSession) AcceptStream(ctx context.Context) (Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.operation(ctx, s.session.AcceptStream)
}

func (s smuxSession) Close() error {
	err := s.session.Close()
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s smuxSession) ReceiveBufferLimit() int { return s.receiveLimit }
func smuxConfig(cfg Config) (*smux.Config, int, error) {
	c := smux.DefaultConfig()
	if cfg.MaxFrameSize != 0 {
		c.MaxFrameSize = cfg.MaxFrameSize
	}
	if cfg.MaxReceiveBuffer != 0 {
		c.MaxReceiveBuffer = cfg.MaxReceiveBuffer - 65535
	}
	if cfg.MaxStreamBuffer != 0 {
		c.MaxStreamBuffer = cfg.MaxStreamBuffer
	}
	if err := smux.VerifyConfig(c); err != nil {
		return nil, 0, errors.New("invalid mux limits")
	}
	return c, c.MaxReceiveBuffer + 65535, nil
}

// Cancellation retires the carrier and joins the backend operation. The backend
// has no per-call cancellation API; leaving a blocked operation would leak it.
func (s smuxSession) operation(ctx context.Context, call func() (*smux.Stream, error)) (Stream, error) {
	type result struct {
		stream *smux.Stream
		err    error
	}
	done := make(chan result, 1)
	go func() { stream, err := call(); done <- result{stream, err} }()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		return &framedStream{Stream: r.stream}, nil
	case <-ctx.Done():
		_ = s.session.Close()
		r := <-done
		if r.stream != nil {
			_ = r.stream.Close()
		}
		return nil, ctx.Err()
	}
}

func (s smuxSession) Done() <-chan struct{} { return s.session.CloseChan() }
