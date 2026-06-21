package mux

import (
	"context"
	"io"
	"net"
)

type Config struct{}

type Backend interface {
	Name() string
	Client(conn net.Conn, cfg Config) (Session, error)
	Server(conn net.Conn, cfg Config) (Session, error)
}

type Session interface {
	OpenStream(ctx context.Context) (Stream, error)
	AcceptStream(ctx context.Context) (Stream, error)
	Close() error
}

type Stream interface {
	io.Reader
	io.Writer
	Close() error
}
