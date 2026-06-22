package carrier

import (
	"context"
	"errors"
	"sync"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
)

var (
	ErrInvalidConfig = errors.New("invalid carrier config")
	ErrCarrierClosed = errors.New("carrier closed")
	ErrCarrierFull   = errors.New("carrier full")
)

type Config struct {
	MaxStreamsPerCarrier int
}

type Carrier struct {
	mu       sync.Mutex
	session  mux.Session
	max      int
	active   int
	reserved int
	closed   bool
}

func New(session mux.Session, cfg Config) (*Carrier, error) {
	if session == nil || cfg.MaxStreamsPerCarrier <= 0 {
		return nil, ErrInvalidConfig
	}
	return &Carrier{session: session, max: cfg.MaxStreamsPerCarrier}, nil
}

func (c *Carrier) OpenStream(ctx context.Context) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrCarrierClosed
	}
	if c.reserved >= c.max {
		c.mu.Unlock()
		return nil, ErrCarrierFull
	}
	c.reserved++
	c.mu.Unlock()

	stream, err := c.session.OpenStream(ctx)
	if err != nil {
		c.releaseReserved()
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = stream.Close()
		c.reserved--
		return nil, ErrCarrierClosed
	}
	c.active++
	return &Lease{Stream: stream, release: c.release}, nil
}

func (c *Carrier) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.session.Close()
}

func (c *Carrier) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Carrier) ActiveStreams() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *Carrier) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active > 0 {
		c.active--
	}
	if c.reserved > 0 {
		c.reserved--
	}
}

func (c *Carrier) releaseReserved() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reserved > 0 {
		c.reserved--
	}
}

type Lease struct {
	Stream mux.Stream

	once    sync.Once
	release func()
	err     error
}

func (l *Lease) Release() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.Stream != nil {
			l.err = l.Stream.Close()
		}
		if l.release != nil {
			l.release()
		}
	})
	return l.err
}
