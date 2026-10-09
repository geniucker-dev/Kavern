package carrier

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
)

var (
	ErrInvalidConfig = errors.New("invalid carrier config")
	ErrCarrierClosed = errors.New("carrier closed")
	ErrCarrierFull   = errors.New("carrier full")
)

type Config struct {
	MaxStreamsPerCarrier int
	// MaxInflight bounds bytes owned by pending synchronous writes.
	MaxInflight int
	// MaxBuffer includes the backend receive bound and pending write copies.
	MaxBuffer int
}

type Carrier struct {
	mu          sync.Mutex
	session     mux.Session
	max         int
	active      int
	reserved    int
	closed      bool
	inflight    int
	maxInflight int
	changed     chan struct{}
}

func New(session mux.Session, cfg Config) (*Carrier, error) {
	if session == nil || cfg.MaxStreamsPerCarrier <= 0 {
		return nil, ErrInvalidConfig
	}
	if cfg.MaxInflight == 0 {
		cfg.MaxInflight = 1 << 20
	}
	if cfg.MaxBuffer == 0 {
		cfg.MaxBuffer = 8 << 20
	}
	if cfg.MaxInflight < 1 || cfg.MaxBuffer < cfg.MaxInflight || session.ReceiveBufferLimit() < 0 || session.ReceiveBufferLimit() > cfg.MaxBuffer-cfg.MaxInflight {
		return nil, ErrInvalidConfig
	}
	return &Carrier{session: session, max: cfg.MaxStreamsPerCarrier, maxInflight: cfg.MaxInflight, changed: make(chan struct{})}, nil
}

func (c *Carrier) OpenStream(ctx context.Context) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.closed || c.backendClosed() {
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
		if c.backendClosed() {
			return nil, ErrCarrierClosed
		}
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.backendClosed() {
		_ = stream.Close()
		c.reserved--
		return nil, ErrCarrierClosed
	}
	c.active++
	return &Lease{Stream: &boundedStream{Stream: stream, carrier: c, ctx: ctx}, release: c.release}, nil
}

func (c *Carrier) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.changed)
	c.mu.Unlock()
	return c.session.Close()
}

func (c *Carrier) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.backendClosed()
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

// InflightBytes reports locally owned pending write payload, not remote acknowledgements.
func (c *Carrier) InflightBytes() int { c.mu.Lock(); defer c.mu.Unlock(); return c.inflight }
func (c *Carrier) acquireBytes(ctx context.Context, n int) error {
	for {
		c.mu.Lock()
		if c.closed || c.backendClosed() {
			c.mu.Unlock()
			return ErrCarrierClosed
		}
		if n <= c.maxInflight-c.inflight {
			c.inflight += n
			c.mu.Unlock()
			return nil
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-c.backendDone():
			return ErrCarrierClosed
		}
	}
}
func (c *Carrier) releaseBytes(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inflight -= n
	if !c.closed {
		close(c.changed)
		c.changed = make(chan struct{})
	}
}

type boundedStream struct {
	mux.Stream
	carrier   *Carrier
	ctx       context.Context
	closeOnce sync.Once
	closeErr  error
}

func (s *boundedStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), min(16<<10, s.carrier.maxInflight))
		if err := s.carrier.acquireBytes(s.ctx, n); err != nil {
			return total, err
		}
		owned := append([]byte(nil), p[:n]...)
		callbackDone := make(chan struct{})
		stop := context.AfterFunc(s.ctx, func() { defer close(callbackDone); _ = s.carrier.Close() })
		written, err := s.Stream.Write(owned)
		if !stop() {
			<-callbackDone
		}
		s.carrier.releaseBytes(n)
		if written < 0 || written > n {
			return total, io.ErrShortWrite
		}
		total += written
		p = p[written:]
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (s *boundedStream) CloseWrite() error {
	if cw, ok := s.Stream.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("mux stream does not support half-close")
}

// AdoptStream applies the same stream and byte budget to remotely opened streams.
// On failure ownership stays with the caller, which must close the stream.
func (c *Carrier) AdoptStream(ctx context.Context, stream mux.Stream) (*Lease, error) {
	if stream == nil {
		return nil, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.backendClosed() {
		return nil, ErrCarrierClosed
	}
	if c.reserved >= c.max {
		return nil, ErrCarrierFull
	}
	c.reserved++
	c.active++
	return &Lease{Stream: &boundedStream{Stream: stream, carrier: c, ctx: ctx}, release: c.release}, nil
}

func (s *boundedStream) SetReadDeadline(t time.Time) error {
	if d, ok := s.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *Carrier) backendDone() <-chan struct{} {
	if d, ok := c.session.(interface{ Done() <-chan struct{} }); ok {
		return d.Done()
	}
	return nil
}
func (c *Carrier) backendClosed() bool {
	select {
	case <-c.backendDone():
		return true
	default:
		return false
	}
}

func (s *boundedStream) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.Stream.Close() })
	return s.closeErr
}
