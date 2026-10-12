package carrier

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrPoolFull           = errors.New("carrier pool full")
	ErrPoolClosed         = errors.New("carrier pool closed")
	ErrNoCarrierAvailable = errors.New("no carrier available")
)

type Pool struct {
	mu       sync.Mutex
	carriers []*Carrier
	closed   bool
	changed  chan struct{}
	next     int
}

func NewPool(carriers ...*Carrier) (*Pool, error) {
	if len(carriers) > 4 {
		return nil, ErrPoolFull
	}
	for _, carrier := range carriers {
		if carrier == nil {
			return nil, ErrInvalidConfig
		}
	}
	return &Pool{carriers: append([]*Carrier(nil), carriers...), changed: make(chan struct{})}, nil
}

func (p *Pool) Add(carrier *Carrier) error {
	if carrier == nil {
		return ErrInvalidConfig
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrPoolClosed
	}
	if carrier.Closed() {
		return ErrCarrierClosed
	}
	live := p.carriers[:0]
	for _, existing := range p.carriers {
		if !existing.Closed() {
			live = append(live, existing)
		}
	}
	p.carriers = live
	if len(p.carriers) >= 4 {
		return ErrPoolFull
	}
	p.carriers = append(p.carriers, carrier)
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

func (p *Pool) Acquire(ctx context.Context) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	carriers := append([]*Carrier(nil), p.carriers...)
	start := p.next
	if len(carriers) > 0 {
		p.next = (p.next + 1) % len(carriers)
	}
	p.mu.Unlock()

	if len(carriers) == 0 {
		return nil, ErrNoCarrierAvailable
	}
	for i := 0; i < len(carriers); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		carrier := carriers[(start+i)%len(carriers)]
		lease, err := carrier.OpenStream(ctx)
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, ErrCarrierFull) && !errors.Is(err, ErrCarrierClosed) {
			return nil, err
		}
	}
	return nil, ErrNoCarrierAvailable
}

func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.changed)
	carriers := append([]*Carrier(nil), p.carriers...)
	p.mu.Unlock()

	var first error
	for _, carrier := range carriers {
		if err := carrier.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (p *Pool) WaitReady(ctx context.Context, n int) error {
	if n < 1 || n > 4 {
		return ErrInvalidConfig
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return ErrPoolClosed
		}
		count := 0
		for _, c := range p.carriers {
			if !c.Closed() {
				count++
			}
		}
		changed := p.changed
		p.mu.Unlock()
		if count >= n {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// LiveCount reports attached, nonclosed carriers; readiness notifications are
// wakeups only, so callers recheck this count after any wait.
func (p *Pool) LiveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	count := 0
	for _, c := range p.carriers {
		if !c.Closed() {
			count++
		}
	}
	return count
}
