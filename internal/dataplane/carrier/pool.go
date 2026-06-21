package carrier

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrPoolClosed         = errors.New("carrier pool closed")
	ErrNoCarrierAvailable = errors.New("no carrier available")
)

type Pool struct {
	mu       sync.Mutex
	carriers []*Carrier
	closed   bool
	next     int
}

func NewPool(carriers ...*Carrier) (*Pool, error) {
	for _, carrier := range carriers {
		if carrier == nil {
			return nil, ErrInvalidConfig
		}
	}
	return &Pool{carriers: append([]*Carrier(nil), carriers...)}, nil
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
