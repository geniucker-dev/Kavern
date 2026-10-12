package agent_v1

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
	"math"
	"sync"
	"time"
)

type clientLifecyclePending struct {
	challenge           LifecycleFrame
	proof               LifecycleFrame
	firstSend, deadline time.Time
	sent, received      int
}

// ClientLease validates the frozen initial auth exchange and conservative grant
// deadlines. It owns no network dispatch; clock and lifetime are constructor inputs.
type ClientLease struct {
	mu          sync.Mutex
	clock       LifecycleClock
	scope       LifecycleScope
	secret      []byte
	generation  domain.ConfigRevision
	expiry      time.Time
	pending     *clientLifecyclePending
	lastNonce   string
	stale       int
	quotaStart  time.Time
	timer       LifecycleTimer
	ticket      uint64
	dueNotified bool
	terminal    bool
	reason      error
	wake        chan struct{}
	done        chan struct{}
	stopContext func() bool
	cleanup     func()
	once        sync.Once
	grantFrames int
}

func NewClientLease(ctx context.Context, finish, grant LifecycleFrame, authFinishSent time.Time, secret []byte, clock LifecycleClock, cleanup func()) (*ClientLease, error) {
	if ctx == nil || ctx.Err() != nil || clock == nil || cleanup == nil || len(secret) != 32 || finish.Type != "auth_finish" || grant.Type != "auth_ok" {
		return nil, ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(finish); e != nil {
		return nil, e
	}
	if _, e := EncodeLifecycleFrame(grant); e != nil {
		return nil, e
	}
	if e := VerifyLifecycleFrame(secret, finish); e != nil {
		return nil, e
	}
	if e := VerifyLifecycleFrame(secret, grant); e != nil {
		return nil, e
	}
	expected := grant
	expected.Type = "auth_finish"
	expected.SessionID = ""
	expected.Generation = 0
	expected.RemainingMillis = 0
	expected.HMAC = finish.HMAC
	if expected != finish {
		return nil, ErrLifecycle
	}
	now := clock.Now()
	deadline := authFinishSent.Add(time.Duration(grant.RemainingMillis) * time.Millisecond)
	if authFinishSent.After(now) || !now.Before(deadline) {
		return nil, ErrLifecycleExpired
	}
	c := &ClientLease{clock: clock, scope: LifecycleScope{grant.DeviceID, grant.SessionID}, secret: append([]byte(nil), secret...), generation: 1, expiry: deadline, quotaStart: now, wake: make(chan struct{}, 1), done: make(chan struct{}), cleanup: cleanup}
	c.mu.Lock()
	c.stopContext = context.AfterFunc(ctx, func() { c.Revoke(ErrLifecycleExpired) })
	c.armLocked()
	c.mu.Unlock()
	return c, nil
}
func (c *ClientLease) Wake() <-chan struct{} { return c.wake }
func (c *ClientLease) Done() <-chan struct{} { return c.done }
func (c *ClientLease) notifyLocked() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *ClientLease) terminalLocked(e error) {
	if c.terminal {
		return
	}
	c.terminal = true
	c.reason = e
	clear(c.secret)
	c.pending = nil
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.ticket++
	c.notifyLocked()
}
func (c *ClientLease) finish() {
	c.mu.Lock()
	terminal := c.terminal
	c.mu.Unlock()
	if terminal {
		c.once.Do(func() {
			if c.stopContext != nil {
				c.stopContext()
			}
			c.cleanup()
			close(c.done)
		})
	}
}
func (c *ClientLease) Revoke(e error) {
	if e == nil {
		e = ErrLifecycleExpired
	}
	c.mu.Lock()
	c.terminalLocked(e)
	c.mu.Unlock()
	c.finish()
}
func (c *ClientLease) liveLocked(now time.Time) error {
	if c.terminal {
		return c.reason
	}
	if !now.Before(c.expiry) || (c.pending != nil && !now.Before(c.pending.deadline)) {
		c.terminalLocked(ErrLifecycleExpired)
		return ErrLifecycleExpired
	}
	return nil
}
func (c *ClientLease) armLocked() {
	if c.terminal {
		return
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.ticket == math.MaxUint64 {
		c.terminalLocked(ErrLifecycleExpired)
		return
	}
	c.ticket++
	ticket := c.ticket
	deadline := c.expiry
	if p := c.pending; p != nil {
		if p.deadline.Before(deadline) {
			deadline = p.deadline
		}
		if p.sent < 3 && !c.dueNotified {
			due := p.firstSend.Add(time.Duration([]int{0, 2, 5}[p.sent]) * time.Second)
			if due.Before(deadline) {
				deadline = due
			}
		}
	}
	delay := deadline.Sub(c.clock.Now())
	if delay < 0 {
		delay = 0
	}
	c.timer = c.clock.AfterFunc(delay, func() {
		c.mu.Lock()
		if c.terminal || ticket != c.ticket {
			c.mu.Unlock()
			return
		}
		if c.liveLocked(c.clock.Now()) == nil {
			c.dueNotified = true
			c.notifyLocked()
			c.armLocked()
		}
		c.mu.Unlock()
		c.finish()
	})
}
func (c *ClientLease) frameScope(f LifecycleFrame) bool {
	return f.DeviceID == c.scope.DeviceID && f.SessionID == c.scope.SessionID
}
func (c *ClientLease) staleLocked(now time.Time) error {
	if now.Sub(c.quotaStart) >= lifecycleRenewAfter {
		c.stale = 0
		c.quotaStart = now
	}
	c.stale++
	if c.stale > 2 {
		return ErrLifecycleQuota
	}
	return ErrLifecycleStale
}
func (c *ClientLease) Challenge(f LifecycleFrame) (*LifecycleFrame, error) {
	if f.Type != "renew_challenge" {
		c.Revoke(ErrLifecycle)
		return nil, ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(f); e != nil {
		c.Revoke(e)
		return nil, e
	}
	c.mu.Lock()
	now := c.clock.Now()
	e := c.liveLocked(now)
	var proof *LifecycleFrame
	if e == nil {
		switch {
		case !c.frameScope(f):
			e = ErrLifecycle
		case f.Generation < c.generation:
			e = c.staleLocked(now)
		case f.Generation == c.generation:
			if f.Nonce != c.lastNonce {
				e = ErrLifecycle
			} else {
				e = c.staleLocked(now)
			}
		case c.generation == domain.ConfigRevision(math.MaxUint64) || f.Generation != c.generation+1:
			e = ErrLifecycle
		default:
			if c.pending == nil {
				signed := f
				signed.Type = "renew_response"
				signed, e = SignLifecycleFrame(c.secret, signed)
				if e == nil {
					c.pending = &clientLifecyclePending{challenge: f, proof: signed, firstSend: now, deadline: now.Add(lifecycleProofBudget)}
				}
			} else if c.pending.challenge != f {
				e = ErrLifecycle
			}
			if e == nil {
				p := c.pending
				p.received++
				if p.received > 3 {
					e = ErrLifecycleQuota
				} else if p.sent < 3 {
					p.sent++
					value := p.proof
					proof = &value
					c.dueNotified = false
				}
			}
		}
	}
	if e != nil && e != ErrLifecycleStale {
		c.terminalLocked(e)
	}
	if e == nil || e == ErrLifecycleStale {
		c.armLocked()
	}
	c.mu.Unlock()
	c.finish()
	return proof, e
}
func (c *ClientLease) Poll() (*LifecycleFrame, error) {
	c.mu.Lock()
	now := c.clock.Now()
	e := c.liveLocked(now)
	var proof *LifecycleFrame
	if e == nil {
		c.dueNotified = false
		if p := c.pending; p != nil && p.sent < 3 {
			due := p.firstSend.Add(time.Duration([]int{0, 2, 5}[p.sent]) * time.Second)
			if !now.Before(due) {
				p.sent++
				f := p.proof
				proof = &f
			}
		}
		c.armLocked()
	}
	c.mu.Unlock()
	c.finish()
	return proof, e
}
func (c *ClientLease) Grant(f LifecycleFrame) error {
	if f.Type != "renew_ok" {
		c.Revoke(ErrLifecycle)
		return ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(f); e != nil {
		c.Revoke(e)
		return e
	}
	c.mu.Lock()
	now := c.clock.Now()
	e := c.liveLocked(now)
	if e == nil {
		switch {
		case !c.frameScope(f):
			e = ErrLifecycle
		case f.Generation < c.generation:
			e = c.staleLocked(now)
		case f.Generation == c.generation:
			c.grantFrames++
			if c.grantFrames > 4 {
				e = ErrLifecycleQuota
				break
			}
			if f.Nonce != c.lastNonce {
				e = ErrLifecycle
			} else {
				e = VerifyLifecycleFrame(c.secret, f)
			}
		default:
			p := c.pending
			if p == nil || f.Generation != p.challenge.Generation || f.Nonce != p.challenge.Nonce {
				e = ErrLifecycle
			} else if e = VerifyLifecycleFrame(c.secret, f); e == nil {
				deadline := p.firstSend.Add(time.Duration(f.RemainingMillis) * time.Millisecond)
				if !now.Before(deadline) {
					e = ErrLifecycleExpired
				} else {
					c.generation = f.Generation
					c.expiry = deadline
					c.lastNonce = f.Nonce
					c.grantFrames = 1
					c.pending = nil
					c.dueNotified = false
				}
			}
		}
	}
	if e != nil && e != ErrLifecycleStale {
		c.terminalLocked(e)
	}
	if e == nil || e == ErrLifecycleStale {
		c.armLocked()
	}
	c.mu.Unlock()
	c.finish()
	return e
}
func (c *ClientLease) Valid() error {
	c.mu.Lock()
	e := c.liveLocked(c.clock.Now())
	c.mu.Unlock()
	c.finish()
	return e
}
