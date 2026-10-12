package agent_v1

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"math"
	"sync"
	"time"
)

const lifecycleRenewAfter = 30 * time.Second
const lifecycleProofBudget = 15 * time.Second
const lifecycleDuration = 90 * time.Second

type lifecyclePending struct {
	frame            LifecycleFrame
	issued, deadline time.Time
	sent             int
}
type lifecycleReceipt struct {
	proof  LifecycleFrame
	expiry time.Time
	proofs int
}

// ServerLease owns negotiated control authority. One timer, one pending
// challenge, one receipt and one wake token
// bound retained state. No nonce/proof/credential is persisted or logged.
type ServerLease struct {
	mu              sync.Mutex
	scope           LifecycleScope
	authority       LifecycleAuthority
	clock           LifecycleClock
	generation      domain.ConfigRevision
	expiry, nextDue time.Time
	pending         *lifecyclePending
	receipt         *lifecycleReceipt
	stale           int
	quotaStart      time.Time
	timer           LifecycleTimer
	ticket          uint64
	dueNotified     bool
	terminal        bool
	reason          error
	wake            chan struct{}
	done            chan struct{}
	stopInterest    func() bool
	cleanup         func()
	cleanupOnce     sync.Once
}

func configLifecycleScope(s LifecycleScope) bool {
	return config.ValidID(string(s.DeviceID)) && lifecycleToken(string(s.SessionID))
}
func NewServerLease(ctx context.Context, scope LifecycleScope, finish LifecycleFrame, authority LifecycleAuthority, clock LifecycleClock, cleanup func()) (*ServerLease, LifecycleFrame, error) {
	if authority != nil && authority.Context() != nil && authority.Context().Err() != nil {
		return nil, LifecycleFrame{}, ErrLifecycleExpired
	}
	if !configLifecycleScope(scope) || finish.Type != "auth_finish" || finish.DeviceID != scope.DeviceID || authority == nil || authority.Context() == nil || clock == nil || cleanup == nil {
		return nil, LifecycleFrame{}, ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(finish); e != nil {
		return nil, LifecycleFrame{}, e
	}
	l := &ServerLease{scope: scope, authority: authority, clock: clock, generation: 1, wake: make(chan struct{}, 1), done: make(chan struct{}), cleanup: cleanup}
	var grant LifecycleFrame
	e := authority.WithCurrent(ctx, scope, func(secret []byte) error {
		if e := VerifyLifecycleFrame(secret, finish); e != nil {
			return e
		}
		now := clock.Now()
		l.expiry = now.Add(lifecycleDuration)
		l.nextDue = now.Add(lifecycleRenewAfter)
		l.quotaStart = now
		grant = finish
		grant.Type = "auth_ok"
		grant.SessionID = scope.SessionID
		grant.Generation = 1
		grant.RemainingMillis = LifecycleLeaseMillis
		var e error
		grant, e = SignLifecycleFrame(secret, grant)
		return e
	})
	if e != nil {
		return nil, LifecycleFrame{}, e
	}
	l.mu.Lock()
	l.stopInterest = context.AfterFunc(authority.Context(), func() { l.Revoke(ErrLifecycleExpired) })
	l.armLocked()
	l.mu.Unlock()
	return l, grant, nil
}
func (l *ServerLease) Wake() <-chan struct{} { return l.wake }
func (l *ServerLease) Done() <-chan struct{} { return l.done }
func (l *ServerLease) notifyLocked() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}
func (l *ServerLease) terminalLocked(reason error) {
	if l.terminal {
		return
	}
	l.terminal = true
	l.reason = reason
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	l.ticket++
	l.pending = nil
	l.receipt = nil
	l.notifyLocked()
}
func (l *ServerLease) finishTerminal() {
	l.mu.Lock()
	terminal := l.terminal
	l.mu.Unlock()
	if !terminal {
		return
	}
	l.cleanupOnce.Do(func() {
		if l.stopInterest != nil {
			l.stopInterest()
		}
		l.cleanup()
		close(l.done)
	})
}
func (l *ServerLease) Revoke(reason error) {
	if reason == nil {
		reason = ErrLifecycleExpired
	}
	l.mu.Lock()
	l.terminalLocked(reason)
	l.mu.Unlock()
	l.finishTerminal()
}
func (l *ServerLease) liveLocked(now time.Time) error {
	if l.terminal {
		return l.reason
	}
	if !now.Before(l.expiry) || (l.pending != nil && !now.Before(l.pending.deadline)) {
		l.terminalLocked(ErrLifecycleExpired)
		return ErrLifecycleExpired
	}
	return nil
}
func (l *ServerLease) armLocked() {
	if l.terminal {
		return
	}
	if l.timer != nil {
		l.timer.Stop()
	}
	if l.ticket == math.MaxUint64 {
		l.terminalLocked(ErrLifecycleExpired)
		return
	}
	l.ticket++
	ticket := l.ticket
	deadline := l.expiry
	if l.pending != nil {
		if l.pending.deadline.Before(deadline) {
			deadline = l.pending.deadline
		}
		if l.pending.sent < 3 && !l.dueNotified {
			retry := l.pending.issued.Add(time.Duration([]int{0, 2, 5}[l.pending.sent]) * time.Second)
			if retry.Before(deadline) {
				deadline = retry
			}
		}
	} else if !l.dueNotified && l.nextDue.Before(deadline) {
		deadline = l.nextDue
	}
	delay := deadline.Sub(l.clock.Now())
	if delay < 0 {
		delay = 0
	}
	l.timer = l.clock.AfterFunc(delay, func() {
		l.mu.Lock()
		if l.terminal || ticket != l.ticket {
			l.mu.Unlock()
			return
		}
		now := l.clock.Now()
		if l.liveLocked(now) == nil {
			l.dueNotified = true
			l.notifyLocked()
			l.armLocked()
		}
		l.mu.Unlock()
		l.finishTerminal()
	})
}
func (l *ServerLease) underAuthority(ctx context.Context, apply func([]byte, time.Time) error) error {
	// Caller cancellation is local to this operation. Revalidate independent
	// session/credential/interest authority even when the caller has timed out.
	operationCanceled := false
	e := l.authority.WithCurrent(context.WithoutCancel(ctx), l.scope, func(secret []byte) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		now := l.clock.Now()
		if e := l.liveLocked(now); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			operationCanceled = true
			return e
		}
		e := apply(secret, now)
		if e == nil || errors.Is(e, ErrLifecycleStale) {
			l.armLocked()
		}
		return e
	})
	if e != nil && !operationCanceled && !errors.Is(e, ErrLifecycleStale) {
		l.mu.Lock()
		l.terminalLocked(e)
		l.mu.Unlock()
	}
	l.finishTerminal()
	return e
}

// Poll produces at most one challenge. Wake is only a coalesced scheduling hint.
func (l *ServerLease) Poll(ctx context.Context) (*LifecycleFrame, error) {
	// Entropy acquisition is outside authority/lease publication guards.
	l.mu.Lock()
	needNonce := !l.terminal && l.pending == nil && !l.clock.Now().Before(l.nextDue)
	l.mu.Unlock()
	var candidate string
	if needNonce {
		var e error
		candidate, e = GenerateNonce()
		if e != nil {
			l.Revoke(e)
			return nil, e
		}
	}
	var result *LifecycleFrame
	e := l.underAuthority(ctx, func(_ []byte, now time.Time) error {
		l.dueNotified = false
		if l.pending == nil {
			if now.Before(l.nextDue) {
				return nil
			}
			if l.generation == domain.ConfigRevision(math.MaxUint64) {
				return ErrLifecycleExpired
			}
			if candidate == "" {
				return ErrLifecycleStale
			}
			nonce := candidate
			f := lifecycleFrame("renew_challenge", l.scope.DeviceID, l.scope.SessionID)
			f.Generation = l.generation + 1
			f.Nonce = nonce
			f.LeaseMillis = LifecycleLeaseMillis
			f.ProofMillis = LifecycleProofMillis
			l.pending = &lifecyclePending{frame: f, issued: now, deadline: now.Add(lifecycleProofBudget)}
		}
		pending := l.pending
		if pending.sent >= 3 {
			return nil
		}
		due := pending.issued.Add(time.Duration([]int{0, 2, 5}[pending.sent]) * time.Second)
		if now.Before(due) {
			return nil
		}
		f := pending.frame
		pending.sent++
		result = &f
		return nil
	})
	return result, e
}
func (l *ServerLease) AcceptProof(ctx context.Context, proof LifecycleFrame) (*LifecycleFrame, error) {
	if proof.Type != "renew_response" {
		l.Revoke(ErrLifecycle)
		return nil, ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(proof); e != nil {
		l.Revoke(e)
		return nil, e
	}
	if proof.DeviceID != l.scope.DeviceID || proof.SessionID != l.scope.SessionID {
		l.Revoke(ErrLifecycle)
		return nil, ErrLifecycle
	}
	var grant *LifecycleFrame
	e := l.underAuthority(ctx, func(secret []byte, now time.Time) error {
		if now.Sub(l.quotaStart) >= lifecycleRenewAfter {
			l.stale = 0
			l.quotaStart = now
		}
		if proof.Generation < l.generation || (proof.Generation == l.generation && l.receipt == nil) {
			l.stale++
			if l.stale > 2 {
				return ErrLifecycleQuota
			}
			return ErrLifecycleStale
		}
		if proof.Generation == l.generation && l.receipt != nil {
			r := l.receipt
			if proof != r.proof {
				return ErrLifecycle
			}
			if r.proofs >= 4 {
				return ErrLifecycleQuota
			}
			if e := VerifyLifecycleFrame(secret, proof); e != nil {
				return e
			}
			r.proofs++
			f := proof
			f.Type = "renew_ok"
			f.RemainingMillis = int(r.expiry.Sub(now) / time.Millisecond)
			if f.RemainingMillis < 1 {
				return ErrLifecycleExpired
			}
			f, e := SignLifecycleFrame(secret, f)
			if e != nil {
				return e
			}
			grant = &f
			return nil
		}
		pending := l.pending
		if pending == nil || proof.Generation != pending.frame.Generation || proof.Nonce != pending.frame.Nonce {
			return ErrLifecycle
		}
		if !now.Before(pending.deadline) {
			return ErrLifecycleExpired
		}
		if e := VerifyLifecycleFrame(secret, proof); e != nil {
			return e
		}
		l.generation = proof.Generation
		l.expiry = now.Add(lifecycleDuration)
		l.nextDue = now.Add(lifecycleRenewAfter)
		l.receipt = &lifecycleReceipt{proof: proof, expiry: l.expiry, proofs: 1}
		l.pending = nil
		l.dueNotified = false
		f := proof
		f.Type = "renew_ok"
		f.RemainingMillis = LifecycleLeaseMillis
		f, e := SignLifecycleFrame(secret, f)
		if e != nil {
			return e
		}
		grant = &f
		return nil
	})
	return grant, e
}

// Valid checks live current authority, not only a timer timestamp. Integration
// must use this boundary for every new carrier/open/readiness authorization.
func (l *ServerLease) Valid(ctx context.Context) error {
	return l.underAuthority(ctx, func([]byte, time.Time) error { return nil })
}
func (l *ServerLease) Generation() domain.ConfigRevision {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.generation
}

// withAdmission isolates an ordinary operation failure from lease authority.
// Independent revocation/expiry still closes the session; a stale application
// tuple or canceled route request cannot revoke an otherwise live session.
func (l *ServerLease) withAdmission(ctx context.Context, apply func([]byte) error) error {
	var operation error
	e := l.underAuthority(ctx, func(secret []byte, _ time.Time) error { operation = apply(secret); return nil })
	if e != nil {
		return e
	}
	return operation
}
