package agent_v1

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"sync"
)

type LifecycleScope struct {
	DeviceID  domain.DeviceID
	SessionID domain.SessionID
}

// WithCurrent serializes current credentials, device/session identity and live
// owner interest with publication. apply is memory-only and must not perform I/O.
type LifecycleAuthority interface {
	Context() context.Context
	WithCurrent(context.Context, LifecycleScope, func([]byte) error) error
}
type LifecycleOwner interface {
	WithNativeInterest(context.Context, context.Context, domain.DeviceID, func([]byte) error) error
}
type OwnedLifecycleAuthority struct {
	registration *sync.Mutex
	owner        LifecycleOwner
	manager      session.SessionManager
	scope        LifecycleScope
	interest     context.Context
}

// interest must be the exact authenticated session's lifecycle-owned interest;
// this constructor is not a wire/bootstrap permission to borrow another session.
func NewOwnedLifecycleAuthority(registration *sync.Mutex, owner LifecycleOwner, manager session.SessionManager, scope LifecycleScope, interest context.Context) (*OwnedLifecycleAuthority, error) {
	if registration == nil || owner == nil || manager == nil || interest == nil || !configLifecycleScope(scope) {
		return nil, ErrLifecycle
	}
	return &OwnedLifecycleAuthority{registration, owner, manager, scope, interest}, nil
}
func (a *OwnedLifecycleAuthority) Context() context.Context { return a.interest }
func (a *OwnedLifecycleAuthority) WithCurrent(ctx context.Context, scope LifecycleScope, apply func([]byte) error) error {
	if scope != a.scope {
		return ErrLifecycle
	}
	a.registration.Lock()
	defer a.registration.Unlock()
	return a.owner.WithNativeInterest(ctx, a.interest, scope.DeviceID, func(secret []byte) error {
		current, e := a.manager.CurrentForDevice(ctx, scope.DeviceID)
		if e != nil {
			return e
		}
		if current.ID() != scope.SessionID || current.DeviceID() != scope.DeviceID || current.Protocol() != domain.AgentProtocolKAPv1 {
			return ErrSessionNotCurrent
		}
		select {
		case <-current.Done():
			return ErrSessionClosed
		default:
		}
		return apply(secret)
	})
}
