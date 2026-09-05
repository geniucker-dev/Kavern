package legacy_npc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type managerObservationKind uint8

const (
	managerUnknown managerObservationKind = iota
	managerKnownCurrent
	managerKnownNone
)

type managerObservation struct {
	kind    managerObservationKind
	current session.AgentSession
}

func observeManager(current session.AgentSession, err error) managerObservation {
	if err == nil && current != nil {
		return managerObservation{kind: managerKnownCurrent, current: current}
	}
	if errors.Is(err, session.ErrNoCurrentSession) {
		return managerObservation{kind: managerKnownNone}
	}
	return managerObservation{kind: managerUnknown}
}

// A failed Attach did not mutate manager state. An unavailable observation
// therefore cannot invalidate a still-live prior main.
func (r *legacyDeviceRuntime) reconcileFailedAttach(next, priorCurrent, priorAttached *LegacyNpcSession, observed managerObservation) (*LegacyMux, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingMainTransitions <= 0 {
		return nil, ErrLegacyRuntimeInvariant
	}
	r.pendingMainTransitions--
	if r.currentMain == next {
		r.currentMain = nil
	}
	if observed.kind != managerUnknown && r.attachedMain != nil && !sameAgentSession(observed.current, r.attachedMain) {
		r.attachedMain = nil
	}
	if r.currentMain == nil && priorCurrent != nil && priorCurrent == priorAttached &&
		r.attachedMain == priorAttached &&
		(observed.kind == managerUnknown || sameAgentSession(observed.current, priorCurrent)) {
		priorCurrent.mu.Lock()
		if priorCurrent.lifecycleActiveLocked() {
			r.currentMain = priorCurrent
		}
		priorCurrent.mu.Unlock()
	}
	r.notifyMainStateLocked()
	if r.hasMainInterestLocked() {
		return nil, nil
	}
	return r.detachMuxLocked(), nil
}

type legacyRuntimeLeaseKind uint8

const (
	legacyRuntimeLeaseTransition legacyRuntimeLeaseKind = iota + 1
	legacyRuntimeLeaseSession
	legacyRuntimeLeaseChan
)

type legacyDeviceRuntime struct {
	deviceID domain.DeviceID

	mainTransitionMu sync.Mutex

	mu                     sync.Mutex
	currentMain            *LegacyNpcSession
	attachedMain           *LegacyNpcSession
	pendingMainTransitions int
	mux                    *LegacyMux
	muxGeneration          uint64
	mainNotify             chan struct{}
}

func (r *legacyDeviceRuntime) notifyMainStateLocked() {
	close(r.mainNotify)
	r.mainNotify = make(chan struct{})
}

func (g *Gateway) acquireMainRuntime(deviceID domain.DeviceID) (*legacyRuntimeLease, *legacyRuntimeLease) {
	g.runtimeMu.Lock()
	entry := g.runtimes[deviceID]
	if entry == nil {
		entry = &legacyRuntimeEntry{
			runtime: newLegacyDeviceRuntime(deviceID),
			byKind:  make(map[legacyRuntimeLeaseKind]int),
		}
		g.runtimes[deviceID] = entry
	}
	entry.refs += 2
	entry.byKind[legacyRuntimeLeaseTransition]++
	entry.byKind[legacyRuntimeLeaseSession]++
	entry.runtime.mu.Lock()
	entry.runtime.pendingMainTransitions++
	entry.runtime.notifyMainStateLocked()
	entry.runtime.mu.Unlock()
	g.runtimeMu.Unlock()
	return &legacyRuntimeLease{gateway: g, entry: entry, kind: legacyRuntimeLeaseTransition},
		&legacyRuntimeLease{gateway: g, entry: entry, kind: legacyRuntimeLeaseSession}
}

func (r *legacyDeviceRuntime) finishUnpublishedMainTransition() (*LegacyMux, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingMainTransitions <= 0 {
		return nil, ErrLegacyRuntimeInvariant
	}
	r.pendingMainTransitions--
	r.notifyMainStateLocked()
	if r.hasMainInterestLocked() {
		return nil, nil
	}
	return r.detachMuxLocked(), nil
}

type legacyRuntimeEntry struct {
	runtime *legacyDeviceRuntime
	refs    int
	byKind  map[legacyRuntimeLeaseKind]int
}

type legacyRuntimeLease struct {
	gateway *Gateway
	entry   *legacyRuntimeEntry
	kind    legacyRuntimeLeaseKind
	once    sync.Once
	err     error
}

func newLegacyDeviceRuntime(deviceID domain.DeviceID) *legacyDeviceRuntime {
	return &legacyDeviceRuntime{
		deviceID:   deviceID,
		mainNotify: make(chan struct{}),
	}
}

func (g *Gateway) acquireRuntime(deviceID domain.DeviceID, kind legacyRuntimeLeaseKind) *legacyRuntimeLease {
	g.runtimeMu.Lock()
	entry := g.runtimes[deviceID]
	if entry == nil {
		entry = &legacyRuntimeEntry{
			runtime: newLegacyDeviceRuntime(deviceID),
			byKind:  make(map[legacyRuntimeLeaseKind]int),
		}
		g.runtimes[deviceID] = entry
	}
	entry.refs++
	entry.byKind[kind]++
	g.runtimeMu.Unlock()
	return &legacyRuntimeLease{gateway: g, entry: entry, kind: kind}
}

func (l *legacyRuntimeLease) Runtime() *legacyDeviceRuntime {
	if l == nil || l.entry == nil {
		return nil
	}
	return l.entry.runtime
}

func (l *legacyRuntimeLease) Release() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		l.err = l.gateway.releaseRuntime(l.entry, l.kind)
	})
	return l.err
}

func (g *Gateway) releaseRuntime(entry *legacyRuntimeEntry, kind legacyRuntimeLeaseKind) error {
	if entry == nil {
		return ErrLegacyRuntimeInvariant
	}
	g.runtimeMu.Lock()
	defer g.runtimeMu.Unlock()
	if entry.refs <= 0 || entry.byKind[kind] <= 0 {
		return ErrLegacyRuntimeInvariant
	}
	entry.refs--
	entry.byKind[kind]--
	if entry.refs != 0 {
		return nil
	}
	for _, count := range entry.byKind {
		if count != 0 {
			return ErrLegacyRuntimeInvariant
		}
	}
	if g.runtimes[entry.runtime.deviceID] == entry {
		delete(g.runtimes, entry.runtime.deviceID)
	}
	return nil
}

func (r *legacyDeviceRuntime) publishMainCandidate(next *LegacyNpcSession) (current, attached *LegacyNpcSession, published bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next.mu.Lock()
	defer next.mu.Unlock()
	if !next.lifecycleActiveLocked() {
		return nil, nil, false
	}
	current, attached = r.currentMain, r.attachedMain
	r.currentMain = next
	r.notifyMainStateLocked()
	return current, attached, true
}

func (r *legacyDeviceRuntime) mainTransitionSessionLive(next *LegacyNpcSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	next.mu.Lock()
	defer next.mu.Unlock()
	return next.lifecycleActiveLocked()
}

func (r *legacyDeviceRuntime) commitAttachedMain(ctx context.Context, next *LegacyNpcSession, managerCurrent session.AgentSession) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next.mu.Lock()
	defer next.mu.Unlock()
	if r.pendingMainTransitions <= 0 {
		return false, ErrLegacyRuntimeInvariant
	}
	if ctx.Err() != nil || !next.lifecycleActiveLocked() || r.currentMain != next || !sameAgentSession(managerCurrent, next) {
		return false, nil
	}
	r.attachedMain = next
	r.pendingMainTransitions--
	r.notifyMainStateLocked()
	return true, nil
}

// Attach succeeded before verification or commit failed. Unlike failed Attach,
// this path cannot assume the prior manager state was preserved.
func (r *legacyDeviceRuntime) reconcileFailedMain(next, priorCurrent, priorAttached *LegacyNpcSession, managerCurrent session.AgentSession) (*LegacyMux, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingMainTransitions <= 0 {
		return nil, ErrLegacyRuntimeInvariant
	}
	r.pendingMainTransitions--
	if r.currentMain == next {
		r.currentMain = nil
	}
	if r.attachedMain != nil && !sameAgentSession(managerCurrent, r.attachedMain) {
		r.attachedMain = nil
	}
	if r.currentMain == nil && priorCurrent != nil && priorCurrent == priorAttached && sameAgentSession(managerCurrent, priorCurrent) {
		priorCurrent.mu.Lock()
		live := priorCurrent.lifecycleActiveLocked()
		priorCurrent.mu.Unlock()
		if live {
			r.currentMain = priorCurrent
			r.attachedMain = priorCurrent
		}
	}
	r.notifyMainStateLocked()
	if r.hasMainInterestLocked() {
		return nil, nil
	}
	return r.detachMuxLocked(), nil
}

func sameAgentSession(got session.AgentSession, want *LegacyNpcSession) bool {
	if got == nil || want == nil {
		return false
	}
	actual, ok := got.(*LegacyNpcSession)
	return ok && actual == want && actual.ID() == want.ID()
}

func (r *legacyDeviceRuntime) hasMainInterestLocked() bool {
	if r.pendingMainTransitions > 0 {
		return true
	}
	for _, candidate := range []*LegacyNpcSession{r.currentMain, r.attachedMain} {
		if candidate == nil {
			continue
		}
		candidate.mu.Lock()
		live := candidate.lifecycleActiveLocked()
		candidate.mu.Unlock()
		if live {
			return true
		}
	}
	return false
}

func (r *legacyDeviceRuntime) installMux(incoming *LegacyMux) (uint64, *LegacyMux, error) {
	if incoming == nil {
		return 0, nil, ErrLegacyDataChannelUnavailable
	}
	// Nested state locks always use mux -> runtime -> session order.
	incoming.mu.Lock()
	defer incoming.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if incoming.closed {
		return 0, nil, classifyLegacyMuxTerminalCause(incoming.muxErrorLocked())
	}
	if r.mux == incoming {
		return 0, nil, ErrLegacyMuxAlreadyInstalled
	}
	old := r.mux
	r.mux = incoming
	r.muxGeneration++
	return r.muxGeneration, old, nil
}

func (r *legacyDeviceRuntime) clearMuxIfCurrent(expected *LegacyMux, generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mux != expected || r.muxGeneration != generation {
		return false
	}
	r.mux = nil
	r.muxGeneration++
	return true
}

func (r *legacyDeviceRuntime) detachMuxLocked() *LegacyMux {
	mux := r.mux
	if mux != nil {
		r.mux = nil
		r.muxGeneration++
	}
	return mux
}

func (r *legacyDeviceRuntime) snapshotMuxForSession(owner *LegacyNpcSession) (*LegacyMux, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.lifecycleActiveLocked() || r.currentMain != owner {
		return nil, 0, ErrLegacySessionClosed
	}
	if r.mux == nil {
		return nil, 0, ErrLegacyDataChannelUnavailable
	}
	return r.mux, r.muxGeneration, nil
}

func (r *legacyDeviceRuntime) waitForMainInterest(ctx context.Context, expected *LegacyMux, generation uint64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		r.mu.Lock()
		if r.mux != expected || r.muxGeneration != generation {
			r.mu.Unlock()
			return ErrLegacyDataChannelReplaced
		}
		if r.hasMainInterestLocked() {
			r.mu.Unlock()
			return nil
		}
		notify := r.mainNotify
		r.mu.Unlock()

		select {
		case <-notify:
			continue
		case <-ctx.Done():
			r.clearMuxIfCurrent(expected, generation)
			return ctx.Err()
		case <-expected.Done():
			r.clearMuxIfCurrent(expected, generation)
			_, terminalErr := expected.terminalErrorSnapshot()
			return classifyLegacyMuxTerminalCause(terminalErr)
		case <-timer.C:
			r.mu.Lock()
			if r.mux != expected || r.muxGeneration != generation {
				r.mu.Unlock()
				return ErrLegacyDataChannelReplaced
			}
			if r.hasMainInterestLocked() {
				r.mu.Unlock()
				return nil
			}
			r.mux = nil
			r.muxGeneration++
			r.mu.Unlock()
			return ErrNoCurrentMainSession
		}
	}
}

func (r *legacyDeviceRuntime) mapMuxOperationError(ctx context.Context, owner *LegacyNpcSession, expected *LegacyMux, generation uint64, operationErr error) error {
	// Nested state locks always use mux -> runtime -> session order.
	expected.mu.Lock()
	defer expected.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	var terminalErr error
	if expected.closed {
		terminalErr = expected.muxErrorLocked()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !owner.lifecycleActiveLocked() || r.currentMain != owner {
		return ErrLegacySessionClosed
	}
	if r.mux != nil && (r.mux != expected || r.muxGeneration != generation) {
		return ErrLegacyDataChannelReplaced
	}
	if err := preservedLegacyMuxCause(operationErr); err != nil {
		return err
	}
	if err := preservedLegacyMuxCause(terminalErr); err != nil {
		return err
	}
	if r.mux == nil {
		return ErrLegacyDataChannelUnavailable
	}
	if isLegacyTransportError(operationErr) || isLegacyTransportError(terminalErr) {
		return ErrLegacyDataChannelUnavailable
	}
	if operationErr != nil {
		return sanitizeLegacyMuxCause(operationErr)
	}
	if terminalErr != nil {
		return sanitizeLegacyMuxCause(terminalErr)
	}
	return nil
}

func joinLegacyErrors(primary, cleanup error) error {
	if primary != nil {
		return primary
	}
	return cleanup
}
