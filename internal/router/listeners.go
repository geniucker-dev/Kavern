package router

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const MaxAcceptedHandlers = 256
const MaxListeners = 1024
const PublicRouteTimeout = 5 * time.Minute

type ListenerSource interface {
	DesiredRoutes(context.Context) ([]domain.RouteView, error)
	ChangeSignal() <-chan struct{}
	Done() <-chan struct{}
	ReserveListener(context.Context, domain.TunnelID, domain.ListenerRef) (uint64, error)
	ListenerCurrent(context.Context, domain.TunnelID, uint64) bool
	RetireListener(domain.TunnelID, uint64)
}
type ListenerRouter interface {
	RouteListenerTCP(context.Context, domain.TunnelID, uint64, net.Conn) error
}
type ListenerStatus struct {
	TunnelID       domain.TunnelID
	DesiredAddress domain.ListenerRef
	BoundAddress   string
	Generation     uint64
	State          string
	RetryAt        time.Time
}
type listenerSpec struct {
	id       domain.TunnelID
	device   domain.DeviceID
	address  domain.ListenerRef
	protocol domain.TunnelProtocol
}
type liveListener struct {
	failed     atomic.Bool
	spec       listenerSpec
	generation uint64
	socket     net.Listener
	cancel     context.CancelFunc
	done       chan struct{}
	workers    sync.WaitGroup
}
type listenerFailure struct {
	id         domain.TunnelID
	generation uint64
}
type retryState struct {
	delay time.Duration
	at    time.Time
	spec  listenerSpec
	state string
}

// ListenerService owns public sockets only. No listener failure is a daemon-
// fatal control-service failure. One coordinator coalesces desired wakeups and
// retry timestamps; accept loops and handlers are bounded and joined.
type ListenerService struct {
	source              ListenerSource
	routes              ListenerRouter
	slots               chan struct{}
	listen              func(context.Context, string) (net.Listener, error)
	retryBase, retryMax time.Duration
	mu                  sync.Mutex
	running             bool
	started             chan struct{}
	status              map[domain.TunnelID]ListenerStatus
	changed             chan struct{}
	failures            chan listenerFailure
	failureWake         chan struct{}
}

func NewListenerService(source ListenerSource, routes ListenerRouter, slots chan struct{}) (*ListenerService, error) {
	if source == nil || routes == nil {
		return nil, errors.New("invalid listener service")
	}
	if slots == nil {
		slots = make(chan struct{}, MaxAcceptedHandlers)
	}
	if cap(slots) != MaxAcceptedHandlers {
		return nil, errors.New("invalid shared handler bound")
	}
	return &ListenerService{source: source, routes: routes, slots: slots, listen: func(ctx context.Context, address string) (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	}, retryBase: 100 * time.Millisecond, retryMax: 5 * time.Second, started: make(chan struct{}), status: make(map[domain.TunnelID]ListenerStatus), changed: make(chan struct{}), failures: make(chan listenerFailure, MaxListeners), failureWake: make(chan struct{}, 1)}, nil
}
func (s *ListenerService) Started() <-chan struct{} { return s.started }
func (s *ListenerService) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}
func (s *ListenerService) Status() []ListenerStatus {
	s.mu.Lock()
	result := make([]ListenerStatus, 0, len(s.status))
	for _, v := range s.status {
		result = append(result, v)
	}
	s.mu.Unlock()
	for i := range result {
		v := &result[i]
		if v.State == "bound" && !s.source.ListenerCurrent(context.Background(), v.TunnelID, v.Generation) {
			v.State = "pending"
			v.BoundAddress = ""
			v.Generation = 0
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TunnelID < result[j].TunnelID })
	return result
}
func (s *ListenerService) setStatus(next map[domain.TunnelID]ListenerStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	equal := len(next) == len(s.status)
	if equal {
		for id, v := range next {
			if v != s.status[id] {
				equal = false
				break
			}
		}
	}
	if !equal {
		s.status = next
		close(s.changed)
		s.changed = make(chan struct{})
	}
}
func (s *ListenerService) serve(ctx context.Context, l *liveListener, failures chan<- listenerFailure) {
	defer close(l.done)
	for {
		conn, err := l.socket.Accept()
		if err != nil {
			if ctx.Err() == nil {
				// Gate stale accepted handlers as soon as Accept fails, even if the
				// coordinator is currently waiting on another bounded bind.
				l.failed.Store(true)
				s.source.RetireListener(l.spec.id, l.generation)
				l.cancel()
				// The per-generation terminal flag is readiness truth. Notification
				// cannot delay cancellation or worker completion. A saturated queue
				// coalesces onto a reliable wakeup; reconcile scans every live flag.
				select {
				case failures <- listenerFailure{l.spec.id, l.generation}:
				default:
				}
				select {
				case s.failureWake <- struct{}{}:
				default:
				}
			}
			return
		}
		select {
		case s.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			defer func() { <-s.slots }()
			defer conn.Close()
			routeCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			callbackDone := make(chan struct{})
			stop := context.AfterFunc(routeCtx, func() { defer close(callbackDone); _ = conn.Close() })
			defer func() {
				if !stop() {
					<-callbackDone
				}
			}()
			_ = s.routes.RouteListenerTCP(routeCtx, l.spec.id, l.generation, conn)
		}()
	}
}
func (s *ListenerService) retire(l *liveListener) {
	s.source.RetireListener(l.spec.id, l.generation)
	l.cancel()
	_ = l.socket.Close()
	<-l.done
	l.workers.Wait()
}
func (s *ListenerService) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("listener service already started")
	}
	s.running = true
	s.mu.Unlock()
	live := make(map[domain.TunnelID]*liveListener)
	retries := make(map[domain.TunnelID]retryState)
	failures := s.failures
	defer func() {
		for _, l := range live {
			s.retire(l)
		}
		s.setStatus(map[domain.TunnelID]ListenerStatus{})
	}()
	desiredChanged := s.source.ChangeSignal()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	scheduleFailure := func(spec listenerSpec, state string) {
		r := retries[spec.id]
		if r.spec != spec {
			r = retryState{spec: spec}
		}
		if r.delay == 0 {
			r.delay = s.retryBase
		} else {
			r.delay *= 2
			if r.delay > s.retryMax {
				r.delay = s.retryMax
			}
		}
		r.state = state
		r.at = time.Now().Add(r.delay)
		retries[spec.id] = r
	}
	reconcile := func() error {
		views, err := s.source.DesiredRoutes(ctx)
		if err != nil {
			for id, l := range live {
				s.retire(l)
				delete(live, id)
			}
			clear(retries)
			// Uncertainty gates all owner admission. Wait for recovery/change rather
			// than spinning or serving a cached desired map.
			status := make(map[domain.TunnelID]ListenerStatus)
			for _, v := range s.Status() {
				v.State = "unavailable"
				v.BoundAddress = ""
				v.Generation = 0
				v.RetryAt = time.Time{}
				status[v.TunnelID] = v
			}
			s.setStatus(status)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		specs := make(map[domain.TunnelID]listenerSpec)
		status := make(map[domain.TunnelID]ListenerStatus, len(views))
		for _, v := range views {
			t := v.Tunnel
			state := "disabled"
			if v.Device.Enabled && t.Enabled {
				state = "pending"
				specs[t.ID] = listenerSpec{t.ID, v.Device.ID, t.Listener, t.Protocol}
			}
			status[t.ID] = ListenerStatus{TunnelID: t.ID, DesiredAddress: t.Listener, State: state}
		}
		if len(specs) > MaxListeners {
			return errors.New("public listener capacity exceeded")
		}
		for id, l := range live {
			spec, ok := specs[id]
			if !ok || spec != l.spec || l.failed.Load() || !s.source.ListenerCurrent(ctx, id, l.generation) {
				s.retire(l)
				delete(live, id)
				// Joining the accept loop also joins terminal flag publication, so
				// an invalidated binding cannot race this retry decision.
				if ok && spec == l.spec && l.failed.Load() {
					scheduleFailure(spec, "accept_failed")
				}
			}
		}
		for id, r := range retries {
			if spec, ok := specs[id]; !ok || spec != r.spec {
				delete(retries, id)
			}
		}
		for _, v := range views {
			id := v.Tunnel.ID
			spec, enabled := specs[id]
			if !enabled {
				continue
			}
			if l := live[id]; l != nil {
				status[id] = ListenerStatus{TunnelID: id, DesiredAddress: spec.address, BoundAddress: l.socket.Addr().String(), Generation: l.generation, State: "bound"}
				continue
			}
			if r, ok := retries[id]; ok && time.Now().Before(r.at) {
				status[id] = ListenerStatus{TunnelID: id, DesiredAddress: spec.address, State: r.state, RetryAt: r.at}
				continue
			}
			generation, err := s.source.ReserveListener(ctx, id, spec.address)
			if err != nil {
				scheduleFailure(spec, "bind_failed")
			} else {
				bindCtx, cancelBind := context.WithTimeout(ctx, 5*time.Second)
				socket, err := s.listen(bindCtx, string(spec.address))
				cancelBind()
				if err != nil {
					s.source.RetireListener(id, generation)
					scheduleFailure(spec, "bind_failed")
				} else if !s.source.ListenerCurrent(ctx, id, generation) {
					s.source.RetireListener(id, generation)
					_ = socket.Close()
					scheduleFailure(spec, "pending")
				} else {
					runCtx, cancel := context.WithCancel(ctx)
					l := &liveListener{spec: spec, generation: generation, socket: socket, cancel: cancel, done: make(chan struct{})}
					live[id] = l
					delete(retries, id)
					go s.serve(runCtx, l, failures)
					status[id] = ListenerStatus{TunnelID: id, DesiredAddress: spec.address, BoundAddress: socket.Addr().String(), Generation: generation, State: "bound"}
					continue
				}
			}
			r := retries[id]
			status[id] = ListenerStatus{TunnelID: id, DesiredAddress: spec.address, State: r.state, RetryAt: r.at}
		}
		s.setStatus(status)
		return nil
	}
	initial := true
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := reconcile(); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if initial {
			close(s.started)
			initial = false
		}
		var deadline time.Time
		for _, r := range retries {
			if deadline.IsZero() || r.at.Before(deadline) {
				deadline = r.at
			}
		}
		var tick <-chan time.Time
		if !deadline.IsZero() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(time.Until(deadline))
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			return nil
		case <-s.source.Done():
			return nil
		case <-desiredChanged:
			desiredChanged = s.source.ChangeSignal()
		case <-tick:
		case <-s.failureWake:
			// Reconcile consumes retained terminal flags even when the event queue
			// is full of older generations. No terminal failure is silently lost.
		case failed := <-failures:
			if l := live[failed.id]; l != nil && l.generation == failed.generation {
				s.retire(l)
				delete(live, failed.id)
				scheduleFailure(l.spec, "accept_failed")
			}
		}
	}
}
