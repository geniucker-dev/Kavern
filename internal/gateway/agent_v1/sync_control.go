package agent_v1

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

const syncControlQueue = 8

type NativeSnapshotSource interface {
	NativeSnapshot(context.Context, domain.DeviceID) (domain.NativeSnapshot, error)
}
type syncTiming struct{ transfer, write, idle, heartbeat time.Duration }

func defaultSyncTiming() syncTiming {
	return syncTiming{SyncTransferTimeout, SyncWriteTimeout, 30 * time.Second, 10 * time.Second}
}

// ConfigServer runs the authenticated snapshot/control coordinator. Renewable
// command sessions retain their exact session lease; schema-only cores remain
// available for standalone protocol tests and keep their absolute timeout.
type ConfigServer struct {
	service   *AuthService
	auth      SyncAuthResult
	source    NativeSnapshotSource
	budget    *SyncStagingBudget
	updates   chan struct{}
	mu        sync.Mutex
	running   bool
	applied   domain.ConfigRevision
	timing    syncTiming
	lifecycle *ServerLease
}

func (s *AuthService) NewConfigServer(ctx context.Context, auth SyncAuthResult, source NativeSnapshotSource, budget *SyncStagingBudget) (*ConfigServer, error) {
	if source == nil {
		return nil, ErrInvalidInput
	}
	var lease *ServerLease
	if err := s.withSyncSession(ctx, auth, func() error {
		entry, ok := s.registry.lookup(auth.SessionID)
		if !ok {
			return ErrSessionNotFound
		}
		entry.session.mu.Lock()
		defer entry.session.mu.Unlock()
		if entry.session.syncData != nil {
			return ErrInvalidInput
		}
		lease = entry.session.lifecycle
		entry.session.syncData = &syncSessionData{service: s, auth: auth, source: source, changed: make(chan struct{})}
		return nil
	}); err != nil {
		return nil, err
	}
	if budget == nil {
		budget = processSyncBudget
	}
	return &ConfigServer{service: s, auth: auth, source: source, budget: budget, updates: make(chan struct{}, 1), timing: defaultSyncTiming(), lifecycle: lease}, nil
}

// Notifications are wakeups. The owned source is re-read and remains truth.
func (s *ConfigServer) NotifyDesired() {
	select {
	case s.updates <- struct{}{}:
	default:
	}
}
func (s *ConfigServer) AppliedRevision(ctx context.Context) (domain.ConfigRevision, error) {
	var revision domain.ConfigRevision
	err := s.service.withSyncSession(ctx, s.auth, func() error { s.mu.Lock(); revision = s.applied; s.mu.Unlock(); return nil })
	return revision, err
}

type syncRead struct {
	frame     syncFrame
	lifecycle *LifecycleFrame
	bytes     int
	err       error
	started   time.Time
}
type syncFlight struct {
	plan     *syncPlan
	next     int
	deadline time.Time
	release  func()
}

func sameSnapshot(a, b domain.NativeSnapshot) bool {
	if a.DeviceID != b.DeviceID || a.Revision != b.Revision || a.Policy != b.Policy || len(a.Tunnels) != len(b.Tunnels) {
		return false
	}
	for i := range a.Tunnels {
		if a.Tunnels[i] != b.Tunnels[i] {
			return false
		}
	}
	return true
}

func (s *ConfigServer) Run(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return ErrInvalidInput
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrInvalidInput
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.applied = 0
		s.mu.Unlock()
		_ = s.service.CloseSession(context.Background(), s.auth.SessionID)
	}()
	if err := s.service.withSyncSession(ctx, s.auth, func() error { return nil }); err != nil {
		_ = conn.Close()
		return err
	}
	entry, ok := s.service.registry.lookup(s.auth.SessionID)
	if !ok {
		_ = conn.Close()
		return ErrSessionNotFound
	}
	// Negotiated lifecycle owns expiry. Standalone schema-only sessions retain
	// their historical absolute session timeout.
	sessionCtx, cancel := context.WithCancel(ctx)
	if s.auth.LifecycleVersion == 0 {
		cancel()
		sessionCtx, cancel = context.WithTimeout(ctx, entry.session.expiresAt.Sub(s.service.now()))
	}
	defer cancel()
	return runConfigControl(sessionCtx, conn, s, nil, entry.session.Done(), s.timing)
}
func (r *ConfigReceiver) Run(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return ErrInvalidInput
	}
	r.mu.Lock()
	if r.running || r.closed || (r.auth.LifecycleVersion != 0 && r.lifecycle == nil) {
		r.mu.Unlock()
		return ErrSessionClosed
	}
	r.running = true
	r.mu.Unlock()
	return runConfigControl(ctx, conn, nil, r, nil, defaultSyncTiming())
}

func syncReader(ctx context.Context, conn net.Conn, inbox chan<- syncRead, done chan<- struct{}, timing syncTiming, negotiated ...int) {
	lifecycle := 0
	if len(negotiated) > 0 {
		lifecycle = negotiated[0]
	}
	defer close(done)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timing.idle)); err != nil {
			select {
			case inbox <- syncRead{err: err}:
			case <-ctx.Done():
			}
			return
		}
		// Idle waiting is separate from progress inside a frame. Start the
		// transfer clock at its first byte, not delayed dispatcher processing.
		var prefix [4]byte
		_, err := io.ReadFull(conn, prefix[:1])
		started := time.Now()
		if err == nil {
			err = conn.SetReadDeadline(started.Add(timing.write))
		}
		if err == nil {
			_, err = io.ReadFull(conn, prefix[1:])
		}
		var f syncFrame
		var life *LifecycleFrame
		size := 0
		if err == nil {
			n := binary.BigEndian.Uint32(prefix[:])
			if n == 0 || n > MaxControlFrameBytes {
				err = ErrSyncTransfer
			} else {
				data := make([]byte, int(n))
				_, err = io.ReadFull(conn, data)
				if err == nil {
					if lifecycle == LifecycleVersion {
						var kind struct {
							Type string `json:"type"`
						}
						_ = json.Unmarshal(data, &kind)
						if strings.HasPrefix(kind.Type, "renew_") {
							var v LifecycleFrame
							v, err = DecodeLifecycleFrame(data)
							life = &v
						} else {
							f, err = decodeLifecycleSyncPayload(data)
						}
					} else {
						f, err = decodeSyncPayload(data)
					}
					size = len(data)
				}
			}
		}
		timer := time.NewTimer(timing.write)
		select {
		case inbox <- syncRead{frame: f, lifecycle: life, bytes: size, err: err, started: started}:
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			_ = conn.Close()
			return
		}
		timer.Stop()
		if err != nil {
			return
		}
	}
}

// The coordinator is the only writer and state dispatcher. Its one reader
// produces at most eight queued frames. Between generated snapshot entries,
// queued heartbeat/ACK events are serviced before the next entry is written.
func runConfigControl(parent context.Context, conn net.Conn, server *ConfigServer, receiver *ConfigReceiver, sessionDone <-chan struct{}, timing syncTiming) error {
	ctx, cancel := context.WithCancel(parent)
	// Replacement must interrupt an in-progress write, not wait for the next
	// coordinator select or the five-second write deadline.
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		select {
		case <-sessionDone:
			cancel()
		case <-ctx.Done():
		}
	}()
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(callbackDone); _ = conn.Close() })
	inbox := make(chan syncRead, syncControlQueue)
	readerDone := make(chan struct{})
	var lifeVersion int
	var serverLease *ServerLease
	var clientLease *ClientLease
	var lifeWake, lifeDone <-chan struct{}
	if server != nil {
		lifeVersion = server.auth.LifecycleVersion
		if lifeVersion != 0 {
			serverLease = server.lifecycle
			lifeWake = serverLease.Wake()
			lifeDone = serverLease.Done()
		}
	} else {
		lifeVersion = receiver.auth.LifecycleVersion
		clientLease = receiver.lifecycle
		if clientLease != nil {
			lifeWake = clientLease.Wake()
			lifeDone = clientLease.Done()
		}
	}
	if lifeVersion != 0 && serverLease == nil && clientLease == nil {
		cancel()
		_ = conn.Close()
		return ErrLifecycle
	}
	leaseMonitorDone := make(chan struct{})
	go func() {
		defer close(leaseMonitorDone)
		select {
		case <-lifeDone:
			cancel()
		case <-ctx.Done():
		}
	}()
	go syncReader(ctx, conn, inbox, readerDone, timing, lifeVersion)
	defer func() {
		cancel()
		_ = conn.Close()
		if !stop() {
			<-callbackDone
		}
		<-readerDone
		<-monitorDone
		<-leaseMonitorDone
		if serverLease != nil {
			serverLease.Revoke(nil)
		}
		if clientLease != nil {
			clientLease.Revoke(nil)
		}
		if receiver != nil {
			receiver.Close()
		}
	}()
	var auth SyncAuthResult
	if server != nil {
		auth = server.auth
	} else {
		auth = receiver.auth
	}
	var flight *syncFlight
	defer func() {
		if flight != nil {
			flight.release()
		}
	}()
	var pendingReady *syncReadyRequest
	defer func() {
		if pendingReady != nil {
			pendingReady.result <- ErrSessionClosed
		}
	}()
	var lastTuple syncTuple
	var lastSnapshot domain.NativeSnapshot
	var counter domain.ConfigRevision
	var readyRequests <-chan syncReadyRequest
	if receiver != nil {
		readyRequests = receiver.readyRequests
	}
	var desiredChanged <-chan struct{}
	var desiredSource interface{ ChangeSignal() <-chan struct{} }
	if server != nil {
		desiredSource, _ = server.source.(interface{ ChangeSignal() <-chan struct{} })
		if desiredSource == nil {
			desiredSource, _ = server.service.store.(interface{ ChangeSignal() <-chan struct{} })
		}
		if desiredSource != nil {
			desiredChanged = desiredSource.ChangeSignal()
		}
	}
	var updates <-chan struct{}
	if server != nil {
		updates = server.updates
	}
	phaseDeadline := func() time.Time {
		if pendingReady != nil {
			if deadline, ok := pendingReady.ctx.Deadline(); ok {
				return deadline
			}
		}
		if flight != nil {
			return flight.deadline
		}
		if receiver != nil {
			return receiver.deadline()
		}
		return time.Time{}
	}
	write := func(f syncFrame) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline := time.Now().Add(timing.write)
		phase := phaseDeadline()
		if !phase.IsZero() {
			deadline = minTime(deadline, phase)
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		data, err := encodeNegotiatedSyncPayload(f, lifeVersion)
		if err == nil {
			err = writeControlPayload(conn, data)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !phase.IsZero() && !time.Now().Before(phase) {
				return ErrSyncDeadline
			}
		}
		return err
	}
	writeLife := func(f *LifecycleFrame) error {
		if f == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := conn.SetWriteDeadline(time.Now().Add(timing.write)); err != nil {
			return err
		}
		return WriteLifecycleFrame(conn, *f)
	}
	pollLife := func() error {
		var f *LifecycleFrame
		var e error
		if serverLease != nil {
			f, e = serverLease.Poll(ctx)
		} else if clientLease != nil {
			f, e = clientLease.Poll()
		}
		if errors.Is(e, ErrLifecycleStale) {
			return nil
		}
		if e != nil {
			return e
		}
		return writeLife(f)
	}
	startLatest := func() error {
		if server == nil || flight != nil {
			return nil
		}
		if err := server.service.withSyncSession(ctx, auth, func() error { return nil }); err != nil {
			return err
		}
		fetch, cancelFetch := context.WithTimeout(ctx, timing.transfer)
		snapshot, err := server.source.NativeSnapshot(fetch, auth.DeviceID)
		cancelFetch()
		if err != nil {
			return err
		}
		if lastSnapshot.Revision != 0 {
			if snapshot.Revision < lastSnapshot.Revision {
				return ErrSyncStale
			}
			if snapshot.Revision == lastSnapshot.Revision {
				if !sameSnapshot(snapshot, lastSnapshot) {
					return ErrSyncStale
				}
				return nil
			}
			// This checkpoint never resizes or migrates a carrier pool in place.
			if snapshot.Policy != lastSnapshot.Policy {
				return ErrSyncNotReady
			}
		}
		if counter == domain.ConfigRevision(math.MaxUint64) {
			return ErrSyncTransfer
		}
		counter++
		plan, err := newSyncPlan(auth, snapshot, counter)
		if err != nil {
			return err
		}
		release, err := server.budget.reserve(plan.total)
		if err != nil {
			return err
		}
		if err = server.service.withSyncSession(ctx, auth, func() error {
			entry, _ := server.service.registry.lookup(auth.SessionID)
			entry.session.syncController().install(plan.tuple, plan.snapshot)
			return nil
		}); err != nil {
			release()
			return err
		}
		flight = &syncFlight{plan: plan, deadline: time.Now().Add(timing.transfer), release: release}
		return nil
	}
	if server != nil {
		if err := startLatest(); err != nil {
			return err
		}
	}
	handle := func(event syncRead) error {
		if event.err != nil {
			return event.err
		}
		if event.lifecycle != nil {
			var reply *LifecycleFrame
			var e error
			if serverLease != nil {
				if event.lifecycle.Type != "renew_response" {
					return ErrLifecycle
				}
				reply, e = serverLease.AcceptProof(ctx, *event.lifecycle)
			} else if clientLease != nil {
				switch event.lifecycle.Type {
				case "renew_challenge":
					reply, e = clientLease.Challenge(*event.lifecycle)
				case "renew_ok":
					e = clientLease.Grant(*event.lifecycle)
				default:
					return ErrLifecycle
				}
			} else {
				return ErrLifecycle
			}
			if errors.Is(e, ErrLifecycleStale) {
				return nil
			}
			if e != nil {
				return e
			}
			return writeLife(reply)
		}
		f := event.frame
		if f.DeviceID != auth.DeviceID || f.SessionID != auth.SessionID {
			return ErrSyncStale
		}
		if server != nil {
			if err := server.service.withSyncSession(ctx, auth, func() error { return nil }); err != nil {
				return err
			}
			if f.Type == "ping" {
				return write(heartbeatFrame("pong", auth))
			}
			if f.Type == "ready" {
				if err := server.service.markSyncReady(ctx, auth, f.tuple(), int(*f.CarrierCount)); err != nil {
					return err
				}
				reply := scopedFrame("ready_ok", f.tuple())
				reply.CarrierCount = f.CarrierCount
				return write(reply)
			}
			if f.Type != "config_ack" {
				return ErrSyncTransfer
			}
			if f.tuple() == lastTuple && lastTuple.Revision != 0 {
				return nil
			}
			if flight == nil || f.tuple() != flight.plan.tuple || flight.next != flight.plan.frames() {
				return ErrSyncStale
			}
			if !time.Now().Before(flight.deadline) {
				return ErrSyncDeadline
			}
			if err := server.service.withSyncSession(ctx, auth, func() error {
				entry, _ := server.service.registry.lookup(auth.SessionID)
				if err := entry.session.syncController().ack(f.tuple()); err != nil {
					return err
				}
				server.mu.Lock()
				server.applied = f.tuple().Revision
				server.mu.Unlock()
				return nil
			}); err != nil {
				return err
			}
			lastTuple, lastSnapshot = f.tuple(), flight.plan.snapshot
			flight.release()
			flight = nil
			return startLatest()
		}
		if f.Type == "ready_ok" {
			if pendingReady == nil || pendingReady.tuple != f.tuple() || pendingReady.ctx.Err() != nil {
				return ErrSyncStale
			}
			if err := receiver.acceptReady(f.tuple(), int(*f.CarrierCount)); err != nil {
				return err
			}
			pendingReady.result <- nil
			pendingReady = nil
			return nil
		}
		if f.Type == "pong" {
			return nil
		}
		ack, err := receiver.acceptAt(f, event.bytes, event.started)
		if err != nil {
			return err
		}
		if ack != nil {
			if err = write(*ack); err != nil {
				return err
			}
			receiver.ackSent()
		}
		return nil
	}
	ticker := time.NewTicker(timing.heartbeat)
	defer ticker.Stop()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		if clientLease != nil {
			if e := clientLease.Valid(); e != nil {
				return e
			}
		}
		if e := pollLife(); e != nil {
			return e
		}
		deadline := phaseDeadline()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return ErrSyncDeadline
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sessionDone:
			return ErrSessionClosed
		default:
		}
		// Poll first so ping/pong can interleave with the bounded transfer.
		select {
		case event := <-inbox:
			if err := handle(event); err != nil {
				return err
			}
			continue
		default:
		}
		if flight != nil && flight.next < flight.plan.frames() {
			if err := write(flight.plan.frame(flight.next)); err != nil {
				return err
			}
			flight.next++
			continue
		}
		select {
		case <-readerDone:
			return io.EOF
		default:
		}
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sessionDone:
			return ErrSessionClosed
		case <-lifeDone:
			return ErrLifecycleExpired
		case <-lifeWake:
			if e := pollLife(); e != nil {
				return e
			}
		case <-timeout:
			return ErrSyncDeadline
		case event := <-inbox:
			if err := handle(event); err != nil {
				return err
			}
		case <-readerDone:
			// A final error may already be queued; it cannot advance state.
			select {
			case event := <-inbox:
				if event.err != nil {
					return event.err
				}
				return io.EOF
			default:
				return io.EOF
			}
		case req := <-readyRequests:
			if pendingReady != nil || req.ctx.Err() != nil {
				req.result <- ErrSyncNotReady
				continue
			}
			pendingReady = &req
			frame := scopedFrame("ready", req.tuple)
			count := uint8(req.count)
			frame.CarrierCount = &count
			if err := write(frame); err != nil {
				return err
			}
		case <-desiredChanged:
			desiredChanged = desiredSource.ChangeSignal()
			if err := startLatest(); err != nil {
				return err
			}
		case <-updates:
			if err := startLatest(); err != nil {
				return err
			}
		case <-ticker.C:
			if server != nil {
				if err := server.service.withSyncSession(ctx, auth, func() error { return nil }); err != nil {
					return err
				}
			} else {
				if err := write(heartbeatFrame("ping", auth)); err != nil {
					return err
				}
			}
		}
	}
}
