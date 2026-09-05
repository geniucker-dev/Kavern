package legacy_npc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type LegacyNpcSession struct {
	id       domain.SessionID
	deviceID domain.DeviceID
	main     net.Conn
	store    LegacyStore
	runtime  *legacyDeviceRuntime
	lease    *legacyRuntimeLease

	mu              sync.Mutex
	closed          bool
	done            chan struct{}
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	operations      sync.WaitGroup
	mainMonitorDone chan struct{}
	monitorStarted  bool
	closeOnce       sync.Once
	closeErr        error
}

func newSession(id domain.SessionID, deviceID domain.DeviceID, main net.Conn, store LegacyStore, runtime *legacyDeviceRuntime, lease *legacyRuntimeLease) *LegacyNpcSession {
	return newSessionWithContext(context.Background(), id, deviceID, main, store, runtime, lease)
}

func newSessionWithContext(parent context.Context, id domain.SessionID, deviceID domain.DeviceID, main net.Conn, store LegacyStore, runtime *legacyDeviceRuntime, lease *legacyRuntimeLease) *LegacyNpcSession {
	lifecycleCtx, lifecycleCancel := context.WithCancel(parent)
	s := &LegacyNpcSession{
		id:              id,
		deviceID:        deviceID,
		main:            main,
		store:           store,
		runtime:         runtime,
		lease:           lease,
		done:            make(chan struct{}),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		mainMonitorDone: make(chan struct{}),
	}
	context.AfterFunc(lifecycleCtx, func() {
		if main != nil {
			_ = main.Close()
		}
	})
	return s
}

func (s *LegacyNpcSession) startMainMonitor() error {
	s.mu.Lock()
	if s.monitorStarted || s.main == nil {
		s.mu.Unlock()
		return ErrLegacyRuntimeInvariant
	}
	s.monitorStarted = true
	main := s.main
	done := s.mainMonitorDone
	s.mu.Unlock()
	go func() {
		defer close(done)
		var buf [1]byte
		for {
			if _, err := main.Read(buf[:]); err != nil {
				s.cancelLifecycleFromMainMonitor()
				return
			}
		}
	}()
	return nil
}

func (s *LegacyNpcSession) cancelLifecycleFromMainMonitor() {
	s.lifecycleCancel()
	if s.runtime != nil {
		s.runtime.mu.Lock()
		s.runtime.notifyMainStateLocked()
		s.runtime.mu.Unlock()
	}
}

func (s *LegacyNpcSession) waitMainMonitor() {
	s.mu.Lock()
	started := s.monitorStarted
	done := s.mainMonitorDone
	s.mu.Unlock()
	if started {
		<-done
	}
}

func (s *LegacyNpcSession) lifecycleActiveLocked() bool {
	return !s.closed && s.lifecycleCtx.Err() == nil
}

func (s *LegacyNpcSession) ID() domain.SessionID {
	return s.id
}

func (s *LegacyNpcSession) DeviceID() domain.DeviceID {
	return s.deviceID
}

func (s *LegacyNpcSession) Protocol() domain.AgentProtocol {
	return domain.AgentProtocolLegacyNPC
}

func (s *LegacyNpcSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.TunnelID == "" || req.TargetAddr != "" || req.Protocol != domain.TunnelProtocolTCP {
		return nil, ErrLegacyInvalidStreamRequest
	}
	opCtx, finish, err := s.beginOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()

	tunnel, err := s.store.GetTunnel(opCtx, req.TunnelID)
	if err != nil {
		return nil, s.mapPreMuxOperationError(ctx, err)
	}
	device, err := s.store.GetDevice(opCtx, s.deviceID)
	if err != nil {
		return nil, s.mapPreMuxOperationError(ctx, err)
	}
	if !tunnel.Enabled {
		return nil, ErrLegacyTunnelDisabled
	}
	if !device.Enabled {
		return nil, ErrLegacyDeviceDisabled
	}
	if device.ID != s.deviceID || tunnel.DeviceID != s.deviceID {
		return nil, ErrLegacyTunnelDeviceMismatch
	}
	if normalizeLegacyTunnelProtocol(tunnel.Protocol) != domain.TunnelProtocolTCP {
		return nil, ErrLegacyUnsupportedTunnelProtocol
	}

	metadata, err := encodeLegacyLinkMetadata(tunnel.TargetAddr, req.RemoteAddr)
	if err != nil {
		return nil, err
	}
	mux, generation, err := s.snapshotMux()
	if err != nil {
		return nil, err
	}
	stream, err := mux.OpenStream(opCtx)
	if err != nil {
		return nil, s.mapMuxOperationError(ctx, mux, generation, err)
	}
	if err := s.mapMuxOperationError(ctx, mux, generation, nil); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if err := writeLegacyLinkMetadata(opCtx, stream, metadata); err != nil {
		_ = stream.Close()
		return nil, s.mapMuxOperationError(ctx, mux, generation, err)
	}
	if err := s.mapMuxOperationError(ctx, mux, generation, nil); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

func (s *LegacyNpcSession) Close(ctx context.Context) error {
	ctxErr := ctx.Err()
	s.closeOnce.Do(func() {
		var main net.Conn
		var mux *LegacyMux
		if s.runtime != nil {
			s.runtime.mu.Lock()
		}
		s.mu.Lock()
		s.closed = true
		close(s.done)
		s.lifecycleCancel()
		main = s.main
		s.main = nil
		if s.runtime != nil {
			changed := false
			if s.runtime.currentMain == s {
				s.runtime.currentMain = nil
				changed = true
			}
			if s.runtime.attachedMain == s {
				s.runtime.attachedMain = nil
				changed = true
			}
			if changed {
				s.runtime.notifyMainStateLocked()
			}
			if !s.runtime.hasMainInterestLocked() {
				mux = s.runtime.detachMuxLocked()
			}
		}
		s.mu.Unlock()
		if s.runtime != nil {
			s.runtime.mu.Unlock()
		}

		if main != nil {
			_ = main.Close()
		}
		if mux != nil {
			_ = mux.Close()
		}
		s.operations.Wait()
		s.waitMainMonitor()
		if s.lease != nil {
			s.closeErr = s.lease.Release()
		}
	})
	return joinLegacyErrors(ctxErr, s.closeErr)
}

func (s *LegacyNpcSession) Done() <-chan struct{} {
	return s.done
}

func (s *LegacyNpcSession) installMux(incoming *LegacyMux) (uint64, *LegacyMux, error) {
	if s.runtime == nil {
		return 0, nil, ErrLegacyDataChannelUnavailable
	}
	return s.runtime.installMux(incoming)
}

func (s *LegacyNpcSession) clearMuxIfCurrent(expected *LegacyMux, generation uint64) bool {
	return s.runtime != nil && s.runtime.clearMuxIfCurrent(expected, generation)
}

func (s *LegacyNpcSession) snapshotMux() (*LegacyMux, uint64, error) {
	if s.runtime == nil {
		return nil, 0, ErrLegacyDataChannelUnavailable
	}
	return s.runtime.snapshotMuxForSession(s)
}

func (s *LegacyNpcSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lifecycleActiveLocked()
}

func (s *LegacyNpcSession) mapMuxOperationError(ctx context.Context, expected *LegacyMux, generation uint64, operationErr error) error {
	if s.runtime == nil {
		return ErrLegacyDataChannelUnavailable
	}
	return s.runtime.mapMuxOperationError(ctx, s, expected, generation, operationErr)
}

func (s *LegacyNpcSession) beginOperation(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.runtime == nil {
		return nil, nil, ErrLegacySessionClosed
	}
	s.runtime.mu.Lock()
	s.mu.Lock()
	if !s.lifecycleActiveLocked() || s.runtime.currentMain != s {
		s.mu.Unlock()
		s.runtime.mu.Unlock()
		return nil, nil, ErrLegacySessionClosed
	}
	s.operations.Add(1)
	lifecycleCtx := s.lifecycleCtx
	s.mu.Unlock()
	s.runtime.mu.Unlock()

	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(lifecycleCtx, cancel)
	finish := func() {
		stop()
		cancel()
		s.operations.Done()
	}
	return opCtx, finish, nil
}

func (s *LegacyNpcSession) mapPreMuxOperationError(ctx context.Context, operationErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.runtime == nil {
		return ErrLegacySessionClosed
	}
	s.runtime.mu.Lock()
	defer s.runtime.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lifecycleActiveLocked() || s.runtime.currentMain != s {
		return ErrLegacySessionClosed
	}
	return operationErr
}

func normalizeLegacyTunnelProtocol(protocol domain.TunnelProtocol) domain.TunnelProtocol {
	if protocol == "" {
		return domain.TunnelProtocolTCP
	}
	return protocol
}

func preservedLegacyMuxCause(err error) error {
	for _, candidate := range []error{
		ErrLegacyProtocol,
		ErrLegacyReceiveLimit,
		ErrLegacyPingTimeout,
		ErrLegacyStreamRejected,
		ErrLegacyStreamLimit,
		ErrLegacyTombstoneLimit,
		ErrLegacyIDExhausted,
		context.DeadlineExceeded,
	} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return nil
}

func isLegacyTransportError(err error) bool {
	if err == nil {
		return false
	}
	var operationErr *net.OpError
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, ErrLegacyMuxClosed) || errors.As(err, &operationErr)
}

func sanitizeLegacyMuxCause(err error) error {
	if err == nil {
		return nil
	}
	for _, candidate := range []error{
		ErrLegacyStreamClosed,
		ErrLegacyLinkMetadataWrite,
		ErrLegacyInvalidStreamRequest,
		ErrLegacyProtocol,
		ErrLegacyReceiveLimit,
		ErrLegacyPingTimeout,
		ErrLegacyStreamRejected,
		ErrLegacyStreamLimit,
		ErrLegacyTombstoneLimit,
		ErrLegacyIDExhausted,
		context.DeadlineExceeded,
	} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return ErrLegacyDataChannelUnavailable
}

func classifyLegacyMuxTerminalCause(err error) error {
	if preserved := preservedLegacyMuxCause(err); preserved != nil {
		return preserved
	}
	if isLegacyTransportError(err) || err == nil {
		return ErrLegacyDataChannelUnavailable
	}
	return sanitizeLegacyMuxCause(err)
}

var _ session.AgentSession = (*LegacyNpcSession)(nil)
