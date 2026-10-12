package legacy_npc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type LegacyStore interface {
	ResolveLegacyDeviceForAuth(ctx context.Context, lookupKey string) (domain.Device, error)
	GetDevice(ctx context.Context, id domain.DeviceID) (domain.Device, error)
	GetTunnel(ctx context.Context, id domain.TunnelID) (domain.Tunnel, error)
}

type Config struct {
	ServerSecret      []byte
	Store             LegacyStore
	Sessions          session.SessionManager
	MuxConfig         LegacyMuxConfig
	HandshakeTimeout  time.Duration
	MaxHandshakeBytes int
	NewSessionID      func() (domain.SessionID, error)
}

type Gateway struct {
	store             LegacyStore
	sessions          session.SessionManager
	serverSecret      []byte
	handshakeTimeout  time.Duration
	maxHandshakeBytes int
	newSessionID      func() (domain.SessionID, error)
	muxConfig         LegacyMuxConfig

	runtimeMu sync.Mutex
	runtimes  map[domain.DeviceID]*legacyRuntimeEntry
}

func New(cfg Config) (*Gateway, error) {
	if len(cfg.ServerSecret) == 0 || cfg.Store == nil || cfg.Sessions == nil {
		return nil, ErrInvalidConfig
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	maxHandshakeBytes := cfg.MaxHandshakeBytes
	if maxHandshakeBytes <= 0 {
		maxHandshakeBytes = defaultMaxHandshakeBytes
	}
	newSessionID := cfg.NewSessionID
	if newSessionID == nil {
		newSessionID = generateSessionID
	}
	muxConfig, err := normalizeLegacyMuxConfig(cfg.MuxConfig)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		store:             cfg.Store,
		sessions:          cfg.Sessions,
		serverSecret:      append([]byte(nil), cfg.ServerSecret...),
		handshakeTimeout:  timeout,
		maxHandshakeBytes: maxHandshakeBytes,
		newSessionID:      newSessionID,
		muxConfig:         muxConfig,
		runtimes:          make(map[domain.DeviceID]*legacyRuntimeEntry),
	}, nil
}

func (g *Gateway) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return ErrInvalidConfig
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	listenerStopped := make(chan struct{})
	stopListener := context.AfterFunc(ctx, func() { defer close(listenerStopped); _ = listener.Close() })
	defer func() {
		cancel()
		if !stopListener() {
			<-listenerStopped
		}
		_ = listener.Close()
		workers.Wait()
	}()
	slots := make(chan struct{}, 256)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			stopped := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { defer close(stopped); _ = conn.Close() })
			defer func() {
				if !stop() {
					<-stopped
				}
			}()
			_ = g.ServeConn(ctx, conn)
		}()
	}
}

func (g *Gateway) ServeConn(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return ErrInvalidConfig
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	result, err := g.readHandshake(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if owner, ok := g.store.(legacyOwner); ok {
		lease, err := owner.AcquireLegacyInterest(ctx, result.deviceID, result.lookupKey)
		if err != nil {
			_ = conn.Close()
			return err
		}
		defer lease.Finish()
		ctx = context.WithValue(lease.Context, legacyCredentialContextKey{}, result.lookupKey)
		stopped := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(stopped); _ = conn.Close() })
		defer func() {
			if !stop() {
				<-stopped
			}
		}()
	}
	switch result.connType {
	case connTypeMain:
		return g.serveMain(ctx, conn, result.deviceID)
	case connTypeChan:
		return g.serveChan(ctx, conn, result.deviceID)
	default:
		_ = conn.Close()
		return ErrUnsupportedConnection
	}
}

func (g *Gateway) serveMain(ctx context.Context, conn net.Conn, deviceID domain.DeviceID) (resultErr error) {
	transitionLease, sessionLease := g.acquireMainRuntime(deviceID)
	defer func() {
		resultErr = joinLegacyErrors(resultErr, transitionLease.Release())
	}()
	runtime := transitionLease.Runtime()
	sessionID, err := g.newSessionID()
	if err != nil || sessionID == "" {
		if err == nil {
			err = ErrInvalidHandshake
		}
		muxToClose, finishErr := runtime.finishUnpublishedMainTransition()
		_ = conn.Close()
		if muxToClose != nil {
			_ = muxToClose.Close()
		}
		releaseErr := sessionLease.Release()
		return joinLegacyErrors(finishErr, joinLegacyErrors(releaseErr, err))
	}
	legacySession := newSessionWithContext(ctx, sessionID, deviceID, conn, g.store, runtime, sessionLease)
	if err := legacySession.startMainMonitor(); err != nil {
		muxToClose, finishErr := runtime.finishUnpublishedMainTransition()
		_ = legacySession.Close(context.Background())
		if muxToClose != nil {
			_ = muxToClose.Close()
		}
		return joinLegacyErrors(finishErr, err)
	}
	if !runtime.mainTransitionSessionLive(legacySession) {
		muxToClose, finishErr := runtime.finishUnpublishedMainTransition()
		_ = legacySession.Close(context.Background())
		if muxToClose != nil {
			_ = muxToClose.Close()
		}
		return joinLegacyErrors(finishErr, ctx.Err())
	}

	runtime.mainTransitionMu.Lock()
	priorCurrent, priorAttached, published := runtime.publishMainCandidate(legacySession)
	if !published {
		muxToClose, finishErr := runtime.finishUnpublishedMainTransition()
		runtime.mainTransitionMu.Unlock()
		_ = legacySession.Close(context.Background())
		if muxToClose != nil {
			_ = muxToClose.Close()
		}
		return joinLegacyErrors(finishErr, ctx.Err())
	}
	var attachErr error
	if _, owned := g.store.(legacyOwner); owned {
		publisher, ok := g.sessions.(interface {
			Publish(context.Context, session.AgentSession) (session.AgentSession, error)
		})
		if !ok {
			attachErr = ErrInvalidConfig
		} else {
			var replaced session.AgentSession
			attachErr = g.withPublication(legacySession.lifecycleCtx, deviceID, func() error {
				var err error
				replaced, err = publisher.Publish(legacySession.lifecycleCtx, legacySession)
				return err
			})
			if attachErr == nil {
				// Revocation must close/detach this publication before predecessor close can block.
				stopped := make(chan struct{})
				stop := context.AfterFunc(legacySession.lifecycleCtx, func() {
					defer close(stopped)
					_ = legacySession.Close(context.Background())
					_ = g.detachSessionForCleanup(context.Background(), sessionID)
				})
				defer func() {
					if !stop() {
						<-stopped
					}
				}()
				if replaced != nil {
					_ = replaced.Close(context.Background())
				}
			}
		}
	} else {
		attachErr = g.sessions.Attach(legacySession.lifecycleCtx, legacySession)
	}
	managerCurrent, currentErr := g.currentSessionForCleanup(ctx, deviceID)
	if attachErr != nil {
		lifecycleCanceled := legacySession.lifecycleCtx.Err() != nil
		muxToClose, reconcileErr := runtime.reconcileFailedAttach(legacySession, priorCurrent, priorAttached, observeManager(managerCurrent, currentErr))
		runtime.mainTransitionMu.Unlock()
		_ = legacySession.Close(context.Background())
		if muxToClose != nil {
			_ = muxToClose.Close()
		}
		if reconcileErr != nil {
			return reconcileErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if lifecycleCanceled {
			return nil
		}
		return attachErr
	}
	committed := false
	var commitErr error
	if currentErr == nil {
		committed, commitErr = runtime.commitAttachedMain(ctx, legacySession, managerCurrent)
	}
	if !committed {
		managerStillExpected := currentErr == nil && sameAgentSession(managerCurrent, legacySession)
		muxToClose, reconcileErr := runtime.reconcileFailedMain(legacySession, priorCurrent, priorAttached, managerCurrent)
		runtime.mainTransitionMu.Unlock()
		_ = legacySession.Close(context.Background())
		_ = g.detachSessionForCleanup(ctx, sessionID)
		if muxToClose != nil {
			_ = muxToClose.Close()
		}
		if commitErr != nil {
			return commitErr
		}
		if reconcileErr != nil {
			return reconcileErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if currentErr != nil {
			return currentErr
		}
		if managerStillExpected {
			return nil
		}
		return errLegacyMainSuperseded
	}
	runtime.mainTransitionMu.Unlock()
	if err := transitionLease.Release(); err != nil {
		return err
	}
	transitionLease = nil

	defer func() {
		_ = legacySession.Close(context.Background())
		_ = g.detachSessionForCleanup(ctx, sessionID)
	}()
	legacySession.waitMainMonitor()
	return nil
}

func (g *Gateway) serveChan(ctx context.Context, conn net.Conn, deviceID domain.DeviceID) (resultErr error) {
	lease := g.acquireRuntime(deviceID, legacyRuntimeLeaseChan)
	defer func() {
		resultErr = joinLegacyErrors(resultErr, lease.Release())
	}()
	runtime := lease.Runtime()
	mux, err := NewLegacyMux(conn, g.muxConfig)
	if err != nil {
		_ = conn.Close()
		return err
	}
	var generation uint64
	var oldMux *LegacyMux
	err = g.withPublication(ctx, deviceID, func() error {
		var installErr error
		generation, oldMux, installErr = runtime.installMux(mux)
		return installErr
	})
	if err != nil {
		if errors.Is(err, ErrLegacyMuxAlreadyInstalled) {
			return err
		}
		closed, terminalErr := mux.terminalErrorSnapshot()
		_ = mux.Close()
		if closed && errors.Is(classifyLegacyMuxTerminalCause(terminalErr), ErrLegacyDataChannelUnavailable) {
			return nil
		}
		return err
	}
	if oldMux != nil {
		_ = oldMux.Close()
	}
	if err := runtime.waitForMainInterest(ctx, mux, generation, g.handshakeTimeout); err != nil {
		_ = mux.Close()
		if errors.Is(err, ErrLegacyDataChannelReplaced) {
			return nil
		}
		if isLegacyTransportError(err) || errors.Is(err, ErrLegacyDataChannelUnavailable) {
			return nil
		}
		return err
	}

	var terminalErr error
	select {
	case <-mux.Done():
		_, terminalErr = mux.terminalErrorSnapshot()
	case <-ctx.Done():
	}
	runtime.clearMuxIfCurrent(mux, generation)
	_ = mux.Close()
	return classifyServeChanExit(ctx, terminalErr)
}

func (g *Gateway) currentSessionForCleanup(parent context.Context, deviceID domain.DeviceID) (session.AgentSession, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), g.handshakeTimeout)
	defer cancel()
	return g.sessions.CurrentForDevice(ctx, deviceID)
}

func (g *Gateway) detachSessionForCleanup(parent context.Context, sessionID domain.SessionID) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), g.handshakeTimeout)
	defer cancel()
	return g.sessions.Detach(ctx, sessionID)
}

func classifyServeChanExit(ctx context.Context, terminalErr error) error {
	if ctx.Err() != nil {
		return nil
	}
	classified := classifyLegacyMuxTerminalCause(terminalErr)
	if errors.Is(classified, ErrLegacyDataChannelUnavailable) {
		return nil
	}
	return classified
}

func generateSessionID() (domain.SessionID, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return domain.SessionID(base64.RawURLEncoding.EncodeToString(raw)), nil
}

type legacyCredentialContextKey struct{}
type legacyOwner interface {
	AcquireLegacyInterest(context.Context, domain.DeviceID, string) (*session.WorkLease, error)
	WithLegacyPublication(context.Context, domain.DeviceID, string, func() error) error
}

func (g *Gateway) withPublication(ctx context.Context, id domain.DeviceID, publish func() error) error {
	if owner, ok := g.store.(legacyOwner); ok {
		key, _ := ctx.Value(legacyCredentialContextKey{}).(string)
		return owner.WithLegacyPublication(ctx, id, key, publish)
	}
	return publish()
}
