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

type DeviceResolver interface {
	ResolveLegacyDeviceForAuth(ctx context.Context, lookupKey string) (domain.Device, error)
}

type Config struct {
	ServerSecret      []byte
	Store             DeviceResolver
	Sessions          session.SessionManager
	HandshakeTimeout  time.Duration
	MaxHandshakeBytes int
	NewSessionID      func() (domain.SessionID, error)
	NewAuthChallenge  func() ([]byte, error)
}

type Gateway struct {
	store             DeviceResolver
	sessions          session.SessionManager
	serverSecret      []byte
	handshakeTimeout  time.Duration
	maxHandshakeBytes int
	newSessionID      func() (domain.SessionID, error)
	newAuthChallenge  func() ([]byte, error)

	mu           sync.Mutex
	sessionsByID map[domain.SessionID]*LegacyNpcSession
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
	newAuthChallenge := cfg.NewAuthChallenge
	if newAuthChallenge == nil {
		newAuthChallenge = generateAuthChallenge
	}
	return &Gateway{
		store:             cfg.Store,
		sessions:          cfg.Sessions,
		serverSecret:      append([]byte(nil), cfg.ServerSecret...),
		handshakeTimeout:  timeout,
		maxHandshakeBytes: maxHandshakeBytes,
		newSessionID:      newSessionID,
		newAuthChallenge:  newAuthChallenge,
		sessionsByID:      make(map[domain.SessionID]*LegacyNpcSession),
	}, nil
}

func (g *Gateway) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return ErrInvalidConfig
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		go func() {
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

func (g *Gateway) serveMain(ctx context.Context, conn net.Conn, deviceID domain.DeviceID) error {
	sessionID, err := g.newSessionID()
	if err != nil {
		_ = conn.Close()
		return err
	}
	if sessionID == "" {
		_ = conn.Close()
		return ErrInvalidHandshake
	}
	legacySession := newSession(sessionID, deviceID, conn)
	if err := g.sessions.Attach(ctx, legacySession); err != nil {
		_ = legacySession.Close(context.Background())
		return err
	}
	g.mu.Lock()
	g.sessionsByID[sessionID] = legacySession
	g.mu.Unlock()

	defer func() {
		_ = legacySession.Close(context.Background())
		_ = g.sessions.Detach(context.Background(), sessionID)
		g.mu.Lock()
		delete(g.sessionsByID, sessionID)
		g.mu.Unlock()
	}()
	go func() {
		<-ctx.Done()
		_ = legacySession.Close(context.Background())
	}()
	legacySession.waitMainEOF()
	return nil
}

func (g *Gateway) serveChan(ctx context.Context, conn net.Conn, deviceID domain.DeviceID) error {
	current, err := g.sessions.CurrentForDevice(ctx, deviceID)
	if err != nil {
		_ = conn.Close()
		return err
	}
	legacySession, ok := current.(*LegacyNpcSession)
	if !ok || legacySession.Protocol() != domain.AgentProtocolLegacyNPC {
		_ = conn.Close()
		return ErrNoCurrentMainSession
	}
	if err := legacySession.addChan(conn); err != nil {
		_ = conn.Close()
		return err
	}
	defer legacySession.removeChan(conn)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var buf [1]byte
	for {
		if _, err := conn.Read(buf[:]); err != nil {
			_ = conn.Close()
			return nil
		}
	}
}

func generateSessionID() (domain.SessionID, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return domain.SessionID(base64.RawURLEncoding.EncodeToString(raw)), nil
}

func generateAuthChallenge() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
