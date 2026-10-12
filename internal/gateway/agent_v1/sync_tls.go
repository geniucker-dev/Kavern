package agent_v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
)

const syncHandshakeTimeout = 5 * time.Second

// Control cancellation must abort TLS I/O immediately; a graceful TLS
// close_notify can otherwise wait on a peer that has stopped reading.
type syncTLSConnection struct{ *tls.Conn }

func (c syncTLSConnection) Close() error { return c.NetConn().Close() }
func ownSyncTLS(ctx context.Context, conn *tls.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = conn.NetConn().Close() })
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = conn.NetConn().Close()
			if !stop() {
				<-done
			}
		})
	}
}

// ServeSyncControl is the opt-in, schema-1 TLS control adapter. It creates no
// listener; the daemon assembly owns listening and transport dispatch.
func (s *AuthService) ServeSyncControl(ctx context.Context, conn *tls.Conn, source NativeSnapshotSource, budget *SyncStagingBudget) error {
	return s.serveSyncTransport(ctx, conn, source, budget, false)
}

// ServeSyncTransport dispatches authenticated schema-1 control/data roles on
// one verified TLS endpoint used by the synchronized daemon assembly.
func (s *AuthService) ServeSyncTransport(ctx context.Context, conn *tls.Conn, source NativeSnapshotSource, budget *SyncStagingBudget) error {
	return s.serveSyncTransport(ctx, conn, source, budget, true)
}
func (s *AuthService) serveSyncTransport(ctx context.Context, conn *tls.Conn, source NativeSnapshotSource, budget *SyncStagingBudget, allowCarrier bool) error {
	if conn == nil || source == nil {
		return ErrInvalidInput
	}
	cleanup := ownSyncTLS(ctx, conn)
	defer cleanup()
	handshakeCtx, cancel := context.WithTimeout(ctx, syncHandshakeTimeout)
	defer cancel()
	if err := conn.SetDeadline(time.Now().Add(syncHandshakeTimeout)); err != nil {
		return err
	}
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return err
	}
	if conn.ConnectionState().Version < tls.VersionTLS12 {
		return ErrInvalidInput
	}
	payload, err := readSyncTransportPayload(conn)
	if err != nil {
		return err
	}
	var role struct {
		Role string `json:"role"`
	}
	_ = json.Unmarshal(payload, &role)
	if hasLifecycle(payload) && role.Role != TransportRoleDataCarrier {
		first, e := DecodeLifecycleFrame(payload)
		if e != nil {
			return e
		}
		return s.serveLifecycleControl(ctx, handshakeCtx, conn, first, source, budget)
	}
	if allowCarrier && !hasLifecycle(payload) {
		reject := lifecycleFrame("auth_reject", "upgrade-required", "")
		reject.Code = "upgrade_required"
		_ = WriteLifecycleFrame(conn, reject)
		return ErrSyncSchema
	}
	if allowCarrier && role.Role == TransportRoleDataCarrier {
		first, err := decodeSyncCarrier(payload)
		if err != nil {
			return err
		}
		return s.serveSyncCarrier(ctx, conn, first)
	}
	start, err := decodeSyncAuth(payload)
	if err != nil {
		if errors.Is(err, ErrSyncSchema) {
			reject := authFrame("auth_reject")
			reject.Code = "upgrade_required"
			_ = writeSyncAuth(conn, reject)
		}
		return err
	}
	if start.Type != "auth_start" {
		return ErrSyncTransfer
	}
	// Schema is validated above, before challenge or session attachment.
	challenge, err := s.BeginSyncAuth(handshakeCtx, AuthStartRequest{DeviceID: start.DeviceID, ClientNonce: start.ClientNonce}, *start.SyncVersion)
	if err != nil {
		return err
	}
	defer func() {
		s.challengesMu.Lock()
		delete(s.challenges, challenge.AuthChallengeID)
		s.challengesMu.Unlock()
	}()
	response := authFrame("auth_challenge")
	response.DeviceID = start.DeviceID
	response.ServerNonce = challenge.ServerNonce
	response.ChallengeID = challenge.AuthChallengeID
	if err = writeSyncAuth(conn, response); err != nil {
		return err
	}
	finish, err := readSyncAuth(conn)
	if err != nil {
		return err
	}
	if finish.Type != "auth_finish" || finish.DeviceID != start.DeviceID || finish.ChallengeID != challenge.AuthChallengeID {
		return ErrSyncTransfer
	}
	auth, err := s.CompleteSyncAuth(handshakeCtx, AuthFinishRequest{AuthChallengeID: finish.ChallengeID, ResponseHMAC: finish.Response}, *finish.SyncVersion)
	if err != nil {
		return err
	}
	defer s.CloseSession(context.Background(), auth.SessionID)
	accepted := authFrame("auth_ok")
	accepted.DeviceID = auth.DeviceID
	accepted.SessionID = auth.SessionID
	if err = writeSyncAuth(conn, accepted); err != nil {
		return err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	control, err := s.NewConfigServer(ctx, auth, source, budget)
	if err != nil {
		return err
	}
	return control.Run(ctx, syncTLSConnection{conn})
}

// AuthenticateSyncControl requires lifecycle v1 and verifies TLS trust and the
// authenticated result before returning a fresh receiver. Run must be called
// once on the returned owned connection to drive snapshot installation/ACK.
func AuthenticateSyncControl(ctx context.Context, conn *tls.Conn, device domain.DeviceID, secret []byte, budget *SyncStagingBudget) (*ConfigReceiver, net.Conn, error) {
	return authenticateLifecycleControl(ctx, conn, device, secret, budget, time.Now().Add(syncHandshakeTimeout), NewLifecycleClock())
}
func authenticateSyncControl(ctx context.Context, conn *tls.Conn, device domain.DeviceID, secret []byte, budget *SyncStagingBudget, deadline time.Time) (*ConfigReceiver, net.Conn, error) {
	if conn == nil || len(secret) != 32 || !config.ValidID(string(device)) {
		return nil, nil, ErrInvalidInput
	}
	cleanup := ownSyncTLS(ctx, conn)
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	handshakeCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, nil, err
	}
	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
		return nil, nil, ErrInvalidInput
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, nil, err
	}
	start := authFrame("auth_start")
	start.DeviceID = device
	start.ClientNonce = nonce
	if err = writeSyncAuth(conn, start); err != nil {
		return nil, nil, err
	}
	challenge, err := readSyncAuth(conn)
	if err != nil {
		return nil, nil, err
	}
	if challenge.Type == "auth_reject" {
		return nil, nil, ErrSyncSchema
	}
	if challenge.Type != "auth_challenge" || challenge.DeviceID != device {
		return nil, nil, ErrSyncTransfer
	}
	proof, err := SignSyncAuthResponse(secret, device, nonce, challenge.ServerNonce, *challenge.SyncVersion)
	if err != nil {
		return nil, nil, err
	}
	finish := authFrame("auth_finish")
	finish.DeviceID = device
	finish.ChallengeID = challenge.ChallengeID
	finish.Response = proof
	if err = writeSyncAuth(conn, finish); err != nil {
		return nil, nil, err
	}
	accepted, err := readSyncAuth(conn)
	if err != nil {
		return nil, nil, err
	}
	if accepted.Type != "auth_ok" || accepted.DeviceID != device {
		return nil, nil, ErrSyncTransfer
	}
	auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: device, SessionID: accepted.SessionID, ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: *accepted.SyncVersion}
	receiver, err := NewConfigReceiver(auth, budget)
	if err != nil {
		return nil, nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		receiver.Close()
		return nil, nil, err
	}
	// The idempotent owned connection transfers and joins the handshake's
	// cancellation callback when the receiver control loop closes it.
	success = true
	return receiver, &ownedSyncTLS{syncTLSConnection: syncTLSConnection{conn}, cleanup: cleanup}, nil
}

type ownedSyncTLS struct {
	syncTLSConnection
	cleanup func()
}

func (c *ownedSyncTLS) Close() error { c.cleanup(); return nil }

// OpenBootstrapControl resolves only bootstrap identity/trust references. It
// does not load targets, negotiate local carrier overrides, or create carriers.
func OpenBootstrapControl(ctx context.Context, cfg config.NativeBootstrap) (*ConfigReceiver, net.Conn, error) {
	secret, trust, err := bootstrapMaterial(cfg)
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	return openBootstrapWithMaterial(ctx, cfg, secret, trust)
}
func bootstrapMaterial(cfg config.NativeBootstrap) ([]byte, *tls.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	secret, err := base64.RawURLEncoding.DecodeString(os.Getenv(cfg.SecretEnv))
	success := false
	defer func() {
		if !success {
			clear(secret)
		}
	}()
	if err != nil || len(secret) != 32 {
		return nil, nil, ErrInvalidInput
	}
	f, err := os.Open(cfg.CAFile)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	ca, err := io.ReadAll(io.LimitReader(f, config.MaxJSONBytes+1))
	if err != nil || len(ca) > config.MaxJSONBytes {
		return nil, nil, ErrInvalidInput
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, ErrInvalidInput
	}
	trust := config.DefaultTLSConfig()
	trust.RootCAs = roots
	trust.ServerName = cfg.ServerName
	success = true
	return secret, trust, nil
}
func openBootstrapWithMaterial(ctx context.Context, cfg config.NativeBootstrap, secret []byte, trust *tls.Config) (*ConfigReceiver, net.Conn, error) {
	trust = trust.Clone()
	deadline := time.Now().Add(syncHandshakeTimeout)
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	dial := net.Dialer{Timeout: syncHandshakeTimeout}
	connected, err := dial.DialContext(dialCtx, "tcp", cfg.Server)
	if err != nil {
		return nil, nil, err
	}
	if trust.ServerName == "" {
		host, _, err := net.SplitHostPort(cfg.Server)
		if err != nil {
			_ = connected.Close()
			return nil, nil, ErrInvalidInput
		}
		trust.ServerName = host
	}
	conn := tls.Client(connected, trust)
	return authenticateLifecycleControl(ctx, conn, domain.DeviceID(cfg.DeviceID), secret, nil, deadline, NewLifecycleClock())
}
