package agent_v1

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/domain"
	"io"
	"net"
	"time"
)

// Lifecycle authentication is deliberately a separate authenticated transcript.
// Command transport never retries the schema-only exchange after rejection.
func (s *AuthService) beginLifecycleAuth(ctx context.Context, start LifecycleFrame) (LifecycleFrame, error) {
	if start.Type != "auth_start" {
		return LifecycleFrame{}, ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(start); e != nil {
		return LifecycleFrame{}, e
	}
	if _, ok := s.store.(LifecycleOwner); !ok {
		return LifecycleFrame{}, ErrLifecycle
	}
	c, e := s.beginAuth(ctx, AuthStartRequest{DeviceID: start.DeviceID, ClientNonce: start.ClientNonce}, ConfigSyncVersion)
	if e != nil {
		return LifecycleFrame{}, e
	}
	f := start
	f.Type = "auth_challenge"
	f.ServerNonce = c.ServerNonce
	f.ChallengeID = c.AuthChallengeID
	f.LeaseMillis = LifecycleLeaseMillis
	f.ProofMillis = LifecycleAuthMillis
	s.challengesMu.Lock()
	state := s.challenges[f.ChallengeID]
	state.ExpiresAt = s.now().Add(syncHandshakeTimeout)
	state.Lifecycle = &f
	s.challenges[f.ChallengeID] = state
	s.challengesMu.Unlock()
	return f, nil
}
func (s *AuthService) completeLifecycleAuth(ctx context.Context, finish LifecycleFrame) (SyncAuthResult, LifecycleFrame, error) {
	if finish.Type != "auth_finish" {
		return SyncAuthResult{}, LifecycleFrame{}, ErrLifecycle
	}
	if _, e := EncodeLifecycleFrame(finish); e != nil {
		return SyncAuthResult{}, LifecycleFrame{}, e
	}
	s.challengesMu.Lock()
	state, ok := s.challenges[finish.ChallengeID]
	if ok && state.Lifecycle != nil {
		expected := *state.Lifecycle
		expected.Type = "auth_finish"
		expected.HMAC = finish.HMAC
		if expected == finish {
			copy := finish
			state.Lifecycle = &copy
			s.challenges[finish.ChallengeID] = state
		} else {
			ok = false
		}
	}
	s.challengesMu.Unlock()
	if !ok || state.Lifecycle == nil {
		return SyncAuthResult{}, LifecycleFrame{}, ErrLifecycle
	}
	result, e := s.completeAuth(ctx, AuthFinishRequest{AuthChallengeID: finish.ChallengeID, ResponseHMAC: finish.HMAC}, ConfigSyncVersion)
	if e != nil {
		return SyncAuthResult{}, LifecycleFrame{}, e
	}
	// Publication succeeded, but the caller has not yet received a usable grant.
	// Every failure below retires only this published session, never a replacement.
	accepted := false
	defer func() {
		if !accepted {
			_ = s.CloseSession(context.Background(), result.SessionID)
		}
	}()
	auth := SyncAuthResult{AuthResult: result, ConfigSyncVersion: ConfigSyncVersion, LifecycleVersion: LifecycleVersion}
	entry, ok := s.registry.lookup(result.SessionID)
	if !ok {
		return auth, LifecycleFrame{}, ErrSessionClosed
	}
	entry.session.mu.Lock()
	grant := entry.session.lifecycleGrant
	entry.session.mu.Unlock()
	if e := entry.session.serverLease().Valid(ctx); e != nil {
		return auth, LifecycleFrame{}, e
	}
	accepted = true
	return auth, grant, nil
}
func (s *AuthService) serveLifecycleControl(ctx, handshake context.Context, conn *tls.Conn, start LifecycleFrame, source NativeSnapshotSource, budget *SyncStagingBudget) error {
	challenge, e := s.beginLifecycleAuth(handshake, start)
	if e != nil {
		return e
	}
	defer func() { s.challengesMu.Lock(); delete(s.challenges, challenge.ChallengeID); s.challengesMu.Unlock() }()
	if e = WriteLifecycleFrame(conn, challenge); e != nil {
		return e
	}
	finish, e := ReadLifecycleFrame(conn)
	if e != nil {
		return e
	}
	// Bind this transport to its frozen challenge before looking up/consuming
	// any pending exchange. A valid proof from a different connection is invalid here.
	expected := challenge
	expected.Type = "auth_finish"
	expected.HMAC = finish.HMAC
	if expected != finish {
		return ErrLifecycle
	}
	auth, grant, e := s.completeLifecycleAuth(handshake, finish)
	if e != nil {
		return e
	}
	defer s.CloseSession(context.Background(), auth.SessionID)
	if e = WriteLifecycleFrame(conn, grant); e != nil {
		return e
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return e
	}
	control, e := s.NewConfigServer(ctx, auth, source, budget)
	if e != nil {
		return e
	}
	return control.Run(ctx, syncTLSConnection{conn})
}
func hasLifecycle(data []byte) bool {
	var f map[string]json.RawMessage
	if json.Unmarshal(data, &f) != nil {
		return false
	}
	_, ok := f["lifecycle_version"]
	return ok
}
func authenticateLifecycleControl(ctx context.Context, conn *tls.Conn, device domain.DeviceID, secret []byte, budget *SyncStagingBudget, deadline time.Time, clock LifecycleClock) (*ConfigReceiver, net.Conn, error) {
	if conn == nil || clock == nil || len(secret) != 32 {
		return nil, nil, ErrInvalidInput
	}
	cleanup := ownSyncTLS(ctx, conn)
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	handshake, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if e := conn.SetDeadline(deadline); e != nil {
		return nil, nil, e
	}
	if e := conn.HandshakeContext(handshake); e != nil {
		return nil, nil, e
	}
	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 {
		return nil, nil, ErrInvalidInput
	}
	nonce, e := GenerateNonce()
	if e != nil {
		return nil, nil, e
	}
	start := lifecycleFrame("auth_start", device, "")
	start.ClientNonce = nonce
	if e = WriteLifecycleFrame(conn, start); e != nil {
		return nil, nil, e
	}
	challenge, e := ReadLifecycleFrame(conn)
	if e != nil {
		return nil, nil, e
	}
	if challenge.Type == "auth_reject" {
		return nil, nil, ErrSyncSchema
	}
	if challenge.Type != "auth_challenge" || challenge.DeviceID != device || challenge.ClientNonce != nonce {
		return nil, nil, ErrLifecycle
	}
	finish := challenge
	finish.Type = "auth_finish"
	finish, e = SignLifecycleFrame(secret, finish)
	if e != nil {
		return nil, nil, e
	}
	sent := clock.Now()
	if e = WriteLifecycleFrame(conn, finish); e != nil {
		return nil, nil, e
	}
	grant, e := ReadLifecycleFrame(conn)
	if e != nil {
		return nil, nil, e
	}
	auth := SyncAuthResult{AuthResult: AuthResult{DeviceID: device, SessionID: grant.SessionID, ProtocolVersion: ProtocolVersion}, ConfigSyncVersion: ConfigSyncVersion, LifecycleVersion: LifecycleVersion}
	receiver, e := NewConfigReceiver(auth, budget)
	if e != nil {
		return nil, nil, e
	}
	// Cleanup aborts the transport immediately. The dispatcher joins receiver
	// work after its reader has exited; expiry must not block on application work.
	lease, e := NewClientLease(ctx, finish, grant, sent, secret, clock, func() { _ = conn.NetConn().Close() })
	if e != nil {
		receiver.Close()
		return nil, nil, e
	}
	receiver.lifecycle = lease
	if e = conn.SetDeadline(time.Time{}); e != nil {
		lease.Revoke(e)
		receiver.Close()
		return nil, nil, e
	}
	success = true
	return receiver, &ownedSyncTLS{syncTLSConnection: syncTLSConnection{conn}, cleanup: func() { lease.Revoke(nil); cleanup() }}, nil
}
func encodeNegotiatedSyncPayload(f syncFrame, lifecycle int) ([]byte, error) {
	if lifecycle == LifecycleVersion {
		return encodeLifecycleSyncPayload(f)
	}
	if lifecycle != 0 {
		return nil, ErrSyncSchema
	}
	return encodeSyncPayload(f)
}

func writeControlPayload(w io.Writer, data []byte) error {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	if e := writeLifecycleBytes(w, prefix[:]); e != nil {
		return e
	}
	return writeLifecycleBytes(w, data)
}
