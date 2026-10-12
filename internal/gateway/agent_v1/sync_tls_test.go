package agent_v1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
)

func syncTLSFixture(t *testing.T) (*tls.Config, *tls.Config, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	server := config.DefaultTLSConfig()
	server.Certificates = []tls.Certificate{pair}
	client := config.DefaultTLSConfig()
	client.RootCAs = x509.NewCertPool()
	if !client.RootCAs.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture root invalid")
	}
	client.ServerName = "127.0.0.1"
	path := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err = os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return server, client, path
}
func syncOwnedFixture(t *testing.T) (*store.ConfigOwner, *AuthService, *session.Manager, []byte) {
	t.Helper()
	ctx := context.Background()
	state := store.NewMemoryStore()
	secret := bytes.Repeat([]byte{0x44}, 32)
	if err := state.CreateUser(ctx, domain.User{ID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := state.CreateProject(ctx, domain.Project{ID: "project-1", UserID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := state.CreateDevice(ctx, domain.Device{ID: "device-1", ProjectID: "project-1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := state.SetKAPv1DeviceSecret(ctx, "device-1", secret); err != nil {
		t.Fatal(err)
	}
	if err := state.CreateTunnel(ctx, domain.Tunnel{ID: "server-tunnel", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, Listener: "127.0.0.1:1001", TargetAddr: "127.0.0.1:2001", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "state.json")
	key := bytes.Repeat([]byte{0x33}, 32)
	if err := state.SaveState(path, key); err != nil {
		t.Fatal(err)
	}
	owner, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	manager := session.NewManager()
	return owner, NewAuthService(owner, manager), manager, secret
}

type watchedOwnedSource struct {
	source NativeSnapshotSource
	calls  chan domain.ConfigRevision
}

func (s *watchedOwnedSource) NativeSnapshot(ctx context.Context, id domain.DeviceID) (domain.NativeSnapshot, error) {
	snapshot, err := s.source.NativeSnapshot(ctx, id)
	if err == nil {
		select {
		case s.calls <- snapshot.Revision:
		default:
		}
	}
	return snapshot, err
}
func awaitOwnedRead(t *testing.T, s *watchedOwnedSource) domain.ConfigRevision {
	t.Helper()
	select {
	case r := <-s.calls:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("owned source not read")
		return 0
	}
}
func writeRawSyncAuth(t *testing.T, conn net.Conn, f syncAuthFrame) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write(prefix[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(data); err != nil {
		t.Fatal(err)
	}
}

func TestSyncTLSBootstrapOnlyClientInstallsOwnedSnapshotThroughACK(t *testing.T) {
	owner, svc, manager, secret := syncOwnedFixture(t)
	serverTrust, _, ca := syncTLSFixture(t)
	source := &watchedOwnedSource{source: owner, calls: make(chan domain.ConfigRevision, 8)}
	budget := &SyncStagingBudget{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- svc.ServeSyncControl(ctx, tls.Server(raw, serverTrust), source, budget)
	}()
	t.Setenv("KAVERN_SYNC_TLS_FIXTURE", base64.RawURLEncoding.EncodeToString(secret))
	bootstrap := config.NativeBootstrap{Server: listener.Addr().String(), DeviceID: "device-1", SecretEnv: "KAVERN_SYNC_TLS_FIXTURE", CAFile: ca}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	body, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	bootstrap, err = config.LoadNativeBootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	receiver, conn, err := OpenBootstrapControl(ctx, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clientDone := make(chan error, 1)
	go func() { clientDone <- receiver.Run(ctx, conn) }()
	if awaitOwnedRead(t, source) != 1 || awaitOwnedRead(t, source) != 1 {
		t.Fatal("server did not accept exact ACK and re-read owned source")
	}
	snapshot, ok := receiver.Snapshot()
	if !ok || snapshot.DeviceID != "device-1" || len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].ID != "server-tunnel" || snapshot.Tunnels[0].TargetAddr != "127.0.0.1:2001" {
		t.Fatal("bootstrap client did not install server configuration")
	}
	current, err := manager.CurrentForDevice(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = current.OpenStream(ctx, domain.StreamOpenRequest{TunnelID: "server-tunnel", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, ErrSyncNotReady) {
		t.Fatal("synchronized stream gate opened prematurely", err)
	}
	cancel()
	_ = awaitSync(t, clientDone)
	_ = awaitSync(t, serverDone)
	if budget.Used() != 0 {
		t.Fatal("TLS control shutdown retained reservation")
	}
	if _, ok = receiver.Snapshot(); ok {
		t.Fatal("TLS disconnect retained applied map")
	}
}

func TestSyncTLSMixedVersionsRejectBeforeReplacingCurrentSession(t *testing.T) {
	for _, kind := range []string{"missing-schema", "unsupported-schema", "wrong-role", "missing-finish-schema", "legacy-proof"} {
		t.Run(kind, func(t *testing.T) {
			owner, svc, manager, secret := syncOwnedFixture(t)
			current := syncAuthFixture(t, svc, secret)
			serverTrust, clientTrust, _ := syncTLSFixture(t)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			serverConn, clientConn := tls.Server(left, serverTrust), tls.Client(right, clientTrust)
			done := make(chan error, 1)
			go func() { done <- svc.ServeSyncControl(ctx, serverConn, owner, nil) }()
			if err := clientConn.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			start := authFrame("auth_start")
			start.DeviceID = "device-1"
			start.ClientNonce = mustNonce(t)
			switch kind {
			case "missing-schema":
				start.SyncVersion = nil
			case "unsupported-schema":
				version := 2
				start.SyncVersion = &version
			case "wrong-role":
				start.Role = TransportRoleDataCarrier
			}
			writeRawSyncAuth(t, clientConn, start)
			if kind == "missing-finish-schema" || kind == "legacy-proof" {
				challenge, err := readSyncAuth(clientConn)
				if err != nil {
					t.Fatal(err)
				}
				finish := authFrame("auth_finish")
				finish.DeviceID = start.DeviceID
				finish.ChallengeID = challenge.ChallengeID
				finish.Response, err = SignSyncAuthResponse(secret, start.DeviceID, start.ClientNonce, challenge.ServerNonce, ConfigSyncVersion)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "missing-finish-schema" {
					finish.SyncVersion = nil
				} else {
					finish.Response = mustAuthResponse(t, secret, start.DeviceID, start.ClientNonce, challenge.ServerNonce)
				}
				writeRawSyncAuth(t, clientConn, finish)
			}
			_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = readSyncAuth(clientConn)
			if err := awaitSync(t, done); err == nil {
				t.Fatal("mixed-version handshake succeeded")
			}
			after, err := manager.CurrentForDevice(context.Background(), "device-1")
			if err != nil || after.ID() != current.SessionID {
				t.Fatal("rejected handshake evicted current session", err)
			}
			svc.challengesMu.Lock()
			remaining := len(svc.challenges)
			svc.challengesMu.Unlock()
			if remaining != 0 {
				t.Fatal("rejected handshake retained challenge")
			}
		})
	}
}

func TestSyncTLSClientVerifiesChallengeSchemaAndDeviceBeforeProof(t *testing.T) {
	for _, kind := range []string{"schema", "device"} {
		t.Run(kind, func(t *testing.T) {
			serverTrust, clientTrust, _ := syncTLSFixture(t)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			serverConn, clientConn := tls.Server(left, serverTrust), tls.Client(right, clientTrust)
			peerDone := make(chan error, 1)
			go func() {
				if err := serverConn.HandshakeContext(ctx); err != nil {
					peerDone <- err
					return
				}
				start, err := readSyncAuth(serverConn)
				if err != nil {
					peerDone <- err
					return
				}
				challenge := authFrame("auth_challenge")
				challenge.DeviceID = start.DeviceID
				challenge.ServerNonce = domainNonce(t)
				challenge.ChallengeID = domainNonce(t)
				if kind == "schema" {
					version := 2
					challenge.SyncVersion = &version
				} else {
					challenge.DeviceID = "other"
				}
				data, _ := json.Marshal(challenge)
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(data)))
				_, err = serverConn.Write(prefix[:])
				if err == nil {
					_, err = serverConn.Write(data)
				}
				if err != nil {
					peerDone <- err
					return
				}
				_, err = readSyncAuth(serverConn)
				peerDone <- err
			}()
			if _, _, err := AuthenticateSyncControl(ctx, clientConn, "device-1", bytes.Repeat([]byte{0x44}, 32), nil); err == nil {
				t.Fatal("unverified challenge accepted")
			}
			if err := awaitSync(t, peerDone); err == nil {
				t.Fatal("client sent proof after wrong challenge")
			}
		})
	}
}
func domainNonce(t *testing.T) string {
	t.Helper()
	n, err := GenerateNonce()
	if err != nil {
		t.Error(err)
	}
	return n
}

func TestSyncTLSClientTrustFailuresDoNotAttach(t *testing.T) {
	for _, kind := range []string{"untrusted", "wrong-name", "expired", "insecure", "old-tls"} {
		t.Run(kind, func(t *testing.T) {
			owner, svc, manager, secret := syncOwnedFixture(t)
			current := syncAuthFixture(t, svc, secret)
			serverTrust, clientTrust, _ := syncTLSFixture(t)
			switch kind {
			case "untrusted":
				clientTrust.RootCAs = x509.NewCertPool()
			case "wrong-name":
				clientTrust.ServerName = "wrong.invalid"
			case "expired":
				clientTrust.Time = func() time.Time { return time.Now().Add(2 * time.Hour) }
			case "insecure":
				clientTrust.InsecureSkipVerify = true
			case "old-tls":
				clientTrust.MinVersion = tls.VersionTLS10
				clientTrust.MaxVersion = tls.VersionTLS11
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- svc.ServeSyncControl(ctx, tls.Server(left, serverTrust), owner, nil) }()
			if _, _, err := AuthenticateSyncControl(ctx, tls.Client(right, clientTrust), "device-1", secret, nil); err == nil {
				t.Fatal("unverified TLS trusted")
			}
			_ = awaitSync(t, done)
			after, err := manager.CurrentForDevice(context.Background(), "device-1")
			if err != nil || after.ID() != current.SessionID {
				t.Fatal("TLS rejection evicted active session", err)
			}
		})
	}
}

func TestSyncTLSNewClientRejectsExistingSchemaZeroServer(t *testing.T) {
	owner, svc, manager, secret := syncOwnedFixture(t)
	current := syncAuthFixture(t, svc, secret)
	serverTrust, clientTrust, _ := syncTLSFixture(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	serverConn, clientConn := tls.Server(left, serverTrust), tls.Client(right, clientTrust)
	done := make(chan error, 1)
	go func() {
		if err := serverConn.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		defer left.Close()
		limits := config.Limits{}
		_ = limits.Validate()
		done <- svc.ServeTransport(ctx, syncTLSConnection{serverConn}, limits)
	}()
	if _, _, err := AuthenticateSyncControl(ctx, clientConn, "device-1", secret, nil); err == nil {
		t.Fatal("new client fell back to schema zero")
	}
	_ = awaitSync(t, done)
	after, err := manager.CurrentForDevice(context.Background(), "device-1")
	if err != nil || after.ID() != current.SessionID {
		t.Fatal("mixed old server path evicted active session", err)
	}
	_ = owner
}

func TestSyncTLSOwnedCloseIsIdempotent(t *testing.T) {
	serverTrust, clientTrust, _ := syncTLSFixture(t)
	left, right := net.Pipe()
	defer right.Close()
	conn := tls.Server(left, serverTrust)
	_ = clientTrust
	cleanup := ownSyncTLS(context.Background(), conn)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); cleanup() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS cleanup not idempotent")
	}
}
