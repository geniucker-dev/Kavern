package agent_v1

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/router"
)

func TestKAPv1TCPEchoThroughRouterAgentSessionCarrierMuxAndAgentLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc, st, _ := newAuthFixture(t, true)
	if err := st.CreateTunnel(ctx, domain.Tunnel{
		ID:       "tunnel-1",
		DeviceID: "device-1",
		Protocol: domain.TunnelProtocolTCP,
		Listener: "tcp:test",
		Enabled:  true,
	}); err != nil {
		t.Fatalf("CreateTunnel() error = %v", err)
	}
	authResult, secret := authenticate(t, svc)
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

	serverMux, agentMux := newMuxPair(t)
	defer serverMux.Close()
	defer agentMux.Close()

	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, authResult.SessionID, authResult.DeviceID, nonce)
	if err := svc.BindAndAttachCarrier(ctx, CarrierBindRequest{SessionID: authResult.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}, serverMux, carrier.Config{MaxStreamsPerCarrier: 2}); err != nil {
		t.Fatalf("BindAndAttachCarrier() error = %v", err)
	}

	loopCtx, stopLoop := context.WithCancel(ctx)
	defer stopLoop()
	loopDone := make(chan error, 1)
	go func() {
		loopDone <- (&AgentDataLoop{Session: agentMux, Targets: TargetMap{"tunnel-1": echoAddr}}).Run(loopCtx)
	}()

	publicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer publicListener.Close()
	routeCtx, stopRoute := context.WithCancel(ctx)
	defer stopRoute()
	routeDone := make(chan error, 1)
	go func() {
		conn, err := publicListener.Accept()
		if err != nil {
			routeDone <- err
			return
		}
		routeDone <- router.New(st, svc.sessions).RouteTCP(routeCtx, domain.Tunnel{ID: "tunnel-1", DeviceID: "device-1", Protocol: domain.TunnelProtocolTCP, Enabled: true}, conn)
	}()

	client, err := net.Dial("tcp", publicListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcpClient := client.(*net.TCPConn)
	defer tcpClient.Close()
	_ = tcpClient.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := tcpClient.Write([]byte("hello kavern")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := tcpClient.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	got := make([]byte, len("hello kavern"))
	if _, err := io.ReadFull(tcpClient, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "hello kavern" {
		t.Fatalf("echo = %q, want %q", got, "hello kavern")
	}
	_ = tcpClient.Close()
	stopRoute()
	select {
	case err := <-routeDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("RouteTCP() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("RouteTCP timed out: %v", ctx.Err())
	}
	stopLoop()
	_ = agentMux.Close()
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("agent loop did not exit")
	}
}

func TestBindAndAttachCarrierRejectsReplay(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)
	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	serverMux, agentMux := newMuxPair(t)
	defer serverMux.Close()
	defer agentMux.Close()

	req := CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}
	if err := svc.BindAndAttachCarrier(ctx, req, serverMux, carrier.Config{MaxStreamsPerCarrier: 1}); err != nil {
		t.Fatalf("BindAndAttachCarrier(first) error = %v", err)
	}
	secondServer, secondAgent := newMuxPair(t)
	defer secondServer.Close()
	defer secondAgent.Close()
	if err := svc.BindAndAttachCarrier(ctx, req, secondServer, carrier.Config{MaxStreamsPerCarrier: 1}); !errors.Is(err, ErrCarrierNonceReplay) {
		t.Fatalf("BindAndAttachCarrier(replay) error = %v, want %v", err, ErrCarrierNonceReplay)
	}
}

func TestBindAndAttachCarrierClosesMuxSessionOnInvalidCarrierConfig(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)
	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	muxSession := &fakeMuxSession{}

	err := svc.BindAndAttachCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}, muxSession, carrier.Config{})
	if !errors.Is(err, carrier.ErrInvalidConfig) {
		t.Fatalf("BindAndAttachCarrier() error = %v, want %v", err, carrier.ErrInvalidConfig)
	}
	if muxSession.CloseCount() != 1 {
		t.Fatalf("mux close count = %d, want 1", muxSession.CloseCount())
	}
}

func TestBindAndAttachCarrierClosesMuxSessionOnBindFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, _ := authenticate(t, svc)
	muxSession := &fakeMuxSession{}

	err := svc.BindAndAttachCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: mustNonce(t), ResponseHMAC: strings.Repeat("0", 64)}, muxSession, carrier.Config{MaxStreamsPerCarrier: 1})
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("BindAndAttachCarrier() error = %v, want %v", err, ErrAuthFailed)
	}
	if muxSession.CloseCount() != 1 {
		t.Fatalf("mux close count = %d, want 1", muxSession.CloseCount())
	}
}

func TestBindAndAttachCarrierClosesCarrierMuxSessionOnAttachFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)
	entry, ok := svc.registry.lookup(result.SessionID)
	if !ok {
		t.Fatal("active session not found")
	}
	if err := entry.session.pool.Close(); err != nil {
		t.Fatal(err)
	}
	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	muxSession := &fakeMuxSession{}

	err := svc.BindAndAttachCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}, muxSession, carrier.Config{MaxStreamsPerCarrier: 1})
	if !errors.Is(err, carrier.ErrPoolClosed) {
		t.Fatalf("BindAndAttachCarrier() error = %v, want %v", err, carrier.ErrPoolClosed)
	}
	if muxSession.CloseCount() != 1 {
		t.Fatalf("mux close count = %d, want 1", muxSession.CloseCount())
	}
}

func TestBindAndAttachCarrierSuccessDoesNotCloseMuxSessionPrematurely(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAuthFixture(t, true)
	result, secret := authenticate(t, svc)
	nonce := mustNonce(t)
	hmac := mustCarrierHMAC(t, secret, result.SessionID, result.DeviceID, nonce)
	muxSession := &fakeMuxSession{}

	if err := svc.BindAndAttachCarrier(ctx, CarrierBindRequest{SessionID: result.SessionID, CarrierNonce: nonce, ResponseHMAC: hmac}, muxSession, carrier.Config{MaxStreamsPerCarrier: 1}); err != nil {
		t.Fatalf("BindAndAttachCarrier() error = %v", err)
	}
	if muxSession.CloseCount() != 0 {
		t.Fatalf("mux close count = %d, want 0", muxSession.CloseCount())
	}
}

func TestOpenStreamMetadataWriteFailureReleasesCarrierSlot(t *testing.T) {
	sess := newAgentSession("session-1", "device-1")
	fakeMux := &fakeMuxSession{streams: []mux.Stream{&failingWriteStream{}, &memoryStream{}}}
	c, err := carrier.New(fakeMux, carrier.Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.attachCarrier(c); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); err == nil {
		t.Fatal("expected metadata write failure")
	}
	stream, err := sess.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
	if err != nil {
		t.Fatalf("second OpenStream() error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenStreamCloseReleasesCarrierLease(t *testing.T) {
	sess := newAgentSession("session-1", "device-1")
	fakeMux := &fakeMuxSession{streams: []mux.Stream{&memoryStream{}, &memoryStream{}}}
	c, err := carrier.New(fakeMux, carrier.Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.attachCarrier(c); err != nil {
		t.Fatal(err)
	}
	first, err := sess.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); !errors.Is(err, carrier.ErrNoCarrierAvailable) {
		t.Fatalf("second OpenStream while first active error = %v, want %v", err, carrier.ErrNoCarrierAvailable)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := sess.OpenStream(context.Background(), domain.StreamOpenRequest{TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP})
	if err != nil {
		t.Fatalf("second OpenStream after close error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentDataLoopRunExitsAfterMuxSessionCloseWithoutCallerCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	muxSession := newBlockingAcceptMuxSession()
	done := make(chan error, 1)
	go func() {
		done <- (&AgentDataLoop{Session: muxSession, Targets: TargetMap{"tunnel-1": "127.0.0.1:1"}}).Run(ctx)
	}()
	muxSession.WaitForAccept(t)
	if err := muxSession.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("Run() did not exit before context deadline: %v", ctx.Err())
	}
	if muxSession.CloseCount() == 0 {
		t.Fatal("mux CloseCount() = 0, want at least 1")
	}
}

func TestAgentDataLoopCancelsHandlersBeforeWaitingOnMuxClose(t *testing.T) {
	parentCtx, cancelParent := context.WithTimeout(context.Background(), time.Second)
	defer cancelParent()
	stream := &memoryStream{}
	if err := WriteOpenStreamMetadata(stream, OpenStreamMetadata{Version: ProtocolVersion, Type: OpenStreamMessageType, TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); err != nil {
		t.Fatal(err)
	}
	muxSession := newOneStreamThenBlockingMuxSession(stream)
	resolver := &blockingResolver{entered: make(chan struct{})}

	done := make(chan error, 1)
	go func() {
		done <- (&AgentDataLoop{Session: muxSession, Targets: resolver}).Run(parentCtx)
	}()
	resolver.WaitForResolve(t)
	if err := muxSession.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-parentCtx.Done():
		t.Fatalf("Run() did not return before parent context deadline: %v", parentCtx.Err())
	}
}

func TestReadOpenStreamMetadataRejectsMalformedOversizedUnknownFieldsAndUnknownTunnelDoesNotDial(t *testing.T) {
	var oversized bytes.Buffer
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], MaxOpenStreamMetadataBytes+1)
	oversized.Write(prefix[:])
	if _, err := ReadOpenStreamMetadata(&oversized); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("oversized metadata error = %v, want %v", err, ErrMetadataTooLarge)
	}

	var unknownField bytes.Buffer
	writeRawMetadata(t, &unknownField, []byte(`{"version":"kapv1","type":"open_stream","tunnel_id":"tunnel-1","protocol":"tcp","target_addr":"127.0.0.1:1"}`))
	if _, err := ReadOpenStreamMetadata(&unknownField); !errors.Is(err, ErrMalformedMetadata) {
		t.Fatalf("unknown field metadata error = %v, want %v", err, ErrMalformedMetadata)
	}

	var malformed bytes.Buffer
	writeRawMetadata(t, &malformed, []byte(`{`))
	if _, err := ReadOpenStreamMetadata(&malformed); !errors.Is(err, ErrMalformedMetadata) {
		t.Fatalf("malformed metadata error = %v, want %v", err, ErrMalformedMetadata)
	}

	stream := &memoryStream{}
	if err := WriteOpenStreamMetadata(stream, OpenStreamMetadata{Version: ProtocolVersion, Type: OpenStreamMessageType, TunnelID: "missing", Protocol: domain.TunnelProtocolTCP}); err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{}
	if err := HandleAgentStream(context.Background(), stream, TargetMap{}, dialer); !errors.Is(err, ErrUnknownTunnelTarget) {
		t.Fatalf("HandleAgentStream unknown tunnel error = %v, want %v", err, ErrUnknownTunnelTarget)
	}
	if dialer.count != 0 {
		t.Fatalf("dial count = %d, want 0", dialer.count)
	}
}

func TestPayloadCannotChooseTargetAddress(t *testing.T) {
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()
	streamA, streamB := net.Pipe()
	defer streamA.Close()
	defer streamB.Close()
	done := make(chan error, 1)
	go func() {
		done <- HandleAgentStream(context.Background(), streamB, TargetMap{"tunnel-1": echoAddr}, &TCPDialer{})
	}()
	if err := WriteOpenStreamMetadata(streamA, OpenStreamMetadata{Version: ProtocolVersion, Type: OpenStreamMessageType, TunnelID: "tunnel-1", Protocol: domain.TunnelProtocolTCP}); err != nil {
		t.Fatal(err)
	}
	if _, err := streamA.Write([]byte("127.0.0.1:1")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("127.0.0.1:1"))
	if _, err := io.ReadFull(streamA, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "127.0.0.1:1" {
		t.Fatalf("echo = %q, want target-like payload echoed", buf)
	}
	_ = streamA.Close()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("HandleAgentStream() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleAgentStream timed out")
	}
}

func newMuxPair(t *testing.T) (mux.Session, mux.Session) {
	t.Helper()
	serverConn, agentConn := net.Pipe()
	backend := mux.NewSmuxBackend()
	agentReady := make(chan mux.Session, 1)
	agentErr := make(chan error, 1)
	go func() {
		agent, err := backend.Server(agentConn, mux.Config{})
		if err != nil {
			agentErr <- err
			return
		}
		agentReady <- agent
	}()
	server, err := backend.Client(serverConn, mux.Config{})
	if err != nil {
		t.Fatalf("server mux: %v", err)
	}
	select {
	case err := <-agentErr:
		t.Fatalf("agent mux: %v", err)
	case agent := <-agentReady:
		return server, agent
	case <-time.After(time.Second):
		t.Fatal("mux pair timed out")
	}
	return nil, nil
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func writeRawMetadata(t *testing.T, w io.Writer, payload []byte) {
	t.Helper()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := w.Write(prefix[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
}

type fakeMuxSession struct {
	mu      sync.Mutex
	streams []mux.Stream
	closed  bool
	closes  int
}

func (s *fakeMuxSession) OpenStream(ctx context.Context) (mux.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.streams) == 0 {
		return nil, errors.New("no stream")
	}
	stream := s.streams[0]
	s.streams = s.streams[1:]
	return stream, nil
}

func (s *fakeMuxSession) AcceptStream(ctx context.Context) (mux.Stream, error) {
	return nil, errors.New("not implemented")
}

func (s *fakeMuxSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.closes++
	return nil
}

func (s *fakeMuxSession) CloseCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

type blockingAcceptMuxSession struct {
	mu      sync.Mutex
	started chan struct{}
	closed  chan struct{}
	closes  int
	once    sync.Once
}

func newBlockingAcceptMuxSession() *blockingAcceptMuxSession {
	return &blockingAcceptMuxSession{started: make(chan struct{}), closed: make(chan struct{})}
}

func (s *blockingAcceptMuxSession) OpenStream(ctx context.Context) (mux.Stream, error) {
	return nil, errors.New("not implemented")
}

func (s *blockingAcceptMuxSession) AcceptStream(ctx context.Context) (mux.Stream, error) {
	s.once.Do(func() {
		close(s.started)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

func (s *blockingAcceptMuxSession) Close() error {
	s.mu.Lock()
	s.closes++
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Unlock()
	return nil
}

func (s *blockingAcceptMuxSession) WaitForAccept(t *testing.T) {
	t.Helper()
	select {
	case <-s.started:
	case <-time.After(time.Second):
		t.Fatal("AcceptStream was not called")
	}
}

func (s *blockingAcceptMuxSession) CloseCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

type oneStreamThenBlockingMuxSession struct {
	mu       sync.Mutex
	stream   mux.Stream
	accepted bool
	closed   chan struct{}
	closes   int
}

func newOneStreamThenBlockingMuxSession(stream mux.Stream) *oneStreamThenBlockingMuxSession {
	return &oneStreamThenBlockingMuxSession{stream: stream, closed: make(chan struct{})}
}

func (s *oneStreamThenBlockingMuxSession) OpenStream(ctx context.Context) (mux.Stream, error) {
	return nil, errors.New("not implemented")
}

func (s *oneStreamThenBlockingMuxSession) AcceptStream(ctx context.Context) (mux.Stream, error) {
	s.mu.Lock()
	if !s.accepted {
		s.accepted = true
		stream := s.stream
		s.mu.Unlock()
		return stream, nil
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

func (s *oneStreamThenBlockingMuxSession) Close() error {
	s.mu.Lock()
	s.closes++
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Unlock()
	return nil
}

type memoryStream struct {
	bytes.Buffer
	closed bool
}

func (s *memoryStream) Close() error {
	s.closed = true
	return nil
}

type failingWriteStream struct{}

func (f *failingWriteStream) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (f *failingWriteStream) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

func (f *failingWriteStream) Close() error {
	return nil
}

type recordingDialer struct {
	count int
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.count++
	return nil, errors.New("unexpected dial")
}

type blockingResolver struct {
	entered chan struct{}
	once    sync.Once
}

func (r *blockingResolver) ResolveTarget(ctx context.Context, tunnelID domain.TunnelID) (string, error) {
	r.once.Do(func() {
		close(r.entered)
	})
	<-ctx.Done()
	return "", ctx.Err()
}

func (r *blockingResolver) WaitForResolve(t *testing.T) {
	t.Helper()
	select {
	case <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("resolver was not called")
	}
}
