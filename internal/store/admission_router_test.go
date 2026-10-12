package store

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/testutil"
	"io"
	"net"
	"testing"
)

type admissionRouteSession struct {
	*testutil.FakeSession
	started, canceled, release chan struct{}
	stream                     session.AgentStream
}

func (s *admissionRouteSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	_, _ = s.FakeSession.OpenStream(ctx, req)
	close(s.started)
	<-ctx.Done()
	close(s.canceled)
	<-s.release
	return s.stream, nil
}
func TestRouterStoredAdmissionTracksPendingOpenBeforeRevocation(t *testing.T) {
	o, _, _ := ownerFixture(t, defaultStateFiles())
	manager := session.NewManager()
	remote, target := net.Pipe()
	defer target.Close()
	inbound, client := net.Pipe()
	defer client.Close()
	fake := &admissionRouteSession{FakeSession: testutil.NewFakeSession("session", "a"), started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), stream: remote}
	if err := manager.Attach(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- router.New(o, manager).RouteTCP(context.Background(), domain.Tunnel{ID: "a-tunnel", DeviceID: "b", TargetAddr: "untrusted.example:9", Protocol: "untrusted", Enabled: false}, inbound)
	}()
	await(t, fake.started)
	if o.work.Count() != 1 {
		t.Fatal("pending route not registered")
	}
	c := desired(t, o, "a")
	c.Tunnels[0].Enabled = false
	committed := make(chan error, 1)
	go func() { _, err := o.Commit(context.Background(), []domain.DeviceConfiguration{c}); committed <- err }()
	await(t, fake.canceled)
	close(fake.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("obsolete open escaped", err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if o.work.Count() != 0 {
		t.Fatal("route work retained")
	}
	req := fake.OpenRequests[0]
	if req.Revision != 1 || req.TunnelID != "a-tunnel" || req.Protocol != domain.TunnelProtocolTCP || req.TargetAddr != "" {
		t.Fatal("caller values bypassed authoritative admission")
	}
	if _, err := target.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("late returned stream not closed", err)
	}
	if _, err := client.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("revoked inbound retained", err)
	}
}
