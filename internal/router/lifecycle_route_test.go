package router

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/testutil"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleRouteSession struct {
	*testutil.FakeSession
	renewable bool
	observed  chan context.Context
	stream    session.AgentStream
}

func (s *lifecycleRouteSession) RenewableStreams() bool { return s.renewable }
func (s *lifecycleRouteSession) OpenStream(ctx context.Context, req domain.StreamOpenRequest) (session.AgentStream, error) {
	s.observed <- ctx
	return s.stream, nil
}

type lifecycleSocket struct {
	net.Conn
	deadlines *atomic.Int64
}

func (c lifecycleSocket) SetDeadline(d time.Time) error {
	if !d.IsZero() {
		c.deadlines.Add(1)
	}
	return c.Conn.SetDeadline(d)
}

type lifecycleListener struct {
	net.Listener
	deadlines *atomic.Int64
}

func (l lifecycleListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return lifecycleSocket{c, l.deadlines}, nil
}
func TestPublicListenerSelectsRenewableLifetimeAndRetainsNonrenewableAges(t *testing.T) {
	for _, renewable := range []bool{false, true} {
		t.Run(map[bool]string{false: "nonrenewable", true: "renewable"}[renewable], func(t *testing.T) {
			owner := listenerOwner(t, "localhost:0")
			manager := session.NewManager()
			remote, peer := net.Pipe()
			defer peer.Close()
			agent := &lifecycleRouteSession{FakeSession: testutil.NewFakeSession("session-a", "a"), renewable: renewable, observed: make(chan context.Context, 1), stream: remote}
			if e := manager.Attach(context.Background(), agent); e != nil {
				t.Fatal(e)
			}
			routes := New(owner, manager)
			public, e := NewListenerService(owner, routes, nil)
			if e != nil {
				t.Fatal(e)
			}
			var deadlines atomic.Int64
			public.listen = func(ctx context.Context, address string) (net.Listener, error) {
				l, e := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
				if e != nil {
					return nil, e
				}
				return lifecycleListener{l, &deadlines}, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- public.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("listener lifecycle workers not joined")
				}
			}()
			bound := listenerStatus(t, public, "a", func(s ListenerStatus) bool { return s.State == "bound" })
			client, e := net.DialTimeout("tcp", bound.BoundAddress, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			var routeCtx context.Context
			select {
			case routeCtx = <-agent.observed:
			case <-time.After(time.Second):
				t.Fatal("route was not admitted")
			}
			deadline, hasDeadline := routeCtx.Deadline()
			if hasDeadline == renewable {
				t.Fatal("route lifetime capability was ignored")
			}
			if !renewable {
				remaining := time.Until(deadline)
				if remaining < PublicRouteTimeout-time.Second || remaining > PublicRouteTimeout {
					t.Fatal("nonrenewable route context age changed", remaining)
				}
				if deadlines.Load() != 1 {
					t.Fatal("nonrenewable socket age deadline missing")
				}
			} else if deadlines.Load() != 0 {
				t.Fatal("renewable socket retained age deadline")
			}
			cancel()
			select {
			case <-routeCtx.Done():
			case <-time.After(time.Second):
				t.Fatal("route did not retire on listener cancellation")
			}
		})
	}
}
