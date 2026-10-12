package agent_v1

import (
	"bufio"
	"context"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/router"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeDeadlineConn struct {
	net.Conn
	ageDeadlines *atomic.Int64
}

func (c *nativeDeadlineConn) SetDeadline(d time.Time) error {
	if !d.IsZero() {
		c.ageDeadlines.Add(1)
	}
	return c.Conn.SetDeadline(d)
}

type nativeDeadlineListener struct {
	net.Listener
	ageDeadlines *atomic.Int64
}

func (l nativeDeadlineListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &nativeDeadlineConn{c, l.ageDeadlines}, nil
}

func TestLifecycleNativeContinuousAndQuietTargetFlowsCrossHistoricalAges(t *testing.T) {
	owner, svc, server, receiver, clock := lifecycleControlFixture(t)
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var accepted atomic.Int64
	var targetWorkers sync.WaitGroup
	acceptDone := make(chan struct{})
	targetClosed := make(chan struct{}, 2)
	go func() {
		defer close(acceptDone)
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			id := accepted.Add(1)
			targetWorkers.Add(1)
			go func() {
				defer targetWorkers.Done()
				defer c.Close()
				defer func() { targetClosed <- struct{}{} }()
				_, _ = fmt.Fprintf(c, "target-%d\n", id)
				reader := bufio.NewReader(c)
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					if _, e = io.WriteString(c, fmt.Sprintf("target-%d:%s", id, line)); e != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = target.Close(); <-acceptDone; targetWorkers.Wait() })
	desired, e := owner.DeviceConfiguration(context.Background(), "device-1")
	if e != nil {
		t.Fatal(e)
	}
	desired.Tunnels[0].TargetAddr = target.Addr().String()
	desired.Tunnels[0].Listener = "127.0.0.1:0"
	if _, e = owner.Commit(context.Background(), []domain.DeviceConfiguration{desired}); e != nil {
		t.Fatal(e)
	}
	entryBefore, _ := svc.registry.lookup(server.auth.SessionID)
	entryBefore.session.expiresAt = svc.now().Add(-time.Hour)
	left, right := net.Pipe()
	startLifecyclePair(t, server, receiver, left, right)
	snapshot, ok := receiver.Snapshot()
	if !ok {
		t.Fatal("initial native snapshot missing")
	}
	receiver.mu.Lock()
	tuple := receiver.currentTupleLocked()
	receiver.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for i := 0; i < snapshot.Policy.Carriers; i++ {
		a, b := net.Pipe()
		limits := muxLimits(policyLimits(snapshot.Policy))
		serverBackend, e := mux.NewSmuxBackend().Client(a, limits)
		if e != nil {
			t.Fatal(e)
		}
		clientBackend, e := mux.NewSmuxBackend().Server(b, limits)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = svc.attachSyncBound(ctx, server.auth, tuple, serverBackend); e != nil {
			t.Fatal(e)
		}
		bounded, e := carrier.New(clientBackend, policyCarrier(snapshot.Policy))
		if e != nil {
			t.Fatal(e)
		}
		client := &SyncClientCarrier{receiver: receiver, backend: clientBackend, carrier: bounded, tuple: tuple, policy: snapshot.Policy}
		receiver.mu.Lock()
		receiver.carriers[client] = struct{}{}
		receiver.mu.Unlock()
		done := make(chan error, 1)
		go func() { done <- client.Run(ctx, nil) }()
		t.Cleanup(func() {
			cancel()
			_ = client.Close()
			_ = serverBackend.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("native carrier handlers did not join")
			}
		})
	}
	if e = receiver.RequestReady(ctx); e != nil {
		t.Fatal(e)
	}
	routes := router.New(owner, svc.sessions)
	var ageDeadlines atomic.Int64
	scope := &nativeTrackedRoutes{routes: routes, ageDeadlines: &ageDeadlines}
	public, e := router.NewListenerService(owner, scope, nil)
	if e != nil {
		t.Fatal(e)
	}
	publicDone := make(chan error, 1)
	go func() { publicDone <- public.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-publicDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("public listener workers did not join")
		}
	})
	<-public.Started()
	var address string
	awaitLifecycle(t, func() bool {
		for _, s := range public.Status() {
			if s.TunnelID == "server-tunnel" && s.State == "bound" {
				address = s.BoundAddress
				return true
			}
		}
		return false
	})
	connect := func() (net.Conn, *bufio.Reader, string) {
		t.Helper()
		c, e := net.DialTimeout("tcp", address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		reader := bufio.NewReader(c)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		id, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal("target-confirmed greeting", e)
		}
		_ = c.SetReadDeadline(time.Time{})
		return c, reader, id[:len(id)-1]
	}
	continuous, continuousReader, continuousID := connect()
	quiet, quietReader, quietID := connect()
	exchange := func(c net.Conn, reader *bufio.Reader, id, payload string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, e := io.WriteString(c, payload+"\n")
		if e != nil {
			t.Fatal(e)
		}
		line, e := reader.ReadString('\n')
		if e != nil || line != id+":"+payload+"\n" {
			t.Fatal("target connection changed or bytes lost", e)
		}
		_ = c.SetDeadline(time.Time{})
	}
	exchange(continuous, continuousReader, continuousID, "start")
	exchange(quiet, quietReader, quietID, "quiet-start")
	entry, _ := svc.registry.lookup(server.auth.SessionID)
	lease := entry.session.serverLease()
	awaitLifecycle(t, func() bool { return clock.active() == 2 })
	for i := 0; i < 125; i++ {
		clock.Advance(30 * time.Second)
		generation := domain.ConfigRevision(i + 2)
		awaitLifecycle(t, func() bool {
			a, b := lifecycleGeneration(lease, receiver.lifecycle)
			return a == generation && b == generation
		})
		exchange(continuous, continuousReader, continuousID, fmt.Sprintf("continuous-%d", i))
		awaitLifecycle(t, func() bool { return clock.active() == 2 })
	}
	exchange(quiet, quietReader, quietID, "quiet-after-hour")
	if accepted.Load() != 2 || ageDeadlines.Load() != 0 || scope.ageContexts.Load() != 0 {
		t.Fatal("native flow reconnected or retained public socket age deadline", accepted.Load(), ageDeadlines.Load())
	}
	if current, ok := receiver.ReadySnapshot(); !ok || current.Revision != snapshot.Revision {
		t.Fatal("renewal changed desired readiness")
	}
	desired, e = owner.DeviceConfiguration(ctx, "device-1")
	if e != nil {
		t.Fatal(e)
	}
	desired.Device.Enabled = false
	if _, e = owner.Commit(ctx, []domain.DeviceConfiguration{desired}); e != nil {
		t.Fatal(e)
	}
	for _, c := range []net.Conn{continuous, quiet} {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, e = c.Read(b[:]); e == nil {
			t.Fatal("revoked native stream remained live")
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-targetClosed:
		case <-time.After(time.Second):
			t.Fatal("revoked target failed to join")
		}
	}
	awaitLifecycle(t, func() bool { return clock.active() == 0 })
}

type nativeTrackedRoutes struct {
	routes       *router.Router
	ageDeadlines *atomic.Int64
	ageContexts  atomic.Int64
}

func (s *nativeTrackedRoutes) RouteListenerTCP(ctx context.Context, id domain.TunnelID, generation uint64, c net.Conn) error {
	if _, ok := ctx.Deadline(); ok {
		s.ageContexts.Add(1)
	}
	return s.routes.RouteListenerTCP(ctx, id, generation, &nativeDeadlineConn{c, s.ageDeadlines})
}
