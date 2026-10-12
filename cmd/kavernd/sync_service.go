package main

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"net"
	"sync"
)

// syncService is a testable owned assembly, deliberately not wired to main's
// native command rollout yet. Its one owner holds the exclusive state lock.
type syncService struct {
	owner    *store.ConfigOwner
	auth     *agent_v1.AuthService
	routes   *router.Router
	public   *router.ListenerService
	trust    *tls.Config
	slots    chan struct{}
	mu       sync.Mutex
	started  bool
	address  string
	cancel   context.CancelFunc
	done     chan struct{}
	closeErr error
}

func newSyncService(path string, key []byte, trust *tls.Config) (*syncService, error) {
	if trust == nil || len(trust.Certificates) == 0 {
		return nil, errors.New("verified TLS server configuration required")
	}
	owner, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		return nil, err
	}
	manager := session.NewManager()
	routes := router.New(owner, manager)
	slots := make(chan struct{}, router.MaxAcceptedHandlers)
	public, err := router.NewListenerService(owner, routes, slots)
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	return &syncService{owner: owner, auth: agent_v1.NewAuthService(owner, manager), routes: routes, public: public, trust: trust.Clone(), slots: slots, done: make(chan struct{})}, nil
}
func (s *syncService) ControlAddress() string { s.mu.Lock(); defer s.mu.Unlock(); return s.address }
func (s *syncService) Run(parent context.Context, address string) (result error) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("synchronized service already started")
	}
	s.started = true
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		closeErr := s.owner.Close()
		s.mu.Lock()
		s.closeErr = closeErr
		s.address = ""
		s.mu.Unlock()
		close(s.done)
		result = errors.Join(result, closeErr)
	}()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	s.mu.Lock()
	s.address = listener.Addr().String()
	s.mu.Unlock()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = listener.Close() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	publicDone := make(chan error, 1)
	go func() { publicDone <- s.public.Run(ctx) }()
	// A control listener failure remains service-fatal, unlike a public failure.
	var workers sync.WaitGroup
	acceptDone := make(chan error, 1)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				acceptDone <- err
				return
			}
			select {
			case s.slots <- struct{}{}:
			default:
				_ = raw.Close()
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				serveConnection(ctx, raw, func(conn net.Conn) { _ = s.auth.ServeSyncTransport(ctx, tls.Server(conn, s.trust), s.owner, nil) }, s.slots)
			}()
		}
	}()
	select {
	case <-ctx.Done():
		err = nil
	case err = <-acceptDone:
		cancel()
		_ = listener.Close()
		<-publicDone
		workers.Wait()
		return err
	case err = <-publicDone:
		cancel()
		_ = listener.Close()
		<-acceptDone
		workers.Wait()
		return err
	}
	cancel()
	_ = listener.Close()
	<-acceptDone
	publicErr := <-publicDone
	workers.Wait()
	return errors.Join(err, publicErr)
}
func (s *syncService) Close() error {
	s.mu.Lock()
	if !s.started {
		s.started = true
		s.mu.Unlock()
		err := s.owner.Close()
		s.mu.Lock()
		s.closeErr = err
		close(s.done)
		s.mu.Unlock()
		return err
	}
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// Keep the existing one-hour native auth/session lifetime in AuthService and
// five-minute public route lifetime in ListenerService. No new lifetime policy.
