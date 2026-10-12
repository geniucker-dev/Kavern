package main

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
	"github.com/geniucker-dev/kavern/internal/gateway/legacy_npc"
	"github.com/geniucker-dev/kavern/internal/router"
	"github.com/geniucker-dev/kavern/internal/session"
	"github.com/geniucker-dev/kavern/internal/store"
	"net"
	"sync"
)

// syncService is the owned native command assembly. Its one owner holds the
// exclusive state lock; the optional legacy gateway stays a separate handler.
type syncService struct {
	owner         *store.ConfigOwner
	manager       *session.Manager
	legacy        *legacy_npc.Gateway
	legacyListen  string
	legacyAddress string
	ready         func() error
	auth          *agent_v1.AuthService
	routes        *router.Router
	public        *router.ListenerService
	trust         *tls.Config
	slots         chan struct{}
	mu            sync.Mutex
	started       bool
	address       string
	cancel        context.CancelFunc
	done          chan struct{}
	closeErr      error
}

func newSyncService(path string, key []byte, trust *tls.Config) (*syncService, error) {
	if trust == nil || len(trust.Certificates) == 0 {
		return nil, errors.New("verified TLS server configuration required")
	}
	owner, err := store.OpenConfigOwner(path, key, domain.DefaultNativePolicy())
	if err != nil {
		return nil, err
	}
	if err := owner.ValidateNativeStartup(context.Background()); err != nil {
		_ = owner.Close()
		return nil, errors.New("native state migration required: store valid bounded TCP targets and carrier policy on the server before starting synchronized commands")
	}
	manager := session.NewManager()
	routes := router.New(owner, manager)
	slots := make(chan struct{}, router.MaxAcceptedHandlers)
	public, err := router.NewListenerService(owner, routes, slots)
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	return &syncService{manager: manager, owner: owner, auth: agent_v1.NewAuthService(owner, manager), routes: routes, public: public, trust: trust.Clone(), slots: slots, done: make(chan struct{})}, nil
}
func (s *syncService) LegacyAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.legacyAddress
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
		s.legacyAddress = ""
		s.mu.Unlock()
		close(s.done)
		result = errors.Join(result, closeErr)
	}()
	type endpoint struct {
		socket  net.Listener
		handler func(net.Conn)
	}
	var endpoints []endpoint
	closeSockets := func() {
		for _, e := range endpoints {
			_ = e.socket.Close()
		}
	}
	defer closeSockets()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return err
	}
	endpoints = append(endpoints, endpoint{listener, func(raw net.Conn) { _ = s.auth.ServeSyncTransport(ctx, tls.Server(raw, s.trust), s.owner, nil) }})
	s.mu.Lock()
	s.address = listener.Addr().String()
	s.mu.Unlock()
	if s.legacy != nil {
		socket, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.legacyListen)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, endpoint{socket, func(raw net.Conn) { _ = s.legacy.ServeConn(ctx, raw) }})
		s.mu.Lock()
		s.legacyAddress = socket.Addr().String()
		s.mu.Unlock()
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); closeSockets() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	publicDone := make(chan error, 1)
	go func() { publicDone <- s.public.Run(ctx) }()
	var loops, workers sync.WaitGroup
	failures := make(chan error, len(endpoints))
	for _, e := range endpoints {
		loops.Add(1)
		go func(e endpoint) {
			defer loops.Done()
			for {
				raw, err := e.socket.Accept()
				if err != nil {
					if ctx.Err() == nil {
						select {
						case failures <- err:
						case <-ctx.Done():
						}
					}
					return
				}
				select {
				case s.slots <- struct{}{}:
				default:
					_ = raw.Close()
					continue
				}
				workers.Add(1)
				go func() { defer workers.Done(); serveConnection(ctx, raw, e.handler, s.slots) }()
			}
		}(e)
	}
	publicJoined := false
	if s.ready != nil {
		select {
		case <-s.public.Started():
			err = s.ready()
		case err = <-publicDone:
			publicJoined = true
		case err = <-failures:
		case <-ctx.Done():
		}
	}
	if err == nil && !publicJoined && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case err = <-failures:
		case err = <-publicDone:
			publicJoined = true
		}
	}
	cancel()
	closeSockets()
	loops.Wait()
	if !publicJoined {
		err = errors.Join(err, <-publicDone)
	}
	workers.Wait()
	return err
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
