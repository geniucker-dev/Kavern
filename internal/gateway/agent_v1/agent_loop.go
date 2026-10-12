package agent_v1

import (
	"context"
	"errors"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"net"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
)

type TargetResolver interface {
	ResolveTarget(ctx context.Context, tunnelID domain.TunnelID) (string, error)
}

type TargetMap map[domain.TunnelID]string

func (m TargetMap) ResolveTarget(ctx context.Context, tunnelID domain.TunnelID) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	target, ok := m[tunnelID]
	if !ok || target == "" {
		return "", ErrUnknownTunnelTarget
	}
	return target, nil
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type TCPDialer struct {
	net.Dialer
}

type AgentDataLoop struct {
	Carrier      *carrier.Carrier
	MaxHandlers  int
	Session      mux.Session
	Targets      TargetResolver
	Dialer       Dialer
	Handlers     sync.WaitGroup
	handleStream func(context.Context, mux.Stream) error
}

func (l *AgentDataLoop) Run(ctx context.Context) error {
	if l.Session == nil || (l.Targets == nil && l.handleStream == nil) {
		return ErrInvalidInput
	}
	maxHandlers := l.MaxHandlers
	if maxHandlers == 0 {
		maxHandlers = 64
	}
	if maxHandlers < 1 || maxHandlers > 1024 {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		<-ctx.Done()
		_ = l.Session.Close()
	}()
	shutdown := func() {
		cancel()
		_ = l.Session.Close()
		l.Handlers.Wait()
		<-monitorDone
	}
	slots := make(chan struct{}, maxHandlers)
	dialer := l.Dialer
	if dialer == nil {
		dialer = &TCPDialer{Dialer: net.Dialer{Timeout: 5 * time.Second}}
	}
	for {
		if err := ctx.Err(); err != nil {
			shutdown()
			return err
		}
		stream, err := l.Session.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				shutdown()
				return ctx.Err()
			}
			if isClosedStreamError(err) {
				shutdown()
				return nil
			}
			shutdown()
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = stream.Close()
			continue
		}
		var lease *carrier.Lease
		if l.Carrier != nil {
			lease, err = l.Carrier.AdoptStream(ctx, stream)
			if err != nil {
				<-slots
				_ = stream.Close()
				continue
			}
			stream = lease.Stream
		}
		l.Handlers.Add(1)
		go func() {
			defer l.Handlers.Done()
			defer func() { <-slots }()
			if lease != nil {
				defer lease.Release()
			}
			if l.handleStream != nil {
				_ = l.handleStream(ctx, stream)
			} else {
				_ = HandleAgentStream(ctx, stream, l.Targets, dialer)
			}
		}()
	}
}

func HandleAgentStream(ctx context.Context, stream mux.Stream, targets TargetResolver, dialer Dialer) error {
	stream = &ownedStream{Stream: stream}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(callbackDone); _ = stream.Close() })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		_ = stream.Close()
	}()
	if targets == nil {
		return ErrInvalidInput
	}
	if dialer == nil {
		dialer = &TCPDialer{Dialer: net.Dialer{Timeout: 5 * time.Second}}
	}
	if deadline, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadline.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer deadline.SetReadDeadline(time.Time{})
	}
	metadata, err := ReadOpenStreamMetadata(stream)
	if err != nil {
		return err
	}
	if deadline, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadline.SetReadDeadline(time.Time{})
	}
	target, err := targets.ResolveTarget(ctx, metadata.TunnelID)
	if err != nil {
		return err
	}
	targetConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer targetConn.Close()
	return session.ProxyBidirectional(ctx, stream, targetConn)
}

func isClosedStreamError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

type ownedStream struct {
	mux.Stream
	once sync.Once
	err  error
}

func (s *ownedStream) Close() error { s.once.Do(func() { s.err = s.Stream.Close() }); return s.err }
func (s *ownedStream) CloseWrite() error {
	if cw, ok := s.Stream.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return ErrUnsupportedTunnelProtocol
}
func (s *ownedStream) SetReadDeadline(t time.Time) error {
	if d, ok := s.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
