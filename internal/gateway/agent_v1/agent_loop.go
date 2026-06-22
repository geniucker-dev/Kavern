package agent_v1

import (
	"context"
	"errors"
	"net"
	"sync"

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
	Session  mux.Session
	Targets  TargetResolver
	Dialer   Dialer
	Handlers sync.WaitGroup
}

func (l *AgentDataLoop) Run(ctx context.Context) error {
	if l.Session == nil || l.Targets == nil {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = l.Session.Close()
	}()
	shutdown := func() {
		cancel()
		_ = l.Session.Close()
		l.Handlers.Wait()
	}
	dialer := l.Dialer
	if dialer == nil {
		dialer = &TCPDialer{}
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
		l.Handlers.Add(1)
		go func() {
			defer l.Handlers.Done()
			_ = HandleAgentStream(ctx, stream, l.Targets, dialer)
		}()
	}
}

func HandleAgentStream(ctx context.Context, stream mux.Stream, targets TargetResolver, dialer Dialer) error {
	defer stream.Close()
	if targets == nil {
		return ErrInvalidInput
	}
	if dialer == nil {
		dialer = &TCPDialer{}
	}
	metadata, err := ReadOpenStreamMetadata(stream)
	if err != nil {
		return err
	}
	target, err := targets.ResolveTarget(ctx, metadata.TunnelID)
	if err != nil {
		return err
	}
	targetConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return session.ProxyBidirectional(ctx, stream, targetConn)
}

func isClosedStreamError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
