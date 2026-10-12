package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type uiConnection struct {
	net.Conn
	once sync.Once
}
type uiListener struct {
	net.Listener
	mu      sync.Mutex
	closed  bool
	live    map[*uiConnection]struct{}
	slots   chan struct{}
	workers sync.WaitGroup
}

func (l *uiListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		peer, _, e := net.SplitHostPort(c.RemoteAddr().String())
		if e != nil || peer != "127.0.0.1" {
			c.Close()
			continue
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			c.Close()
			return nil, net.ErrClosed
		}
		select {
		case l.slots <- struct{}{}:
			l.workers.Add(1)
			v := &uiConnection{Conn: c}
			l.live[v] = struct{}{}
			l.mu.Unlock()
			return v, nil
		default:
			l.mu.Unlock()
			c.Close()
		}
	}
}
func (l *uiListener) finish(c *uiConnection) {
	c.once.Do(func() { l.mu.Lock(); delete(l.live, c); l.mu.Unlock(); <-l.slots; l.workers.Done() })
}
func (l *uiListener) Close() error {
	l.mu.Lock()
	l.closed = true
	connections := make([]net.Conn, 0, len(l.live))
	for c := range l.live {
		connections = append(connections, c)
	}
	l.mu.Unlock()
	e := l.Listener.Close()
	for _, c := range connections {
		_ = c.Close()
	}
	return e
}
func serveUI(ctx context.Context, bridge *uiBridge, socket net.Listener, out io.Writer, launch string) error {
	listener := &uiListener{Listener: socket, live: make(map[*uiConnection]struct{}), slots: make(chan struct{}, uiMaxConnections)}
	server := &http.Server{Handler: bridge, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }, ConnState: func(c net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			if v, ok := c.(*uiConnection); ok {
				listener.finish(v)
			}
		}
	}}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	if _, e := fmt.Fprintln(out, launch); e != nil {
		_ = server.Close()
		_ = listener.Close()
		<-done
		listener.workers.Wait()
		return errors.New("cannot deliver browser launch URL")
	}
	launch = ""
	var result error
	joined := false
	select {
	case <-ctx.Done():
	case result = <-done:
		joined = true
	}
	bridge.auth.close()
	_ = server.Close()
	_ = listener.Close()
	if !joined {
		result = <-done
	}
	listener.workers.Wait()
	bridge.client.Close()
	if errors.Is(result, http.ErrServerClosed) {
		return nil
	}
	return result
}
