package mux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSmuxBackendOpensMultipleStreamsOverNetPipe(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	backend := NewSmuxBackend()
	serverReady := make(chan Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		server, err := backend.Server(serverConn, Config{})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- server
	}()

	client, err := backend.Client(clientConn, Config{})
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer client.Close()

	var server Session
	select {
	case err := <-serverErr:
		t.Fatalf("server session: %v", err)
	case server = <-serverReady:
	case <-time.After(2 * time.Second):
		t.Fatal("server session timed out")
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		accepted := make(chan Stream, 1)
		acceptErr := make(chan error, 1)
		go func() {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- stream
		}()

		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}

		var peer Stream
		select {
		case err := <-acceptErr:
			t.Fatalf("accept stream %d: %v", i, err)
		case peer = <-accepted:
		case <-ctx.Done():
			t.Fatalf("accept stream %d timed out: %v", i, ctx.Err())
		}

		msg := []byte{byte('a' + i)}
		readDone := make(chan []byte, 1)
		readErr := make(chan error, 1)
		go func() {
			buf := make([]byte, 1)
			if _, err := io.ReadFull(peer, buf); err != nil {
				readErr <- err
				return
			}
			readDone <- buf
		}()

		if _, err := stream.Write(msg); err != nil {
			t.Fatalf("write stream %d: %v", i, err)
		}
		select {
		case err := <-readErr:
			t.Fatalf("read stream %d: %v", i, err)
		case got := <-readDone:
			if string(got) != string(msg) {
				t.Fatalf("read stream %d = %q, want %q", i, got, msg)
			}
		case <-ctx.Done():
			t.Fatalf("read stream %d timed out: %v", i, ctx.Err())
		}
		_ = stream.Close()
		_ = peer.Close()
	}
}
