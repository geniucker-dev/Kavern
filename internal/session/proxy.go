package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

type closeWriter interface {
	CloseWrite() error
}

func ProxyBidirectional(ctx context.Context, left, right io.ReadWriteCloser) error {
	if left == nil || right == nil {
		return errors.New("proxy endpoint is nil")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type copyOutcome struct {
		err   error
		fatal bool
	}
	errCh := make(chan copyOutcome, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	go func() {
		<-ctx.Done()
		closeBoth()
	}()

	copyOne := func(dst, src io.ReadWriteCloser) {
		_, err := io.Copy(dst, src)
		err = normalizeCopyError(err)
		fatal := err != nil
		var timeout net.Error
		// Normal completion and a directional timeout can preserve a response.
		// Other hard errors must not block while trying to send directional EOF.
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			if cw, ok := dst.(closeWriter); ok {
				if closeErr := cw.CloseWrite(); closeErr == nil && err != nil {
					fatal = false
				}
			}
		}
		errCh <- copyOutcome{err: err, fatal: fatal}
	}

	go copyOne(right, left)
	go copyOne(left, right)

	var first error
	for i := 0; i < 2; i++ {
		outcome := <-errCh
		if outcome.err != nil && first == nil {
			first = outcome.err
		}
		if outcome.fatal {
			closeBoth()
		}
	}
	closeBoth()
	return first
}

func normalizeCopyError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "read/write on closed pipe") {
		return nil
	}
	return err
}
