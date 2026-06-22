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

	errCh := make(chan error, 2)
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
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		errCh <- normalizeCopyError(err)
	}

	go copyOne(right, left)
	go copyOne(left, right)

	var first error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && first == nil {
			first = err
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
