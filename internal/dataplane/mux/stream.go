package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

// framedStream provides Kavern half-close independently of backend FIN cleanup.
// Each record is a four-byte length followed by at most 16 KiB. Zero length ends
// the write direction; the underlying stream stays open until both copies finish.
// Reading does not allocate a record-sized buffer: the backend's bounded receive
// queue owns payload and Read consumes it directly into the caller's buffer.
type framedStream struct {
	Stream
	readMu      sync.Mutex
	writeMu     sync.Mutex
	remaining   uint32
	eof         bool
	writeClosed bool
	closeOnce   sync.Once
	closeErr    error
}

const maxStreamRecord = 16 << 10

func (s *framedStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.eof {
		return 0, io.EOF
	}
	if s.remaining == 0 {
		var prefix [4]byte
		if _, err := io.ReadFull(s.Stream, prefix[:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		s.remaining = binary.BigEndian.Uint32(prefix[:])
		if s.remaining == 0 {
			s.eof = true
			return 0, io.EOF
		}
		if s.remaining > maxStreamRecord {
			_ = s.Close()
			return 0, errors.New("invalid mux stream record")
		}
	}
	n, err := s.Stream.Read(p[:min(len(p), int(s.remaining))])
	s.remaining -= uint32(n)
	if err == io.EOF && s.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func (s *framedStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxStreamRecord)
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(n))
		if err := streamWrite(s.Stream, prefix[:]); err != nil {
			return total, err
		}
		written, err := s.Stream.Write(p[:n])
		if written < 0 || written > n {
			return total, io.ErrShortWrite
		}
		total += written
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}
func streamWrite(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}
func (s *framedStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return nil
	}
	s.writeClosed = true
	return streamWrite(s.Stream, make([]byte, 4))
}
func (s *framedStream) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.Stream.Close() })
	return s.closeErr
}
func (s *framedStream) SetReadDeadline(t time.Time) error {
	if d, ok := s.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
