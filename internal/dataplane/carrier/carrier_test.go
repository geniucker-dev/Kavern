package carrier

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
)

func TestCarrierEnforcesMaxStreams(t *testing.T) {
	session := &fakeSession{}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}

	lease, err := carrier.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := carrier.OpenStream(context.Background()); !errors.Is(err, ErrCarrierFull) {
		t.Fatalf("second open error = %v, want %v", err, ErrCarrierFull)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := carrier.OpenStream(context.Background()); err != nil {
		t.Fatalf("open after release: %v", err)
	}
}

func TestCarrierOpenFailureDoesNotLeakSlot(t *testing.T) {
	session := &fakeSession{openErr: errors.New("open failed")}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := carrier.OpenStream(context.Background()); err == nil {
		t.Fatal("expected open failure")
	}
	if got := carrier.ActiveStreams(); got != 0 {
		t.Fatalf("active streams = %d, want 0", got)
	}
	session.openErr = nil
	if _, err := carrier.OpenStream(context.Background()); err != nil {
		t.Fatalf("open after failed open: %v", err)
	}
}

func TestMuxOpenFailureReleasesReservedSlot(t *testing.T) {
	session := &fakeSession{openErr: errors.New("open failed")}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := carrier.OpenStream(context.Background()); err == nil {
		t.Fatal("expected open failure")
	}
	if got := carrier.ActiveStreams(); got != 0 {
		t.Fatalf("active streams = %d, want 0", got)
	}

	session.setOpenErr(nil)
	lease, err := carrier.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("open after failed open: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentOpenStreamDoesNotCallMuxBeyondMaxWhileBlocked(t *testing.T) {
	session := newBlockedSession()
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 2})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 10)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lease, err := carrier.OpenStream(context.Background())
			if err == nil {
				err = lease.Release()
			}
			errs <- err
		}()
	}
	close(start)

	if !session.waitForBlocked(2, time.Second) {
		t.Fatalf("blocked mux opens = %d, want 2", session.OpenCount())
	}
	if got := session.OpenCount(); got != 2 {
		t.Fatalf("mux OpenStream calls while blocked = %d, want 2", got)
	}

	session.releaseBlocked()
	wg.Wait()
	close(errs)

	successes := 0
	full := 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrCarrierFull):
			full++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 2 {
		t.Fatalf("successes = %d, want 2", successes)
	}
	if full != 8 {
		t.Fatalf("full errors = %d, want 8", full)
	}
}

func TestCarrierCloseDuringBlockedOpenReleasesReservedSlotAndClosesStream(t *testing.T) {
	stream := &fakeStream{}
	session := newBlockedSession()
	session.next = []mux.Stream{stream}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		lease, err := carrier.OpenStream(context.Background())
		if err == nil {
			err = lease.Release()
		}
		result <- err
	}()

	if !session.waitForBlocked(1, time.Second) {
		t.Fatalf("blocked mux opens = %d, want 1", session.OpenCount())
	}
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	session.releaseBlocked()

	select {
	case err := <-result:
		if !errors.Is(err, ErrCarrierClosed) {
			t.Fatalf("open error = %v, want %v", err, ErrCarrierClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("open did not return")
	}
	if got := carrier.ActiveStreams(); got != 0 {
		t.Fatalf("active streams = %d, want 0", got)
	}
	if stream.closeCount != 1 {
		t.Fatalf("stream close count = %d, want 1", stream.closeCount)
	}
	if _, err := carrier.OpenStream(context.Background()); !errors.Is(err, ErrCarrierClosed) {
		t.Fatalf("open after close error = %v, want %v", err, ErrCarrierClosed)
	}
}

func TestLeaseReleaseIsIdempotentAndClosesStream(t *testing.T) {
	stream := &fakeStream{}
	session := &fakeSession{next: []mux.Stream{stream}}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := carrier.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if got := carrier.ActiveStreams(); got != 0 {
		t.Fatalf("active streams = %d, want 0", got)
	}
	if stream.closeCount != 1 {
		t.Fatalf("stream close count = %d, want 1", stream.closeCount)
	}
}

func TestCarrierCloseIsIdempotentAndRejectsFutureOpens(t *testing.T) {
	session := &fakeSession{}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 1})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := carrier.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if session.closeCount != 1 {
		t.Fatalf("session close count = %d, want 1", session.closeCount)
	}
	if _, err := carrier.OpenStream(context.Background()); !errors.Is(err, ErrCarrierClosed) {
		t.Fatalf("open after close error = %v, want %v", err, ErrCarrierClosed)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentOpenStreamDoesNotExceedMax(t *testing.T) {
	session := &fakeSession{}
	carrier, err := New(session, Config{MaxStreamsPerCarrier: 3})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	failures := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := carrier.OpenStream(context.Background())
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if errors.Is(err, ErrCarrierFull) {
				failures++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 3 {
		t.Fatalf("successes = %d, want 3", successes)
	}
	if failures != 17 {
		t.Fatalf("failures = %d, want 17", failures)
	}
}

type fakeSession struct {
	mu         sync.Mutex
	openErr    error
	closeErr   error
	closeCount int
	openCount  int
	block      chan struct{}
	blocked    atomic.Int32
	next       []mux.Stream
}

func (s *fakeSession) OpenStream(ctx context.Context) (mux.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.openCount++
	if s.openErr != nil {
		err := s.openErr
		s.mu.Unlock()
		return nil, err
	}
	block := s.block
	s.mu.Unlock()

	if block != nil {
		s.blocked.Add(1)
		<-block
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.openErr != nil {
		return nil, s.openErr
	}
	if len(s.next) > 0 {
		stream := s.next[0]
		s.next = s.next[1:]
		return stream, nil
	}
	return &fakeStream{}, nil
}

func (s *fakeSession) AcceptStream(ctx context.Context) (mux.Stream, error) {
	return nil, errors.New("not implemented")
}

func (s *fakeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	return s.closeErr
}

func (s *fakeSession) OpenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openCount
}

func (s *fakeSession) setOpenErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openErr = err
}

func newBlockedSession() *fakeSession {
	return &fakeSession{block: make(chan struct{})}
}

func (s *fakeSession) waitForBlocked(want int32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.blocked.Load() >= want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return s.blocked.Load() >= want
}

func (s *fakeSession) releaseBlocked() {
	close(s.block)
}

type fakeStream struct {
	closeCount int
}

func (s *fakeStream) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (s *fakeStream) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *fakeStream) Close() error {
	s.closeCount++
	return nil
}

func (s *fakeSession) ReceiveBufferLimit() int { return 0 }
