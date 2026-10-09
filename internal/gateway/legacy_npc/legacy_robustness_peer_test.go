package legacy_npc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const robustnessWait = 5 * time.Second

var errPeerOverflow = errors.New("test peer bounded queue overflow")

type peerWrite struct {
	frame Frame
	raw   []byte
	done  chan error
}

type peerTerminalResult struct {
	err error
}

// The peer never asserts from a worker. Its owner joins all three workers and
// checks the single terminal result, including any harness-capacity failure.
type robustnessPeer struct {
	conn       net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	once       sync.Once
	terminal   chan peerTerminalResult
	overflow   atomic.Bool
	incoming   chan Frame
	outgoing   chan peerWrite
	writerDone chan struct{}
	mu         sync.Mutex
	changed    chan struct{}
	frames     []Frame
	credit     bool
	echo       bool
	held       map[int32]bool
}

func newRobustnessPeer(t *testing.T, conn net.Conn, credit, echo bool) *robustnessPeer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &robustnessPeer{conn: conn, ctx: ctx, cancel: cancel, terminal: make(chan peerTerminalResult, 1), incoming: make(chan Frame, 256), outgoing: make(chan peerWrite, 1024), writerDone: make(chan struct{}), changed: make(chan struct{}), credit: credit, echo: echo, held: make(map[int32]bool)}
	p.wg.Add(3)
	go p.readLoop()
	go p.writeLoop()
	go p.scriptLoop()
	t.Cleanup(func() {
		p.cancel()
		_ = p.conn.Close()
		joined := make(chan struct{})
		go func() { p.wg.Wait(); close(joined) }()
		awaitRobustness(t, joined)
		if p.overflow.Load() {
			t.Error(errPeerOverflow)
		}
		select {
		case result := <-p.terminal:
			err := result.err
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				t.Error("test peer worker failed:", err)
			}
		default:
		}
	})
	return p
}

func (p *robustnessPeer) fail(err error) {
	if errors.Is(err, errPeerOverflow) {
		p.overflow.Store(true)
	}
	p.once.Do(func() { p.terminal <- peerTerminalResult{err: err}; p.cancel(); _ = p.conn.Close() })
}

func TestLegacyRobustnessPeerOverflowSurvivesTerminalEOF(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &robustnessPeer{conn: left, ctx: ctx, cancel: cancel, terminal: make(chan peerTerminalResult, 1)}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		p.fail(io.EOF)
		p.fail(errPeerOverflow)
	}()
	workers.Wait()
	if !p.overflow.Load() || len(p.terminal) != 1 {
		t.Fatal("harness overflow was lost or terminal result duplicated")
	}
}

func (p *robustnessPeer) readLoop() {
	defer p.wg.Done()
	for {
		frame, err := ReadFrame(p.conn)
		if err != nil {
			p.fail(err)
			return
		}
		select {
		case p.incoming <- frame:
		case <-p.ctx.Done():
			return
		default:
			p.fail(errPeerOverflow)
			return
		}
	}
}

func (p *robustnessPeer) writeLoop() {
	defer p.wg.Done()
	defer close(p.writerDone)
	for {
		select {
		case <-p.ctx.Done():
			return
		case command := <-p.outgoing:
			err := p.conn.SetWriteDeadline(time.Now().Add(robustnessWait))
			if err == nil {
				if command.raw != nil {
					err = writeAll(p.conn, command.raw)
				} else {
					err = WriteFrame(p.conn, command.frame)
				}
			}
			if command.done != nil {
				command.done <- err
			}
			if err != nil {
				p.fail(err)
				return
			}
		}
	}
}

func (p *robustnessPeer) enqueue(command peerWrite) {
	select {
	case <-p.ctx.Done():
		if command.done != nil {
			command.done <- p.ctx.Err()
		}
	case p.outgoing <- command:
	default:
		p.fail(errPeerOverflow)
	}
}

func (p *robustnessPeer) scriptLoop() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case frame := <-p.incoming:
			p.mu.Lock()
			if len(p.frames) == 8192 {
				p.mu.Unlock()
				p.fail(errPeerOverflow)
				return
			}
			p.frames = append(p.frames, frame)
			credit, echo := p.credit && !p.held[frame.StreamID], p.echo
			close(p.changed)
			p.changed = make(chan struct{})
			p.mu.Unlock()
			switch frame.Flag {
			case FrameFlagPing:
				p.enqueue(peerWrite{frame: Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: frame.Content}})
			case FrameFlagStreamOpen:
				p.enqueue(peerWrite{frame: Frame{Flag: FrameFlagStreamAccepted, StreamID: frame.StreamID}})
			case FrameFlagDataContinue, FrameFlagDataFinal:
				if credit {
					p.enqueue(peerWrite{frame: Frame{Flag: FrameFlagWindow, StreamID: frame.StreamID, WindowState: packWindowState(defaultLegacyMuxWindow, uint64(len(frame.Content)))}})
				}
				if echo {
					p.enqueue(peerWrite{frame: frame})
				}
			case FrameFlagStreamClose:
				p.enqueue(peerWrite{frame: frame})
			}
		}
	}
}

func (p *robustnessPeer) send(t *testing.T, frame Frame) {
	t.Helper()
	p.sendCommand(t, peerWrite{frame: frame})
}

func (p *robustnessPeer) sendCommand(t *testing.T, command peerWrite) {
	t.Helper()
	done := make(chan error, 1)
	command.done = done
	p.enqueue(command)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("test peer write failed")
		}
	case <-p.ctx.Done():
		// A deliberately malformed frame can close the mux immediately after
		// delivery, before the owner receives the successful writer result.
		awaitRobustness(t, p.writerDone)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("test peer write failed")
			}
		default:
			t.Fatal("test peer stopped before write completion")
		}
	case <-time.After(robustnessWait):
		t.Fatal("test peer write did not finish")
	}
}

func (p *robustnessPeer) wait(t *testing.T, predicate func([]Frame) bool) []Frame {
	t.Helper()
	timer := time.NewTimer(robustnessWait)
	defer timer.Stop()
	for {
		p.mu.Lock()
		ready := predicate(p.frames)
		notify := p.changed
		var frames []Frame
		if ready {
			frames = append(frames, p.frames...)
		}
		p.mu.Unlock()
		if ready {
			return frames
		}
		select {
		case <-notify:
		case <-p.ctx.Done():
			t.Fatal("test peer stopped before expected frames")
		case <-timer.C:
			t.Fatal("test peer frame wait timed out")
		}
	}
}

func dataFrames(frames []Frame, id int32) []Frame {
	var result []Frame
	for _, f := range frames {
		if f.StreamID == id && (f.Flag == FrameFlagDataContinue || f.Flag == FrameFlagDataFinal) {
			result = append(result, f)
		}
	}
	return result
}

func deterministicPayload(n, seed int) []byte {
	result := make([]byte, n)
	for i := range result {
		result[i] = byte((i*31 + i/251 + seed*17) % 251)
	}
	return result
}

func awaitRobustness(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(robustnessWait):
		t.Fatal("test worker did not finish")
	}
}

func openRobustnessStream(t *testing.T, mux *LegacyMux) *LegacyStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), robustnessWait)
	defer cancel()
	stream, err := mux.OpenStream(ctx)
	if err != nil {
		t.Fatal("open test stream:", err)
	}
	return stream
}

func runRobustnessWorker(t *testing.T, mux *LegacyMux, work func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); work() }()
	t.Cleanup(func() { _ = mux.Close(); awaitRobustness(t, done) })
}
