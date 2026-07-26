//go:build legacy_npc_integration && legacy_npc_observe

package legacy_npc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/security"
	"github.com/geniucker-dev/kavern/internal/store"
)

const candidateProofStreamID uint32 = 1

const (
	candidateSessionStreamID             uint32 = 0xffffffff
	candidateSessionControlTimeout              = 3 * time.Second
	candidateStreamOpenTimeout                  = 6 * time.Second
	candidateNearTimeout                        = 4800 * time.Millisecond
	candidateStartupRounds                      = 20
	candidateFullProofBundles                   = 10
	candidateMaxSessionControlFrames            = 16
	candidateMaxSessionControlMismatches        = 2
)

type candidateStrategy string

const (
	candidateStrategyPeerAckOnly     candidateStrategy = "peer_ack_only_then_stream_open"
	candidateStrategyPeerAckThenPing candidateStrategy = "peer_ack_then_server_ping_then_stream_open"
	candidateStrategyInterleaved     candidateStrategy = "peer_ack_then_interleaved_server_ping_and_stream_open"
)

func TestCandidateCodecProof(t *testing.T) {
	strict, err := candidateStrictMode()
	if err != nil {
		t.Fatal(err)
	}
	npcBin := requireNPCBin(t)
	recorder := newObserveRecorder(t, "candidate_codec_proof_gate6b1_6", "", nil)
	recorder.note("candidate_strict_mode", fmt.Sprintf("enabled=%t", strict))

	attempts := make([]candidateStartupObservation, 0, candidateStartupRounds*3)
	for round := 1; round <= candidateStartupRounds; round++ {
		for _, strategy := range []candidateStrategy{candidateStrategyPeerAckOnly, candidateStrategyPeerAckThenPing, candidateStrategyInterleaved} {
			attempt := runCandidateStartupAttempt(t, npcBin, strategy, round)
			if attempt.HarnessErr != nil {
				t.Fatalf("candidate startup harness error strategy=%s round=%d: %s", strategy, round, candidateSanitizeErr(attempt.HarnessErr))
			}
			attempts = append(attempts, attempt)
			recordCandidateStartupAttempt(recorder, attempt)
		}
	}
	recordCandidateStartupReport(recorder, attempts)
	selected := selectCandidateStrategy(attempts)
	if selected == "" {
		recorder.note("candidate_strategy_selected", "none")
		recorder.note("candidate_readiness", "insufficient for Gate 6B-2")
		if strict {
			t.Fatal("candidate startup matrix did not select a qualifying strategy")
		}
		return
	}
	recorder.note("candidate_strategy_selected", string(selected))

	bundles := make([]candidateFullProofBundle, 0, candidateFullProofBundles)
	for bundle := 1; bundle <= candidateFullProofBundles; bundle++ {
		proof := candidateFullProofBundle{Bundle: bundle, Strategy: selected}
		proof.Metadata = runCandidatePumpedCheckpoint(t, npcBin, selected, bundle, "M", candidatePumpedMetadataDial)
		if proof.Metadata.HarnessErr != nil {
			t.Fatalf("candidate full proof harness error bundle=%d checkpoint=M: %s", bundle, candidateSanitizeErr(proof.Metadata.HarnessErr))
		}
		proof.Payload = runCandidatePumpedCheckpoint(t, npcBin, selected, bundle, "P", candidatePumpedPayloadEcho)
		if proof.Payload.HarnessErr != nil {
			t.Fatalf("candidate full proof harness error bundle=%d checkpoint=P: %s", bundle, candidateSanitizeErr(proof.Payload.HarnessErr))
		}
		proof.Close = runCandidatePumpedCheckpoint(t, npcBin, selected, bundle, "X", candidatePumpedClose)
		if proof.Close.HarnessErr != nil {
			t.Fatalf("candidate full proof harness error bundle=%d checkpoint=X: %s", bundle, candidateSanitizeErr(proof.Close.HarnessErr))
		}
		bundles = append(bundles, proof)
		recordCandidateFullProofBundle(recorder, proof)
	}
	if !candidateFullProofsPass(bundles) {
		recorder.note("candidate_readiness", "insufficient for Gate 6B-2")
		if strict {
			t.Fatal("selected candidate strategy failed one or more full proofs")
		}
		return
	}
	recorder.note("candidate_readiness", "sufficient for Gate 6B-2 plan")
}

func candidateStrictMode() (bool, error) {
	switch os.Getenv("KAVERN_CANDIDATE_REQUIRE_SUFFICIENT") {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("KAVERN_CANDIDATE_REQUIRE_SUFFICIENT must be unset or exactly 1")
	}
}

type candidateResultClass string

const (
	candidateResultSuccess  candidateResultClass = "success"
	candidateResultProtocol candidateResultClass = "protocol_result_failure"
)

type candidateStartupObservation struct {
	Strategy         candidateStrategy
	Round            int
	Client00BodyLen  int
	Client00AckSent  bool
	Server00Sent     bool
	Client08Received bool
	Stream06Sent     bool
	Stream01Received bool
	AckTo01          time.Duration
	Stream06To01     time.Duration
	UnexpectedOpcode string
	NearTimeout      bool
	CleanupBounded   bool
	NPCExitStatus    string
	Result           candidateResultClass
	ProtocolErr      error
	HarnessErr       error
}

type candidateCheckpointProof struct {
	Checkpoint       string
	Bundle           int
	Strategy         candidateStrategy
	TargetDialed     bool
	TargetPayload    bool
	ResponseReturned bool
	CloseSent        bool
	CloseReceived    bool
	TargetClosed     bool
	ChanEOF          bool
	NoHang           bool
	WindowCount      int
	WindowStreamIDs  []uint32
	Result           candidateResultClass
	ProtocolErr      error
	HarnessErr       error
}

type candidateFullProofBundle struct {
	Bundle   int
	Strategy candidateStrategy
	Metadata candidateCheckpointProof
	Payload  candidateCheckpointProof
	Close    candidateCheckpointProof
}

type candidatePumpEventKind string

const (
	candidatePumpPeerPingAck candidatePumpEventKind = "peer_00_acknowledged"
	candidatePumpSessionAck  candidatePumpEventKind = "peer_08_observed"
	candidatePumpWindow      candidatePumpEventKind = "peer_05_observed"
	candidatePumpStreamOpen  candidatePumpEventKind = "peer_01_observed"
	candidatePumpData        candidatePumpEventKind = "peer_03_observed"
	candidatePumpClose       candidatePumpEventKind = "peer_07_observed"
)

type candidatePumpEvent struct {
	Kind         candidatePumpEventKind
	Frame        candidateCodecFrame
	ReceivedAt   time.Time
	AckCompleted time.Time
}

type candidatePumpCommand struct {
	Label  string
	Frame  []byte
	Result chan candidatePumpWriteResult
}

type candidatePumpWriteResult struct {
	Completed time.Time
	Err       error
}

type candidatePumpInvariantError struct {
	reason string
}

func (e *candidatePumpInvariantError) Error() string {
	return "candidate pump invariant: " + e.reason
}

type candidateChanPump struct {
	conn     net.Conn
	codec    *candidateProofCodec
	ctx      context.Context
	cancel   context.CancelFunc
	frames   chan candidateCodecFrame
	commands chan candidatePumpCommand
	events   chan candidatePumpEvent
	terminal chan error
	done     chan struct{}

	readerWG  sync.WaitGroup
	writerWG  sync.WaitGroup
	termOnce  sync.Once
	mu        sync.Mutex
	err       error
	termCount int
}

func newCandidateChanPump(parent context.Context, conn net.Conn, recorder *observeRecorder) *candidateChanPump {
	ctx, cancel := context.WithCancel(parent)
	pump := &candidateChanPump{
		conn:     conn,
		codec:    &candidateProofCodec{conn: conn, recorder: recorder},
		ctx:      ctx,
		cancel:   cancel,
		frames:   make(chan candidateCodecFrame, 32),
		commands: make(chan candidatePumpCommand, 8),
		events:   make(chan candidatePumpEvent, 64),
		terminal: make(chan error, 1),
		done:     make(chan struct{}),
	}
	pump.readerWG.Add(1)
	go pump.readLoop()
	pump.writerWG.Add(1)
	go pump.coordinatorLoop()
	return pump
}

func (p *candidateChanPump) readLoop() {
	defer p.readerWG.Done()
	for {
		frame, err := p.codec.readFrame(p.ctx, time.Second)
		if errors.Is(err, osErrTimeout) {
			continue
		}
		if err != nil {
			if p.ctx.Err() == nil {
				p.reportTerminal(err)
			}
			return
		}
		select {
		case p.frames <- frame:
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *candidateChanPump) coordinatorLoop() {
	defer p.writerWG.Done()
	defer close(p.done)
	defer close(p.events)
	defer p.failPendingCommands()
	defer func() {
		p.cancel()
		_ = p.conn.Close()
		p.readerWG.Wait()
	}()

	for {
		if err := p.drainFrames(); err != nil {
			p.setErr(err)
			return
		}
		select {
		case <-p.ctx.Done():
			return
		case err := <-p.terminal:
			p.setErr(err)
			return
		case frame := <-p.frames:
			if err := p.handleFrame(frame); err != nil {
				p.setErr(err)
				return
			}
		case command := <-p.commands:
			if err := p.drainFrames(); err != nil {
				p.respond(command, candidatePumpWriteResult{Err: err})
				p.setErr(err)
				return
			}
			p.writeCommand(command)
		}
	}
}

func (p *candidateChanPump) drainFrames() error {
	for {
		select {
		case frame := <-p.frames:
			if err := p.handleFrame(frame); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (p *candidateChanPump) handleFrame(frame candidateCodecFrame) error {
	p.codec.logFrame("npc_to_fake_server", frame)
	event := candidatePumpEvent{Frame: frame, ReceivedAt: time.Now()}
	switch frame.Opcode {
	case 0x00:
		if frame.StreamID != candidateSessionStreamID || len(frame.Body) == 0 || len(frame.Body) > 4096 {
			return fmt.Errorf("malformed peer session ping")
		}
		if err := p.codec.writeSessionControl(0x08, candidateSessionStreamID, frame.Body); err != nil {
			return err
		}
		event.Kind = candidatePumpPeerPingAck
		event.AckCompleted = time.Now()
	case 0x08:
		if frame.StreamID != candidateSessionStreamID || len(frame.Body) == 0 || len(frame.Body) > 4096 {
			return fmt.Errorf("malformed peer session acknowledgement")
		}
		event.Kind = candidatePumpSessionAck
	case 0x05:
		if frame.StreamID != candidateProofStreamID || len(frame.Body) != 8 {
			return fmt.Errorf("malformed candidate window control")
		}
		event.Kind = candidatePumpWindow
	case 0x01:
		if frame.StreamID != candidateProofStreamID || len(frame.Body) != 0 {
			return fmt.Errorf("malformed candidate stream acknowledgement")
		}
		event.Kind = candidatePumpStreamOpen
	case 0x03:
		if frame.StreamID != candidateProofStreamID {
			return fmt.Errorf("unexpected candidate data stream=%d", frame.StreamID)
		}
		event.Kind = candidatePumpData
	case 0x07:
		if frame.StreamID != candidateProofStreamID || len(frame.Body) != 0 {
			return fmt.Errorf("malformed candidate close")
		}
		event.Kind = candidatePumpClose
	default:
		return fmt.Errorf("unsupported candidate opcode=0x%02x", frame.Opcode)
	}
	select {
	case p.events <- event:
		return nil
	default:
		return &candidatePumpInvariantError{reason: "event channel exhausted"}
	}
}

func (p *candidateChanPump) writeCommand(command candidatePumpCommand) {
	p.codec.note("candidate_pump_write", command.Label)
	err := p.codec.writeBounded(command.Frame)
	p.respond(command, candidatePumpWriteResult{Completed: time.Now(), Err: err})
	if err != nil {
		p.setErr(err)
		p.cancel()
	}
}

func (p *candidateChanPump) respond(command candidatePumpCommand, result candidatePumpWriteResult) {
	select {
	case command.Result <- result:
	default:
		p.setErr(&candidatePumpInvariantError{reason: "command result channel exhausted"})
	}
}

func (p *candidateChanPump) reportTerminal(err error) {
	p.termOnce.Do(func() {
		p.mu.Lock()
		p.termCount++
		p.mu.Unlock()
		select {
		case p.terminal <- err:
		default:
			p.setErr(&candidatePumpInvariantError{reason: "terminal channel exhausted"})
		}
	})
}

func (p *candidateChanPump) setErr(err error) {
	if err == nil {
		return
	}
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
}

func (p *candidateChanPump) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *candidateChanPump) TerminalReports() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.termCount
}

func (p *candidateChanPump) Done() <-chan struct{} {
	return p.done
}

func (p *candidateChanPump) Close() {
	p.cancel()
	_ = p.conn.Close()
	<-p.done
}

func (p *candidateChanPump) failPendingCommands() {
	err := p.Err()
	if err == nil {
		err = context.Canceled
	}
	for {
		select {
		case command := <-p.commands:
			p.respond(command, candidatePumpWriteResult{Err: err})
		default:
			return
		}
	}
}

func (p *candidateChanPump) submit(ctx context.Context, label string, frame []byte) (time.Time, error) {
	command := candidatePumpCommand{Label: label, Frame: append([]byte(nil), frame...), Result: make(chan candidatePumpWriteResult, 1)}
	select {
	case <-p.done:
		return time.Time{}, p.closedErr()
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	case p.commands <- command:
	}
	select {
	case result := <-command.Result:
		return result.Completed, result.Err
	case <-p.done:
		return time.Time{}, p.closedErr()
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	}
}

func (p *candidateChanPump) next(ctx context.Context, timeout time.Duration) (candidatePumpEvent, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event, ok := <-p.events:
		if !ok {
			return candidatePumpEvent{}, p.closedErr()
		}
		return event, nil
	case <-p.done:
		return candidatePumpEvent{}, p.closedErr()
	case <-ctx.Done():
		return candidatePumpEvent{}, ctx.Err()
	case <-timer.C:
		return candidatePumpEvent{}, osErrTimeout
	}
}

func (p *candidateChanPump) closedErr() error {
	if err := p.Err(); err != nil {
		return err
	}
	return context.Canceled
}

func candidateShortFrame(opcode byte, streamID uint32) []byte {
	frame := make([]byte, 5)
	frame[0] = opcode
	binary.LittleEndian.PutUint32(frame[1:5], streamID)
	return frame
}

func candidateSessionControlFrame(opcode byte, streamID uint32, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > 4096 {
		return nil, fmt.Errorf("candidate session body length=%d", len(body))
	}
	frame := make([]byte, 7+len(body))
	frame[0] = opcode
	binary.LittleEndian.PutUint32(frame[1:5], streamID)
	binary.LittleEndian.PutUint16(frame[5:7], uint16(len(body)))
	copy(frame[7:], body)
	return frame, nil
}

type candidatePumpedSession struct {
	mainConn net.Conn
	pump     *candidateChanPump
	close    sync.Once
}

func (s *candidatePumpedSession) Close() {
	s.close.Do(func() {
		if s.mainConn != nil {
			_ = s.mainConn.Close()
		}
		if s.pump != nil {
			s.pump.Close()
		}
	})
}

func (s *candidateProofServer) startPumpedSession(ctx context.Context, npcMonitor *processMonitor) (*candidatePumpedSession, error) {
	mainConn, err := s.waitConn(ctx, npcMonitor, s.mainReady, "main")
	if err != nil {
		return nil, err
	}
	go discardCandidateMain(ctx, mainConn)
	chanConn, err := s.waitConn(ctx, npcMonitor, s.chanReady, "chan")
	if err != nil {
		_ = mainConn.Close()
		return nil, err
	}
	return &candidatePumpedSession{mainConn: mainConn, pump: newCandidateChanPump(ctx, chanConn, s.recorder)}, nil
}

func runCandidateStartupAttempt(t *testing.T, npcBin string, strategy candidateStrategy, round int) candidateStartupObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, _, vkey := newObserveStore(t, ctx)
	recorder := newObserveRecorder(t, "candidate_startup_matrix", vkey, []byte("server-secret"))
	recorder.note("candidate_startup_attempt", fmt.Sprintf("strategy=%s round=%d", strategy, round))
	server := startCandidateProofServer(t, ctx, st, []byte("server-secret"), recorder)
	cmdCtx, stopNPC := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+server.Addr(), "-vkey="+vkey)
	stdout := newBoundedBuffer(observeOutputLimit)
	stderr := newBoundedBuffer(observeOutputLimit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	observation := candidateStartupObservation{Strategy: strategy, Round: round, Client00BodyLen: -1, Result: candidateResultProtocol}
	if err := cmd.Start(); err != nil {
		observation.HarnessErr = fmt.Errorf("start stock npc: %w", err)
		server.Close()
		return observation
	}
	monitor := newProcessMonitor(cmd)
	session, err := server.startPumpedSession(ctx, monitor)
	if err != nil {
		observation.ProtocolErr = err
	} else {
		observation = runCandidateStartupStrategy(ctx, session.pump, strategy, round)
		session.Close()
		observation.CleanupBounded = true
	}
	server.Close()
	stopNPC()
	waitObservedProcess(t, "npc", cmd, monitor, recorder)
	observation.NPCExitStatus = monitor.Status()
	candidateOutputSummary(recorder, "npc_stdout_summary", stdout.String())
	candidateOutputSummary(recorder, "npc_stderr_summary", stderr.String())
	return observation
}

func runCandidateStartupStrategy(ctx context.Context, pump *candidateChanPump, strategy candidateStrategy, round int) candidateStartupObservation {
	observation := candidateStartupObservation{Strategy: strategy, Round: round, Client00BodyLen: -1, Result: candidateResultProtocol}
	deadline := time.Now().Add(candidateStreamOpenTimeout)
	var peerAckAt time.Time
	var stream06At time.Time
	var streamOpenAt time.Time
	var serverBody []byte
	streamSent := false
	waitingForOwnAck := false
	for time.Now().Before(deadline) {
		event, err := pump.next(ctx, time.Until(deadline))
		if err != nil {
			setCandidateStartupError(&observation, err)
			return observation
		}
		switch event.Kind {
		case candidatePumpPeerPingAck:
			if peerAckAt.IsZero() {
				peerAckAt = event.AckCompleted
				observation.Client00BodyLen = len(event.Frame.Body)
				observation.Client00AckSent = true
				switch strategy {
				case candidateStrategyPeerAckOnly:
					completed, err := pump.submit(ctx, "opcode=0x06 stream=1", candidateShortFrame(0x06, candidateProofStreamID))
					if err != nil {
						setCandidateStartupError(&observation, err)
						return observation
					}
					stream06At, streamSent, observation.Stream06Sent = completed, true, true
				case candidateStrategyPeerAckThenPing, candidateStrategyInterleaved:
					serverBody = candidateServerSessionBody(time.Now().UTC())
					frame, err := candidateSessionControlFrame(0x00, candidateSessionStreamID, serverBody)
					if err != nil {
						observation.HarnessErr = err
						return observation
					}
					if _, err := pump.submit(ctx, "opcode=0x00 stream=session", frame); err != nil {
						setCandidateStartupError(&observation, err)
						return observation
					}
					observation.Server00Sent = true
					if strategy == candidateStrategyPeerAckThenPing {
						waitingForOwnAck = true
					} else {
						completed, err := pump.submit(ctx, "opcode=0x06 stream=1", candidateShortFrame(0x06, candidateProofStreamID))
						if err != nil {
							setCandidateStartupError(&observation, err)
							return observation
						}
						stream06At, streamSent, observation.Stream06Sent = completed, true, true
					}
				}
			}
		case candidatePumpSessionAck:
			observation.Client08Received = true
			if strategy == candidateStrategyPeerAckOnly || !observation.Server00Sent || !bytes.Equal(event.Frame.Body, serverBody) {
				observation.ProtocolErr = fmt.Errorf("unexpected or mismatched client session acknowledgement")
				return observation
			}
			if waitingForOwnAck {
				completed, err := pump.submit(ctx, "opcode=0x06 stream=1", candidateShortFrame(0x06, candidateProofStreamID))
				if err != nil {
					setCandidateStartupError(&observation, err)
					return observation
				}
				stream06At, streamSent, observation.Stream06Sent = completed, true, true
				waitingForOwnAck = false
			}
			if strategy == candidateStrategyInterleaved && !streamOpenAt.IsZero() {
				observation.Result = candidateResultSuccess
				return observation
			}
		case candidatePumpStreamOpen:
			if !streamSent || peerAckAt.IsZero() {
				observation.ProtocolErr = fmt.Errorf("stream acknowledgement before stream open")
				return observation
			}
			streamOpenAt = event.ReceivedAt
			observation.Stream01Received = true
			observation.AckTo01 = streamOpenAt.Sub(peerAckAt)
			observation.Stream06To01 = streamOpenAt.Sub(stream06At)
			if observation.AckTo01 >= candidateNearTimeout {
				observation.NearTimeout = true
				observation.ProtocolErr = fmt.Errorf("stream acknowledgement near timeout")
				return observation
			}
			if strategy == candidateStrategyInterleaved && !observation.Client08Received {
				continue
			}
			observation.Result = candidateResultSuccess
			return observation
		case candidatePumpWindow, candidatePumpData, candidatePumpClose:
			observation.UnexpectedOpcode = fmt.Sprintf("0x%02x", event.Frame.Opcode)
			observation.ProtocolErr = fmt.Errorf("unexpected startup opcode=%s", observation.UnexpectedOpcode)
			return observation
		default:
			observation.HarnessErr = &candidatePumpInvariantError{reason: "unroutable pump event"}
			return observation
		}
	}
	observation.ProtocolErr = fmt.Errorf("startup deadline elapsed without stream acknowledgement")
	return observation
}

func setCandidateStartupError(observation *candidateStartupObservation, err error) {
	var invariant *candidatePumpInvariantError
	if errors.As(err, &invariant) {
		observation.HarnessErr = err
		return
	}
	observation.ProtocolErr = err
}

func recordCandidateStartupAttempt(recorder *observeRecorder, attempt candidateStartupObservation) {
	bodyLen := "unknown"
	if attempt.Client00BodyLen >= 0 {
		bodyLen = fmt.Sprintf("%d", attempt.Client00BodyLen)
	}
	reason := "none"
	if attempt.ProtocolErr != nil {
		reason = candidateSanitizeErr(attempt.ProtocolErr)
	}
	recorder.note("candidate_startup_result", fmt.Sprintf("strategy=%s round=%d client_00_body_len=%s client_00_ack_sent=%t server_00_sent=%t client_08_received=%t stream_06_sent=%t stream_01_received=%t ack_to_0x01=%s stream_06_to_0x01=%s unexpected_opcode=%s near_timeout=%t npc_exit=%s result=%s reason=%s", attempt.Strategy, attempt.Round, bodyLen, attempt.Client00AckSent, attempt.Server00Sent, attempt.Client08Received, attempt.Stream06Sent, attempt.Stream01Received, candidateDuration(attempt.AckTo01), candidateDuration(attempt.Stream06To01), candidateStartupOpcode(attempt), attempt.NearTimeout, attempt.NPCExitStatus, attempt.Result, reason))
}

func candidateStartupOpcode(attempt candidateStartupObservation) string {
	if attempt.UnexpectedOpcode == "" {
		return "none"
	}
	return attempt.UnexpectedOpcode
}

func selectCandidateStrategy(attempts []candidateStartupObservation) candidateStrategy {
	for _, strategy := range []candidateStrategy{candidateStrategyPeerAckOnly, candidateStrategyPeerAckThenPing, candidateStrategyInterleaved} {
		matching := 0
		qualifies := true
		for _, attempt := range attempts {
			if attempt.Strategy != strategy {
				continue
			}
			matching++
			if attempt.Result != candidateResultSuccess || !attempt.Stream01Received || !attempt.Client00AckSent || attempt.NearTimeout || attempt.UnexpectedOpcode != "" || !attempt.CleanupBounded {
				qualifies = false
			}
		}
		if matching == candidateStartupRounds && qualifies {
			return strategy
		}
	}
	return ""
}

func recordCandidateStartupReport(recorder *observeRecorder, attempts []candidateStartupObservation) {
	for _, strategy := range []candidateStrategy{candidateStrategyPeerAckOnly, candidateStrategyPeerAckThenPing, candidateStrategyInterleaved} {
		strategyAttempts := filterCandidateAttempts(attempts, strategy)
		successes := 0
		for _, attempt := range strategyAttempts {
			if attempt.Result == candidateResultSuccess {
				successes++
			}
		}
		recorder.note("candidate_strategy_summary", fmt.Sprintf("strategy=%s attempts=%d success=%d failure=%d ack_latency=%s stream_latency=%s", strategy, len(strategyAttempts), successes, len(strategyAttempts)-successes, candidateLatencySummary(strategyAttempts, true), candidateLatencySummary(strategyAttempts, false)))
	}
	bodyGroups := map[int][]candidateStartupObservation{}
	for _, attempt := range attempts {
		bodyGroups[attempt.Client00BodyLen] = append(bodyGroups[attempt.Client00BodyLen], attempt)
	}
	lengths := make([]int, 0, len(bodyGroups))
	for length := range bodyGroups {
		lengths = append(lengths, length)
	}
	sort.Ints(lengths)
	for _, length := range lengths {
		group := bodyGroups[length]
		label := "unknown"
		if length >= 0 {
			label = fmt.Sprintf("%d", length)
		}
		success, missing, near := 0, 0, 0
		for _, attempt := range group {
			if attempt.Result == candidateResultSuccess {
				success++
			}
			if !attempt.Stream01Received {
				missing++
			}
			if attempt.NearTimeout {
				near++
			}
		}
		recorder.note("candidate_body_length_summary", fmt.Sprintf("body_len=%s attempts=%d success=%d missing_or_timeout=%d near_timeout=%d strategy_breakdown=%s", label, len(group), success, missing, near, candidateStrategyBreakdown(group)))
	}
}

func filterCandidateAttempts(attempts []candidateStartupObservation, strategy candidateStrategy) []candidateStartupObservation {
	result := make([]candidateStartupObservation, 0, candidateStartupRounds)
	for _, attempt := range attempts {
		if attempt.Strategy == strategy {
			result = append(result, attempt)
		}
	}
	return result
}

func candidateStrategyBreakdown(attempts []candidateStartupObservation) string {
	parts := make([]string, 0, 3)
	for _, strategy := range []candidateStrategy{candidateStrategyPeerAckOnly, candidateStrategyPeerAckThenPing, candidateStrategyInterleaved} {
		total, success := 0, 0
		for _, attempt := range attempts {
			if attempt.Strategy == strategy {
				total++
				if attempt.Result == candidateResultSuccess {
					success++
				}
			}
		}
		if total > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d/%d", strategy, success, total))
		}
	}
	return strings.Join(parts, ",")
}

func candidateLatencySummary(attempts []candidateStartupObservation, ack bool) string {
	values := make([]time.Duration, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.Result != candidateResultSuccess {
			continue
		}
		if ack {
			values = append(values, attempt.AckTo01)
		} else {
			values = append(values, attempt.Stream06To01)
		}
	}
	if len(values) == 0 {
		return "n=0"
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	median := values[(len(values)-1)/2]
	p95 := values[(95*len(values)+99)/100-1]
	return fmt.Sprintf("n=%d,min=%s,median=%s,p95=%s,max=%s", len(values), candidateDuration(values[0]), candidateDuration(median), candidateDuration(p95), candidateDuration(values[len(values)-1]))
}

func candidateDuration(value time.Duration) string {
	if value == 0 {
		return "n/a"
	}
	return value.String()
}

type candidatePumpedCheckpoint func(context.Context, *candidateChanPump, *candidateProofEchoTarget, *candidateCheckpointProof, *observeRecorder)

func runCandidatePumpedCheckpoint(t *testing.T, npcBin string, strategy candidateStrategy, bundle int, checkpoint string, run candidatePumpedCheckpoint) candidateCheckpointProof {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	st, _, vkey := newObserveStore(t, ctx)
	recorder := newObserveRecorder(t, "candidate_full_proof_"+checkpoint, vkey, []byte("server-secret"))
	proof := candidateCheckpointProof{Checkpoint: checkpoint, Bundle: bundle, Strategy: strategy, Result: candidateResultProtocol}
	server := startCandidateProofServer(t, ctx, st, []byte("server-secret"), recorder)
	target := startCandidateProofEchoTarget(t, ctx, recorder)
	cmdCtx, stopNPC := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+server.Addr(), "-vkey="+vkey)
	stdout := newBoundedBuffer(observeOutputLimit)
	stderr := newBoundedBuffer(observeOutputLimit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		proof.HarnessErr = fmt.Errorf("start stock npc: %w", err)
		target.Close()
		server.Close()
		return proof
	}
	monitor := newProcessMonitor(cmd)
	session, err := server.startPumpedSession(ctx, monitor)
	if err != nil {
		proof.ProtocolErr = err
	} else {
		startup := runCandidateStartupStrategy(ctx, session.pump, strategy, bundle)
		if startup.HarnessErr != nil {
			proof.HarnessErr = startup.HarnessErr
		} else if startup.Result != candidateResultSuccess {
			proof.ProtocolErr = startup.ProtocolErr
		} else {
			run(ctx, session.pump, target, &proof, recorder)
		}
		session.Close()
	}
	target.Close()
	server.Close()
	stopNPC()
	waitObservedProcess(t, "npc", cmd, monitor, recorder)
	candidateOutputSummary(recorder, "npc_stdout_summary", stdout.String())
	candidateOutputSummary(recorder, "npc_stderr_summary", stderr.String())
	return proof
}

func candidatePumpedMetadataDial(ctx context.Context, pump *candidateChanPump, target *candidateProofEchoTarget, proof *candidateCheckpointProof, recorder *observeRecorder) {
	metadata, err := candidateOpenMetadataForTarget(target.Addr())
	if err != nil {
		proof.ProtocolErr = err
		return
	}
	body, err := encodeCandidateOpenMetadataBody(metadata)
	if err != nil {
		proof.HarnessErr = err
		return
	}
	frame, err := encodeCandidateDataFrame(candidateProofStreamID, body)
	if err != nil {
		proof.HarnessErr = err
		return
	}
	if _, err := pump.submit(ctx, "opcode=0x03 stream=1 metadata", frame); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	recorder.note("candidate_metadata", fmt.Sprintf("checkpoint=%s keys=%s host=target_listener_addr body_len=%d", proof.Checkpoint, candidateMetadataKeySet(), len(body)))
	if err := waitCandidateTargetDial(ctx, pump, target); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	proof.TargetDialed = true
	proof.NoHang = true
	proof.Result = candidateResultSuccess
}

func candidatePumpedPayloadEcho(ctx context.Context, pump *candidateChanPump, target *candidateProofEchoTarget, proof *candidateCheckpointProof, recorder *observeRecorder) {
	candidatePumpedMetadataDial(ctx, pump, target, proof, recorder)
	if proof.Result != candidateResultSuccess {
		return
	}
	payload := []byte("kavern-proof-echo-1")
	frame, err := encodeCandidateDataFrame(candidateProofStreamID, payload)
	if err != nil {
		proof.HarnessErr = err
		return
	}
	if _, err := pump.submit(ctx, "opcode=0x03 stream=1 payload_len=19", frame); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	if err := waitCandidateTargetPayload(ctx, pump, target, payload); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	proof.TargetPayload = true
	if err := waitCandidatePumpedPayload(ctx, pump, payload, proof, recorder); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	proof.ResponseReturned = true
	proof.NoHang = true
	proof.Result = candidateResultSuccess
}

func candidatePumpedClose(ctx context.Context, pump *candidateChanPump, target *candidateProofEchoTarget, proof *candidateCheckpointProof, recorder *observeRecorder) {
	candidatePumpedMetadataDial(ctx, pump, target, proof, recorder)
	if proof.Result != candidateResultSuccess {
		return
	}
	if _, err := pump.submit(ctx, "opcode=0x07 stream=1", candidateShortFrame(0x07, candidateProofStreamID)); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	proof.CloseSent = true
	if err := waitCandidatePumpedClose(ctx, pump, target, proof); err != nil {
		setCandidateCheckpointPumpError(proof, err)
		return
	}
	proof.NoHang = true
	proof.Result = candidateResultSuccess
}

func waitCandidateTargetDial(ctx context.Context, pump *candidateChanPump, target *candidateProofEchoTarget) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-target.accepted:
		return nil
	case <-pump.Done():
		return pump.closedErr()
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("timeout waiting for target dial")
	}
}

func waitCandidateTargetPayload(ctx context.Context, pump *candidateChanPump, target *candidateProofEchoTarget, want []byte) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case got := <-target.received:
		if !bytes.Equal(got, want) {
			return fmt.Errorf("target payload mismatch: got_len=%d want_len=%d", len(got), len(want))
		}
		return nil
	case <-pump.Done():
		return pump.closedErr()
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("timeout waiting for target payload")
	}
}

func waitCandidatePumpedPayload(ctx context.Context, pump *candidateChanPump, payload []byte, proof *candidateCheckpointProof, recorder *observeRecorder) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		event, err := pump.next(ctx, time.Until(deadline))
		if err != nil {
			return err
		}
		switch event.Kind {
		case candidatePumpWindow:
			proof.WindowCount++
			proof.WindowStreamIDs = append(proof.WindowStreamIDs, event.Frame.StreamID)
		case candidatePumpData:
			if !bytes.Equal(event.Frame.Body, payload) {
				return fmt.Errorf("unexpected candidate response payload length=%d", len(event.Frame.Body))
			}
			recorder.note("candidate_payload_response", fmt.Sprintf("checkpoint=P payload_len=%d equality=true", len(payload)))
			return nil
		case candidatePumpPeerPingAck, candidatePumpSessionAck:
			continue
		case candidatePumpClose, candidatePumpStreamOpen:
			return fmt.Errorf("unexpected candidate event=%s while waiting for payload", event.Kind)
		default:
			return &candidatePumpInvariantError{reason: "unroutable payload event"}
		}
	}
	return fmt.Errorf("timeout waiting for candidate payload response")
}

func waitCandidatePumpedClose(ctx context.Context, pump *candidateChanPump, target *candidateProofEchoTarget, proof *candidateCheckpointProof) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if target.peerClosed() {
			proof.TargetClosed = true
		}
		if proof.TargetClosed && (proof.CloseReceived || proof.ChanEOF) {
			return nil
		}
		event, err := pump.next(ctx, 200*time.Millisecond)
		if errors.Is(err, osErrTimeout) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				proof.ChanEOF = true
				continue
			}
			return err
		}
		switch event.Kind {
		case candidatePumpWindow:
			proof.WindowCount++
			proof.WindowStreamIDs = append(proof.WindowStreamIDs, event.Frame.StreamID)
		case candidatePumpClose:
			proof.CloseReceived = true
		case candidatePumpPeerPingAck, candidatePumpSessionAck:
			continue
		case candidatePumpData, candidatePumpStreamOpen:
			return fmt.Errorf("unexpected candidate event=%s while waiting for close", event.Kind)
		default:
			return &candidatePumpInvariantError{reason: "unroutable close event"}
		}
	}
	return fmt.Errorf("timeout waiting for bounded close")
}

func setCandidateCheckpointPumpError(proof *candidateCheckpointProof, err error) {
	var invariant *candidatePumpInvariantError
	if errors.As(err, &invariant) {
		proof.HarnessErr = err
		return
	}
	proof.ProtocolErr = err
}

func recordCandidateFullProofBundle(recorder *observeRecorder, bundle candidateFullProofBundle) {
	for _, proof := range []candidateCheckpointProof{bundle.Metadata, bundle.Payload, bundle.Close} {
		reason := "none"
		if proof.ProtocolErr != nil {
			reason = candidateSanitizeErr(proof.ProtocolErr)
		}
		recorder.note("candidate_full_proof", fmt.Sprintf("bundle=%d checkpoint=%s strategy=%s target_dialed=%t target_payload=%t response_returned=%t close_sent=%t close_received=%t target_closed=%t chan_eof=%t no_hang=%t window_count=%d window_stream_ids=%v active_0x05_reply=false result=%s reason=%s", proof.Bundle, proof.Checkpoint, proof.Strategy, proof.TargetDialed, proof.TargetPayload, proof.ResponseReturned, proof.CloseSent, proof.CloseReceived, proof.TargetClosed, proof.ChanEOF, proof.NoHang, proof.WindowCount, proof.WindowStreamIDs, proof.Result, reason))
	}
}

func candidateFullProofsPass(bundles []candidateFullProofBundle) bool {
	if len(bundles) != candidateFullProofBundles {
		return false
	}
	for _, bundle := range bundles {
		if !candidateCheckpointPass(bundle.Metadata, "M") || !candidateCheckpointPass(bundle.Payload, "P") || !candidateCheckpointPass(bundle.Close, "X") {
			return false
		}
	}
	return true
}

func candidateCheckpointPass(proof candidateCheckpointProof, checkpoint string) bool {
	if proof.Result != candidateResultSuccess || proof.HarnessErr != nil || proof.ProtocolErr != nil || !proof.TargetDialed || !proof.NoHang {
		return false
	}
	switch checkpoint {
	case "M":
		return true
	case "P":
		return proof.TargetPayload && proof.ResponseReturned
	case "X":
		return proof.CloseSent && proof.TargetClosed && (proof.CloseReceived || proof.ChanEOF)
	default:
		return false
	}
}

type candidateProofResult struct {
	TargetReached            bool
	TargetDialed             bool
	PayloadReceivedByTarget  bool
	ResponseReturned         bool
	StreamOpenAck            bool
	CloseSent                bool
	CloseReceived            bool
	TargetClosed             bool
	ChanEOF                  bool
	ChanRemainedUsable       string
	NoHang                   bool
	FlowControlSeen          bool
	FlowControlReplyRequired bool
	CloseSummary             string
	Readiness                string
	Err                      error
}

type candidateProofSession struct {
	mainConn net.Conn
	chanConn net.Conn
	codec    *candidateProofCodec
	runtime  candidateRuntimeState
	close    sync.Once
}

func (s *candidateProofSession) Close() {
	s.close.Do(func() {
		if s.mainConn != nil {
			_ = s.mainConn.Close()
		}
		if s.chanConn != nil {
			_ = s.chanConn.Close()
		}
	})
}

type candidateRuntimeState struct {
	SessionPingsAcked int
	SessionAcksSeen   int
	WindowControls    int
	CloseReceived     bool
}

type candidateCheckpoint func(context.Context, *candidateProofSession, *candidateProofEchoTarget, *observeRecorder) candidateProofResult

func runCandidateCheckpoint(t *testing.T, npcBin, checkpoint string, run candidateCheckpoint) candidateProofResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()

	st, _, vkey := newObserveStore(t, ctx)
	recorder := newObserveRecorder(t, "candidate_codec_proof_"+checkpoint, vkey, []byte("server-secret"))
	recorder.note("candidate_checkpoint", checkpoint)
	recorder.note("npc_bin", fmt.Sprintf("basename=%s sha256=%s", filepath.Base(npcBin), formatSHA256ForLog(sha256File(t, npcBin))))
	server := startCandidateProofServer(t, ctx, st, []byte("server-secret"), recorder)
	target := startCandidateProofEchoTarget(t, ctx, recorder)

	cmdCtx, stopNPC := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+server.Addr(), "-vkey="+vkey)
	npcStdout := newBoundedBuffer(observeOutputLimit)
	npcStderr := newBoundedBuffer(observeOutputLimit)
	cmd.Stdout = npcStdout
	cmd.Stderr = npcStderr
	if err := cmd.Start(); err != nil {
		target.Close()
		server.Close()
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	recorder.note("npc_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(npcBin), cmd.Process != nil))
	npcMonitor := newProcessMonitor(cmd)

	result := candidateProofResult{ChanRemainedUsable: "unknown"}
	session, err := server.startMinimalSession(ctx, npcMonitor)
	if err != nil {
		result.Err = err
		result.CloseSummary = "startup_failed"
	} else {
		result = run(ctx, session, target, recorder)
		session.Close()
	}
	if result.Err != nil {
		recorder.note("candidate_checkpoint_result", fmt.Sprintf("checkpoint=%s outcome=insufficient reason=%s", checkpoint, candidateSanitizeErr(result.Err, vkey)))
	}
	recorder.note("candidate_target_dialed", fmt.Sprintf("%t", result.TargetDialed))
	recorder.note("candidate_payload_received_by_target", fmt.Sprintf("%t", result.PayloadReceivedByTarget))
	recorder.note("candidate_response_returned", fmt.Sprintf("%t", result.ResponseReturned))
	recorder.note("candidate_close", fmt.Sprintf("sent=%t received=%t target_closed=%t chan_eof=%t chan_remained_usable=%s no_hang=%t", result.CloseSent, result.CloseReceived, result.TargetClosed, result.ChanEOF, result.ChanRemainedUsable, result.NoHang))
	recorder.note("candidate_0x05", fmt.Sprintf("seen=%t active_handling_required=%t", result.FlowControlSeen, result.FlowControlReplyRequired))

	target.Close()
	server.Close()
	stopNPC()
	waitObservedProcess(t, "npc", cmd, npcMonitor, recorder)
	recorder.note("candidate_npc_exit_status", fmt.Sprintf("status=%s", npcMonitor.Status()))
	candidateOutputSummary(recorder, "npc_stdout_summary", npcStdout.String())
	candidateOutputSummary(recorder, "npc_stderr_summary", npcStderr.String())
	return result
}

func candidateCheckpointSummary(result candidateProofResult) string {
	reason := "none"
	if result.Err != nil {
		reason = candidateSanitizeErr(result.Err)
	}
	return fmt.Sprintf("target_dialed=%t payload_received_by_target=%t response_returned=%t close_sent=%t close_received=%t target_closed=%t chan_eof=%t no_hang=%t flow_control_seen=%t active_0x05_required=%t reason=%s", result.TargetDialed, result.PayloadReceivedByTarget, result.ResponseReturned, result.CloseSent, result.CloseReceived, result.TargetClosed, result.ChanEOF, result.NoHang, result.FlowControlSeen, result.FlowControlReplyRequired, reason)
}

func candidateOutputSummary(recorder *observeRecorder, state, output string) {
	if output == "" {
		recorder.note(state, "present=false bytes=0")
		return
	}
	sanitized := loopbackPattern.ReplaceAllString(recorder.redact(output), "<loopback_addr>")
	recorder.note(state, fmt.Sprintf("present=true bytes=%d preview=%s", len(output), asciiPreview([]byte(sanitized), 240)))
}

func candidateSanitizeErr(err error, extraRedactValues ...string) string {
	return loopbackPattern.ReplaceAllString(sanitizeErr(err, extraRedactValues...), "<loopback_addr>")
}

func candidateCheckpointMetadataDial(ctx context.Context, session *candidateProofSession, target *candidateProofEchoTarget, recorder *observeRecorder) candidateProofResult {
	result := candidateProofResult{StreamOpenAck: true, ChanRemainedUsable: "unknown"}
	metadata, err := candidateOpenMetadataForTarget(target.Addr())
	if err != nil {
		result.Err = err
		result.CloseSummary = "metadata_build_failed"
		return result
	}
	body, err := encodeCandidateOpenMetadataBody(metadata)
	if err != nil {
		result.Err = err
		result.CloseSummary = "metadata_encode_failed"
		return result
	}
	recorder.note("candidate_metadata", fmt.Sprintf("keys=%s host=target_listener_addr body_len=%d", candidateMetadataKeySet(), len(body)))
	if err := session.codec.writeDataFrame(candidateProofStreamID, body); err != nil {
		result.Err = err
		result.CloseSummary = "metadata_write_failed"
		return result
	}
	if err := target.waitForDial(ctx); err != nil {
		result.Err = err
		result.CloseSummary = "target_dial_missing"
		return result
	}
	result.TargetReached = true
	result.TargetDialed = true
	result.CloseSummary = "metadata_target_dial_observed"
	result.NoHang = true
	return result
}

func candidateCheckpointPayloadEcho(ctx context.Context, session *candidateProofSession, target *candidateProofEchoTarget, recorder *observeRecorder) candidateProofResult {
	result := candidateCheckpointMetadataDial(ctx, session, target, recorder)
	if result.Err != nil || !result.TargetDialed {
		return result
	}
	payload := []byte("kavern-proof-echo-1")
	if err := session.codec.writeDataFrame(candidateProofStreamID, payload); err != nil {
		result.Err = err
		result.CloseSummary = "payload_write_failed"
		return result
	}
	if err := target.waitForPayload(ctx, payload); err != nil {
		result.Err = err
		result.CloseSummary = "target_payload_missing"
		return result
	}
	result.PayloadReceivedByTarget = true

	responseReturned, runtime, err := waitForCandidatePayload(ctx, session.codec, payload, session.runtime, recorder)
	session.runtime = runtime
	result.FlowControlSeen = runtime.WindowControls > 0
	result.FlowControlReplyRequired = false
	result.ResponseReturned = responseReturned
	if err != nil {
		result.Err = err
		result.CloseSummary = "payload_response_missing"
		return result
	}
	result.CloseSummary = "payload_echo_observed"
	result.NoHang = true
	return result
}

func candidateCheckpointClose(ctx context.Context, session *candidateProofSession, target *candidateProofEchoTarget, recorder *observeRecorder) candidateProofResult {
	result := candidateCheckpointMetadataDial(ctx, session, target, recorder)
	if result.Err != nil || !result.TargetDialed {
		return result
	}
	if err := session.codec.writeShort(0x07, candidateProofStreamID); err != nil {
		result.Err = err
		result.CloseSummary = "close_write_failed"
		return result
	}
	result.CloseSent = true
	closeReceived, targetClosed, chanEOF, runtime, err := waitForCandidateClose(ctx, session.codec, target, session.runtime, recorder)
	session.runtime = runtime
	result.FlowControlSeen = runtime.WindowControls > 0
	result.FlowControlReplyRequired = false
	result.CloseReceived = closeReceived
	result.TargetClosed = targetClosed
	result.ChanEOF = chanEOF
	if err != nil {
		result.Err = err
		result.CloseSummary = "close_not_bounded"
		return result
	}
	result.CloseSummary = "close_bounded"
	result.NoHang = true
	return result
}

type candidateStrategyResult struct {
	Strategy      candidateStrategy
	StreamOpenAck bool
}

func candidateMatrixResult(results []candidateStrategyResult, strategy candidateStrategy) bool {
	for _, result := range results {
		if result.Strategy == strategy {
			return result.StreamOpenAck
		}
	}
	return false
}

func runCandidateStrategy(t *testing.T, npcBin string, strategy candidateStrategy) candidateStrategyResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, _, vkey := newObserveStore(t, ctx)
	recorder := newObserveRecorder(t, "candidate_codec_proof", vkey, []byte("server-secret"))
	recorder.note("candidate_strategy", string(strategy))
	recorder.note("npc_bin", fmt.Sprintf("basename=%s sha256=%s", filepath.Base(npcBin), formatSHA256ForLog(sha256File(t, npcBin))))
	server := startCandidateProofServer(t, ctx, st, []byte("server-secret"), recorder)
	defer server.Close()

	cmdCtx, stopNPC := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, npcBin, "-server="+server.Addr(), "-vkey="+vkey)
	npcStdout := newBoundedBuffer(observeOutputLimit)
	npcStderr := newBoundedBuffer(observeOutputLimit)
	cmd.Stdout = npcStdout
	cmd.Stderr = npcStderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stock npc basename=%s: %v", filepath.Base(npcBin), err)
	}
	recorder.note("npc_started", fmt.Sprintf("basename=%s pid_present=%t", filepath.Base(npcBin), cmd.Process != nil))
	npcMonitor := newProcessMonitor(cmd)

	result := server.RunStrategy(ctx, npcMonitor, strategy)
	if result.Err != nil {
		recorder.note("candidate_codec_result", fmt.Sprintf("outcome=insufficient err=%s", candidateSanitizeErr(result.Err)))
	}
	recorder.note("close_behavior", result.CloseSummary)
	recorder.note("candidate_target_dialed", "seen=false")
	recorder.note("candidate_response_returned", "seen=false")
	if result.StreamOpenAck {
		recorder.note("candidate_readiness", "sufficient for next test-only metadata/payload active proof")
	} else {
		recorder.note("candidate_readiness", "insufficient")
	}

	stopNPC()
	waitObservedProcess(t, "npc", cmd, npcMonitor, recorder)
	recorder.note("candidate_npc_exit_status", fmt.Sprintf("status=%s", npcMonitor.Status()))
	candidateOutputSummary(recorder, "npc_stdout_summary", npcStdout.String())
	candidateOutputSummary(recorder, "npc_stderr_summary", npcStderr.String())
	return candidateStrategyResult{Strategy: strategy, StreamOpenAck: result.StreamOpenAck}
}

type candidateSessionControlState struct {
	serverBody       []byte
	serverPingSent   bool
	peerPingSeen     bool
	peerPingAckSent  bool
	ownPingAcked     bool
	client08Seen     bool
	client08Matches  bool
	mismatches       int
	unexpectedOpcode string
}

type candidateSessionControlAction struct {
	PeerPing           bool
	PeerPingBody       []byte
	OwnPingAck         bool
	OwnPingAckMatches  bool
	ClientFrameBodyLen int
}

func newCandidateSessionControlState(serverBody []byte) (*candidateSessionControlState, error) {
	if len(serverBody) == 0 || len(serverBody) > 4096 {
		return nil, fmt.Errorf("invalid server session body length=%d", len(serverBody))
	}
	return &candidateSessionControlState{serverBody: append([]byte(nil), serverBody...)}, nil
}

func (s *candidateSessionControlState) markServerPingSent() {
	s.serverPingSent = true
}

func (s *candidateSessionControlState) handle(frame candidateCodecFrame) (candidateSessionControlAction, error) {
	if frame.StreamID != candidateSessionStreamID {
		s.unexpectedOpcode = fmt.Sprintf("0x%02x", frame.Opcode)
		return candidateSessionControlAction{}, fmt.Errorf("unexpected session control stream=%d", frame.StreamID)
	}
	if len(frame.Body) == 0 || len(frame.Body) > 4096 {
		s.unexpectedOpcode = fmt.Sprintf("0x%02x", frame.Opcode)
		return candidateSessionControlAction{}, fmt.Errorf("invalid session control body length=%d", len(frame.Body))
	}
	switch frame.Opcode {
	case 0x00:
		s.peerPingSeen = true
		return candidateSessionControlAction{
			PeerPing:           true,
			PeerPingBody:       append([]byte(nil), frame.Body...),
			ClientFrameBodyLen: len(frame.Body),
		}, nil
	case 0x08:
		if !s.serverPingSent {
			s.unexpectedOpcode = "0x08"
			return candidateSessionControlAction{}, fmt.Errorf("unexpected session acknowledgement before server ping")
		}
		s.client08Seen = true
		matches := subtle.ConstantTimeCompare(frame.Body, s.serverBody) == 1
		s.client08Matches = matches
		if matches {
			s.ownPingAcked = true
		} else {
			s.mismatches++
			if s.mismatches > candidateMaxSessionControlMismatches {
				return candidateSessionControlAction{}, fmt.Errorf("too many mismatched session acknowledgements")
			}
		}
		return candidateSessionControlAction{
			OwnPingAck:         true,
			OwnPingAckMatches:  matches,
			ClientFrameBodyLen: len(frame.Body),
		}, nil
	default:
		s.unexpectedOpcode = fmt.Sprintf("0x%02x", frame.Opcode)
		return candidateSessionControlAction{}, fmt.Errorf("unexpected opcode=0x%02x stream=%d body_len=%d", frame.Opcode, frame.StreamID, len(frame.Body))
	}
}

func (s *candidateSessionControlState) markPeerPingAckSent() {
	s.peerPingAckSent = true
}

func (s *candidateSessionControlState) ready() bool {
	return s.serverPingSent && s.peerPingSeen && s.peerPingAckSent && s.ownPingAcked
}

func candidateStrategyReadyForStreamOpen(strategy candidateStrategy, state *candidateSessionControlState) bool {
	switch strategy {
	case candidateStrategyPeerAckOnly:
		return state.peerPingSeen && state.peerPingAckSent
	case candidateStrategyPeerAckThenPing:
		return state.peerPingSeen && state.peerPingAckSent && state.serverPingSent && state.ownPingAcked
	case candidateStrategyInterleaved:
		return state.peerPingSeen && state.peerPingAckSent && state.serverPingSent
	default:
		return false
	}
}

func isCandidateStreamOpenAck(frame candidateCodecFrame) bool {
	return frame.Opcode == 0x01 && frame.StreamID == candidateProofStreamID && len(frame.Body) == 0
}

func TestCandidateSessionControlStateIsOrderIndependent(t *testing.T) {
	serverBody := bytes.Repeat([]byte{0x53}, 30)
	for _, tc := range []struct {
		name     string
		peerBody []byte
		frames   []candidateCodecFrame
	}{
		{
			name:     "peer_ping_before_own_ack_29_bytes",
			peerBody: bytes.Repeat([]byte{0x29}, 29),
			frames: []candidateCodecFrame{
				{Opcode: 0x00, StreamID: candidateSessionStreamID, Body: bytes.Repeat([]byte{0x29}, 29)},
				{Opcode: 0x08, StreamID: candidateSessionStreamID, Body: serverBody},
			},
		},
		{
			name:     "own_ack_before_peer_ping_30_bytes",
			peerBody: bytes.Repeat([]byte{0x30}, 30),
			frames: []candidateCodecFrame{
				{Opcode: 0x08, StreamID: candidateSessionStreamID, Body: serverBody},
				{Opcode: 0x00, StreamID: candidateSessionStreamID, Body: bytes.Repeat([]byte{0x30}, 30)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := newCandidateSessionControlState(serverBody)
			if err != nil {
				t.Fatal(err)
			}
			state.markServerPingSent()
			var echoed [][]byte
			for _, frame := range tc.frames {
				action, err := state.handle(frame)
				if err != nil {
					t.Fatal(err)
				}
				if action.PeerPing {
					echoed = append(echoed, action.PeerPingBody)
					state.markPeerPingAckSent()
				}
			}
			if !state.ready() {
				t.Fatalf("state not ready: peer_seen=%t peer_ack_sent=%t own_acked=%t", state.peerPingSeen, state.peerPingAckSent, state.ownPingAcked)
			}
			if !state.client08Seen || !state.client08Matches {
				t.Fatalf("matching client 0x08 was not recorded: seen=%t matches=%t", state.client08Seen, state.client08Matches)
			}
			if len(echoed) != 1 || subtle.ConstantTimeCompare(echoed[0], tc.peerBody) != 1 {
				t.Fatalf("peer body was not echoed exactly: echoes=%d", len(echoed))
			}
		})
	}
}

func TestCandidateSessionControlStateAcknowledgesInterleavedPeerPing(t *testing.T) {
	serverBody := bytes.Repeat([]byte{0x53}, 30)
	state, err := newCandidateSessionControlState(serverBody)
	if err != nil {
		t.Fatal(err)
	}
	state.markServerPingSent()
	for _, frame := range []candidateCodecFrame{
		{Opcode: 0x00, StreamID: candidateSessionStreamID, Body: bytes.Repeat([]byte{0x30}, 30)},
		{Opcode: 0x08, StreamID: candidateSessionStreamID, Body: serverBody},
	} {
		action, err := state.handle(frame)
		if err != nil {
			t.Fatal(err)
		}
		if action.PeerPing {
			state.markPeerPingAckSent()
		}
	}
	if !state.ready() {
		t.Fatal("state should be ready before the interleaved peer ping")
	}
	interleaved := bytes.Repeat([]byte{0x29}, 29)
	action, err := state.handle(candidateCodecFrame{Opcode: 0x00, StreamID: candidateSessionStreamID, Body: interleaved})
	if err != nil {
		t.Fatal(err)
	}
	if !action.PeerPing || subtle.ConstantTimeCompare(action.PeerPingBody, interleaved) != 1 {
		t.Fatal("interleaved peer ping was not prepared for an exact immediate acknowledgement")
	}
}

func TestCandidateStrategyReadiness(t *testing.T) {
	serverBody := bytes.Repeat([]byte{0x53}, 30)
	state, err := newCandidateSessionControlState(serverBody)
	if err != nil {
		t.Fatal(err)
	}
	peerPing := candidateCodecFrame{Opcode: 0x00, StreamID: candidateSessionStreamID, Body: bytes.Repeat([]byte{0x29}, 29)}
	action, err := state.handle(peerPing)
	if err != nil || !action.PeerPing {
		t.Fatalf("peer ping action = %+v err=%v", action, err)
	}
	state.markPeerPingAckSent()
	if !candidateStrategyReadyForStreamOpen(candidateStrategyPeerAckOnly, state) {
		t.Fatal("Strategy A should not require the server-owned ping acknowledgement")
	}
	if candidateStrategyReadyForStreamOpen(candidateStrategyPeerAckThenPing, state) {
		t.Fatal("Strategy B must not open before the server ping is acknowledged")
	}

	state.markServerPingSent()
	if candidateStrategyReadyForStreamOpen(candidateStrategyPeerAckThenPing, state) {
		t.Fatal("Strategy B must wait for the own-ping acknowledgement")
	}
	action, err = state.handle(candidateCodecFrame{Opcode: 0x08, StreamID: candidateSessionStreamID, Body: serverBody})
	if err != nil || !action.OwnPingAckMatches {
		t.Fatalf("own ping acknowledgement = %+v err=%v", action, err)
	}
	if !candidateStrategyReadyForStreamOpen(candidateStrategyPeerAckThenPing, state) {
		t.Fatal("Strategy B should open after acknowledging peer ping and receiving own acknowledgement")
	}
}

func TestCandidateStrategyCInterleavedAcknowledgementAndStreamOpen(t *testing.T) {
	serverBody := bytes.Repeat([]byte{0x53}, 30)
	for _, frames := range [][]candidateCodecFrame{
		{
			{Opcode: 0x08, StreamID: candidateSessionStreamID, Body: serverBody},
			{Opcode: 0x01, StreamID: candidateProofStreamID},
		},
		{
			{Opcode: 0x01, StreamID: candidateProofStreamID},
			{Opcode: 0x08, StreamID: candidateSessionStreamID, Body: serverBody},
		},
	} {
		state, err := newCandidateSessionControlState(serverBody)
		if err != nil {
			t.Fatal(err)
		}
		state.peerPingSeen = true
		state.peerPingAckSent = true
		state.markServerPingSent()
		streamAckSeen := false
		for _, frame := range frames {
			if isCandidateStreamOpenAck(frame) {
				streamAckSeen = true
				continue
			}
			if _, err := state.handle(frame); err != nil {
				t.Fatal(err)
			}
		}
		if !streamAckSeen || !state.ownPingAcked {
			t.Fatalf("interleaved events not both accepted: stream_ack=%t own_ack=%t", streamAckSeen, state.ownPingAcked)
		}
	}
}

type candidateProofServer struct {
	listener     net.Listener
	store        *store.MemoryStore
	serverSecret []byte
	recorder     *observeRecorder
	mainReady    chan net.Conn
	chanReady    chan net.Conn
	done         chan struct{}
	closeOnce    sync.Once
}

func startCandidateProofServer(t *testing.T, ctx context.Context, st *store.MemoryStore, serverSecret []byte, recorder *observeRecorder) *candidateProofServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &candidateProofServer{
		listener:     l,
		store:        st,
		serverSecret: append([]byte(nil), serverSecret...),
		recorder:     recorder,
		mainReady:    make(chan net.Conn, 1),
		chanReady:    make(chan net.Conn, 1),
		done:         make(chan struct{}),
	}
	go s.serve(ctx)
	return s
}

func (s *candidateProofServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *candidateProofServer) Close() {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		close(s.done)
	})
}

func (s *candidateProofServer) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *candidateProofServer) handleConn(ctx context.Context, conn net.Conn) {
	connType, err := s.handshake(ctx, conn)
	if err != nil {
		s.recorder.note("candidate_handshake_failed", fmt.Sprintf("err=%s", candidateSanitizeErr(err)))
		_ = conn.Close()
		return
	}
	s.recorder.note("candidate_connection_type", fmt.Sprintf("type=%s", connType))
	switch connType {
	case "main":
		select {
		case s.mainReady <- conn:
		case <-ctx.Done():
			_ = conn.Close()
		}
	case "chan":
		select {
		case s.chanReady <- conn:
		case <-ctx.Done():
			_ = conn.Close()
		}
	default:
		_ = conn.Close()
	}
}

func (s *candidateProofServer) handshake(ctx context.Context, conn net.Conn) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	defer conn.SetDeadline(time.Time{})

	var preface [3]byte
	if _, err := io.ReadFull(conn, preface[:]); err != nil {
		return "", err
	}
	if string(preface[:]) != "TST" {
		return "", fmt.Errorf("unexpected preface")
	}
	if _, err := readCandidateLengthPrefixed(conn, 4096); err != nil {
		return "", err
	}
	if _, err := readCandidateLengthPrefixed(conn, 4096); err != nil {
		return "", err
	}
	if err := writeAll(conn, []byte("TST")); err != nil {
		return "", err
	}
	stockServerAuthField := bytes.Repeat([]byte{0x41}, 32)
	if err := writeAll(conn, stockServerAuthField); err != nil {
		return "", err
	}
	var token [32]byte
	if _, err := io.ReadFull(conn, token[:]); err != nil {
		return "", err
	}
	normalized, err := security.NormalizeLegacyWireToken(string(token[:]))
	if err != nil {
		return "", err
	}
	lookupKey, err := security.LegacyLookupKey(s.serverSecret, normalized)
	if err != nil {
		return "", err
	}
	if _, err := s.store.ResolveLegacyDeviceForAuth(ctx, lookupKey); err != nil {
		return "", err
	}
	if err := writeAll(conn, []byte("sucs")); err != nil {
		return "", err
	}
	var connType [4]byte
	if _, err := io.ReadFull(conn, connType[:]); err != nil {
		return "", err
	}
	return string(connType[:]), nil
}

// startMinimalSession performs only the active startup sequence already proven by
// the stock-npc fixtures: peer 0x00, exact 0x08 echo, server 0x06, peer 0x01.
func (s *candidateProofServer) startMinimalSession(ctx context.Context, npcMonitor *processMonitor) (*candidateProofSession, error) {
	mainConn, err := s.waitConn(ctx, npcMonitor, s.mainReady, "main")
	if err != nil {
		s.recorder.note("candidate_main_ready", "false")
		s.recorder.note("candidate_chan_ready", "false")
		return nil, err
	}
	s.recorder.note("candidate_main_ready", "true")
	go discardCandidateMain(ctx, mainConn)

	chanConn, err := s.waitConn(ctx, npcMonitor, s.chanReady, "chan")
	if err != nil {
		_ = mainConn.Close()
		s.recorder.note("candidate_chan_ready", "false")
		return nil, err
	}
	s.recorder.note("candidate_chan_ready", "true")

	session := &candidateProofSession{
		mainConn: mainConn,
		chanConn: chanConn,
		codec:    &candidateProofCodec{conn: chanConn, recorder: s.recorder},
	}
	state, err := newCandidateSessionControlState(candidateServerSessionBody(time.Now().UTC()))
	if err != nil {
		session.Close()
		return nil, err
	}
	if err := s.waitForInitialPeerPing(ctx, session.codec, state); err != nil {
		session.Close()
		return nil, err
	}
	if err := session.codec.writeShort(0x06, candidateProofStreamID); err != nil {
		session.Close()
		return nil, err
	}
	s.recorder.note("candidate_stream_06_sent", fmt.Sprintf("true stream=%d", candidateProofStreamID))

	deadline := time.Now().Add(candidateStreamOpenTimeout)
	for frameCount := 0; frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := session.codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			session.Close()
			return nil, err
		}
		session.codec.logFrame("npc_to_fake_server", frame)
		if isCandidateStreamOpenAck(frame) {
			s.recorder.note("candidate_stream_01_received", "true")
			return session, nil
		}
		if err := handleCandidateRuntimeControl(ctx, session.codec, frame, &session.runtime); err != nil {
			session.Close()
			return nil, err
		}
	}
	session.Close()
	return nil, fmt.Errorf("stream open acknowledgement frame limit")
}

func handleCandidateRuntimeControl(ctx context.Context, codec *candidateProofCodec, frame candidateCodecFrame, state *candidateRuntimeState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch frame.Opcode {
	case 0x00:
		if frame.StreamID != candidateSessionStreamID || len(frame.Body) == 0 || len(frame.Body) > 4096 {
			return fmt.Errorf("malformed peer session ping")
		}
		if err := codec.writeSessionControl(0x08, candidateSessionStreamID, frame.Body); err != nil {
			return err
		}
		state.SessionPingsAcked++
		codec.note("candidate_session_ping_ack", fmt.Sprintf("stream=session body_len=%d", len(frame.Body)))
		return nil
	case 0x08:
		if frame.StreamID != candidateSessionStreamID || len(frame.Body) == 0 || len(frame.Body) > 4096 {
			return fmt.Errorf("malformed peer session acknowledgement")
		}
		state.SessionAcksSeen++
		codec.note("candidate_session_ack_observed", fmt.Sprintf("stream=session body_len=%d", len(frame.Body)))
		return nil
	case 0x05:
		if frame.StreamID != candidateProofStreamID || len(frame.Body) != 8 {
			return fmt.Errorf("malformed candidate window control")
		}
		state.WindowControls++
		codec.note("candidate_window_control_observed", fmt.Sprintf("stream=%d body_len=%d active_reply=false", frame.StreamID, len(frame.Body)))
		return nil
	case 0x07:
		if frame.StreamID != candidateProofStreamID || len(frame.Body) != 0 {
			return fmt.Errorf("malformed candidate close")
		}
		state.CloseReceived = true
		codec.note("candidate_close_received", fmt.Sprintf("stream=%d", frame.StreamID))
		return nil
	case 0x01, 0x06:
		return fmt.Errorf("unexpected candidate control opcode=0x%02x", frame.Opcode)
	case 0x03:
		return fmt.Errorf("unexpected candidate data frame")
	default:
		return fmt.Errorf("unsupported candidate opcode=0x%02x", frame.Opcode)
	}
}

func waitForCandidatePayload(ctx context.Context, codec *candidateProofCodec, payload []byte, state candidateRuntimeState, recorder *observeRecorder) (bool, candidateRuntimeState, error) {
	deadline := time.Now().Add(5 * time.Second)
	for frameCount := 0; frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			return false, state, err
		}
		codec.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == 0x03 {
			if frame.StreamID != candidateProofStreamID || !bytes.Equal(frame.Body, payload) {
				return false, state, fmt.Errorf("unexpected candidate payload frame stream=%d body_len=%d", frame.StreamID, len(frame.Body))
			}
			recorder.note("candidate_payload_response", fmt.Sprintf("stream=%d payload_len=%d equality=true", frame.StreamID, len(payload)))
			return true, state, nil
		}
		if err := handleCandidateRuntimeControl(ctx, codec, frame, &state); err != nil {
			return false, state, err
		}
		if state.CloseReceived {
			return false, state, fmt.Errorf("candidate close received before payload response")
		}
	}
	return false, state, fmt.Errorf("payload response frame limit")
}

func waitForCandidateClose(ctx context.Context, codec *candidateProofCodec, target *candidateProofEchoTarget, state candidateRuntimeState, recorder *observeRecorder) (bool, bool, bool, candidateRuntimeState, error) {
	deadline := time.Now().Add(5 * time.Second)
	closeReceived := false
	targetClosed := false
	chanEOF := false
	for time.Now().Before(deadline) {
		if target.peerClosed() {
			targetClosed = true
		}
		if targetClosed && (closeReceived || chanEOF) {
			recorder.note("candidate_close_bounded", "true")
			return closeReceived, targetClosed, chanEOF, state, nil
		}
		remaining := time.Until(deadline)
		readWindow := 200 * time.Millisecond
		if remaining < readWindow {
			readWindow = remaining
		}
		frame, err := codec.readFrame(ctx, readWindow)
		if errors.Is(err, osErrTimeout) {
			continue
		}
		if errors.Is(err, io.EOF) {
			chanEOF = true
			continue
		}
		if err != nil {
			return closeReceived, targetClosed, chanEOF, state, err
		}
		codec.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == 0x07 {
			if err := handleCandidateRuntimeControl(ctx, codec, frame, &state); err != nil {
				return closeReceived, targetClosed, chanEOF, state, err
			}
			closeReceived = true
			continue
		}
		if err := handleCandidateRuntimeControl(ctx, codec, frame, &state); err != nil {
			return closeReceived, targetClosed, chanEOF, state, err
		}
	}
	return closeReceived, targetClosed, chanEOF, state, fmt.Errorf("timeout waiting for bounded close")
}

func (s *candidateProofServer) RunStrategy(ctx context.Context, npcMonitor *processMonitor, strategy candidateStrategy) candidateProofResult {
	mainConn, err := s.waitConn(ctx, npcMonitor, s.mainReady, "main")
	if err != nil {
		s.recorder.note("candidate_main_ready", "false")
		s.recorder.note("candidate_chan_ready", "false")
		s.recordCandidateSessionControlUnavailable()
		return candidateProofResult{CloseSummary: "main_not_ready", Readiness: "insufficient", Err: err}
	}
	defer mainConn.Close()
	go discardCandidateMain(ctx, mainConn)
	s.recorder.note("candidate_main_ready", "true")

	chanConn, err := s.waitConn(ctx, npcMonitor, s.chanReady, "chan")
	if err != nil {
		s.recorder.note("candidate_chan_ready", "false")
		s.recordCandidateSessionControlUnavailable()
		return candidateProofResult{CloseSummary: "chan_not_ready", Readiness: "insufficient", Err: err}
	}
	defer chanConn.Close()
	s.recorder.note("candidate_chan_ready", "true")

	codec := &candidateProofCodec{conn: chanConn, recorder: s.recorder}
	state, err := newCandidateSessionControlState(candidateServerSessionBody(time.Now().UTC()))
	if err != nil {
		s.recordCandidateSessionControlUnavailable()
		return candidateProofResult{CloseSummary: "server_session_body_invalid", Readiness: "insufficient", Err: err}
	}
	if err := s.waitForInitialPeerPing(ctx, codec, state); err != nil {
		s.recorder.note("candidate_server_00_sent", "false")
		s.recordCandidateSessionControlState(state)
		s.recordCandidateStreamOpenUnavailable()
		return candidateProofResult{CloseSummary: "initial_peer_ping_missing", Readiness: "insufficient", Err: err}
	}

	switch strategy {
	case candidateStrategyPeerAckOnly:
		s.recorder.note("candidate_server_00_sent", "false")
		return s.openStreamAfterSessionControl(ctx, codec, state, false)
	case candidateStrategyPeerAckThenPing:
		if err := s.sendServerPing(codec, state); err != nil {
			s.recordCandidateSessionControlState(state)
			s.recordCandidateStreamOpenUnavailable()
			return candidateProofResult{CloseSummary: "server_00_write_failed", Readiness: "insufficient", Err: err}
		}
		if err := s.waitForOwnPingAck(ctx, codec, state); err != nil {
			s.recordCandidateSessionControlState(state)
			s.recordCandidateStreamOpenUnavailable()
			return candidateProofResult{CloseSummary: "server_00_ack_missing", Readiness: "insufficient", Err: err}
		}
		return s.openStreamAfterSessionControl(ctx, codec, state, false)
	case candidateStrategyInterleaved:
		if err := s.sendServerPing(codec, state); err != nil {
			s.recordCandidateSessionControlState(state)
			s.recordCandidateStreamOpenUnavailable()
			return candidateProofResult{CloseSummary: "server_00_write_failed", Readiness: "insufficient", Err: err}
		}
		return s.openStreamAfterSessionControl(ctx, codec, state, true)
	default:
		s.recorder.note("candidate_server_00_sent", "false")
		s.recordCandidateSessionControlState(state)
		s.recordCandidateStreamOpenUnavailable()
		return candidateProofResult{CloseSummary: "unknown_strategy", Readiness: "insufficient", Err: fmt.Errorf("unknown strategy %q", strategy)}
	}
}

func (s *candidateProofServer) waitForInitialPeerPing(ctx context.Context, codec *candidateProofCodec, state *candidateSessionControlState) error {
	deadline := time.Now().Add(candidateSessionControlTimeout)
	for frameCount := 0; frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			return err
		}
		codec.logFrame("npc_to_fake_server", frame)
		if err := s.handleCandidateSessionControl(codec, state, frame); err != nil {
			return err
		}
		if state.peerPingSeen && state.peerPingAckSent {
			return nil
		}
	}
	return fmt.Errorf("initial peer ping frame limit")
}

func (s *candidateProofServer) sendServerPing(codec *candidateProofCodec, state *candidateSessionControlState) error {
	if err := codec.writeSessionControl(0x00, candidateSessionStreamID, state.serverBody); err != nil {
		s.recorder.note("candidate_server_00_sent", "false")
		return err
	}
	state.markServerPingSent()
	s.recorder.note("candidate_server_00_sent", fmt.Sprintf("true body_len=%d", len(state.serverBody)))
	return nil
}

func (s *candidateProofServer) waitForOwnPingAck(ctx context.Context, codec *candidateProofCodec, state *candidateSessionControlState) error {
	deadline := time.Now().Add(candidateSessionControlTimeout)
	for frameCount := 0; frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			return err
		}
		codec.logFrame("npc_to_fake_server", frame)
		if err := s.handleCandidateSessionControl(codec, state, frame); err != nil {
			return err
		}
		if state.ownPingAcked {
			return nil
		}
	}
	return fmt.Errorf("server ping acknowledgement frame limit")
}

func (s *candidateProofServer) openStreamAfterSessionControl(ctx context.Context, codec *candidateProofCodec, state *candidateSessionControlState, allowUnackedServerPing bool) candidateProofResult {
	defer s.recordCandidateSessionControlState(state)
	if err := codec.writeShort(0x06, candidateProofStreamID); err != nil {
		s.recorder.note("candidate_stream_06_sent", "false")
		s.recorder.note("candidate_stream_01_received", "false")
		return candidateProofResult{CloseSummary: "stream_open_write_failed", Readiness: "insufficient", Err: err}
	}
	s.recorder.note("candidate_stream_06_sent", fmt.Sprintf("true stream=%d", candidateProofStreamID))

	deadline := time.Now().Add(candidateSessionControlTimeout)
	for frameCount := 0; frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			s.recorder.note("candidate_stream_01_received", "false")
			return candidateProofResult{CloseSummary: "stream_open_ack_missing", Readiness: "insufficient", Err: err}
		}
		codec.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == 0x01 && frame.StreamID == candidateProofStreamID && len(frame.Body) == 0 {
			s.recorder.note("candidate_stream_01_received", "true")
			s.recorder.note("candidate_metadata_sent", "false reason=proof_stops_after_0x01")
			return candidateProofResult{CloseSummary: "stream_open_ack_observed", Readiness: "sufficient", StreamOpenAck: true}
		}
		if err := s.handleCandidateSessionControl(codec, state, frame); err != nil {
			s.recorder.note("candidate_stream_01_received", "false")
			return candidateProofResult{CloseSummary: "unexpected_stream_open_wait_frame", Readiness: "insufficient", Err: err}
		}
		if !allowUnackedServerPing && state.serverPingSent && !state.ownPingAcked {
			s.recorder.note("candidate_stream_01_received", "false")
			return candidateProofResult{CloseSummary: "server_00_ack_missing", Readiness: "insufficient", Err: fmt.Errorf("server ping acknowledgement missing while waiting for stream open")}
		}
	}
	s.recorder.note("candidate_stream_01_received", "false")
	return candidateProofResult{CloseSummary: "stream_open_frame_limit", Readiness: "insufficient", Err: fmt.Errorf("stream open acknowledgement frame limit")}
}

func (s *candidateProofServer) RunProof(ctx context.Context, npcMonitor *processMonitor) candidateProofResult {
	s.recorder.note("candidate_proof_mode", "symmetric_session_control")

	mainConn, err := s.waitConn(ctx, npcMonitor, s.mainReady, "main")
	if err != nil {
		s.recordCandidateSessionControlUnavailable()
		return candidateProofResult{CloseSummary: "main_not_ready", Readiness: "insufficient", Err: err}
	}
	defer mainConn.Close()
	go discardCandidateMain(ctx, mainConn)
	s.recorder.note("candidate_main_ready", "ready=true")

	chanConn, err := s.waitConn(ctx, npcMonitor, s.chanReady, "chan")
	if err != nil {
		s.recordCandidateSessionControlUnavailable()
		return candidateProofResult{CloseSummary: "chan_not_ready", Readiness: "insufficient", Err: err}
	}
	defer chanConn.Close()
	s.recorder.note("candidate_chan_ready", "ready=true")

	codec := &candidateProofCodec{conn: chanConn, recorder: s.recorder}
	state, err := newCandidateSessionControlState(candidateServerSessionBody(time.Now().UTC()))
	if err != nil {
		s.recordCandidateSessionControlUnavailable()
		return candidateProofResult{CloseSummary: "server_session_body_invalid", Readiness: "insufficient", Err: err}
	}
	if err := codec.writeSessionControl(0x00, candidateSessionStreamID, state.serverBody); err != nil {
		s.recorder.note("candidate_server_00_sent", "false")
		s.recordCandidateSessionControlState(state)
		return candidateProofResult{CloseSummary: "server_00_write_failed", Readiness: "insufficient", Err: err}
	}
	state.markServerPingSent()
	s.recorder.note("candidate_server_00_sent", fmt.Sprintf("true body_len=%d", len(state.serverBody)))

	deadline := time.Now().Add(candidateSessionControlTimeout)
	for frameCount := 0; !state.ready() && frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			s.recordCandidateSessionControlState(state)
			s.recordCandidateStreamOpenUnavailable()
			return candidateProofResult{CloseSummary: "session_control_not_ready", Readiness: "insufficient", Err: err}
		}
		codec.logFrame("npc_to_fake_server", frame)
		if err := s.handleCandidateSessionControl(codec, state, frame); err != nil {
			s.recordCandidateSessionControlState(state)
			s.recordCandidateStreamOpenUnavailable()
			return candidateProofResult{CloseSummary: "unexpected_session_control_frame", Readiness: "insufficient", Err: err}
		}
	}
	if !state.ready() {
		s.recordCandidateSessionControlState(state)
		s.recordCandidateStreamOpenUnavailable()
		return candidateProofResult{CloseSummary: "session_control_frame_limit", Readiness: "insufficient", Err: fmt.Errorf("session control did not become ready")}
	}
	s.recordCandidateSessionControlState(state)

	if err := codec.writeShort(0x06, candidateProofStreamID); err != nil {
		s.recorder.note("candidate_stream_06_sent", "false")
		s.recorder.note("candidate_stream_01_received", "false")
		return candidateProofResult{CloseSummary: "stream_open_write_failed", Readiness: "insufficient", Err: err}
	}
	s.recorder.note("candidate_stream_06_sent", fmt.Sprintf("true stream=%d", candidateProofStreamID))

	deadline = time.Now().Add(candidateSessionControlTimeout)
	for frameCount := 0; frameCount < candidateMaxSessionControlFrames; frameCount++ {
		frame, err := codec.readFrame(ctx, time.Until(deadline))
		if err != nil {
			s.recorder.note("candidate_stream_01_received", "false")
			return candidateProofResult{CloseSummary: "stream_open_ack_missing", Readiness: "insufficient", Err: err}
		}
		codec.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == 0x01 && frame.StreamID == candidateProofStreamID && len(frame.Body) == 0 {
			s.recorder.note("candidate_stream_01_received", "true")
			s.recorder.note("candidate_metadata_sent", "false reason=proof_stops_after_0x01")
			s.recorder.note("candidate_target_dialed", "seen=false")
			s.recorder.note("candidate_response_returned", "seen=false")
			return candidateProofResult{CloseSummary: "session_control_and_stream_open_ack_observed", Readiness: "sufficient"}
		}
		if err := s.handleCandidateSessionControl(codec, state, frame); err != nil {
			s.recorder.note("candidate_stream_01_received", "false")
			return candidateProofResult{CloseSummary: "unexpected_stream_open_wait_frame", Readiness: "insufficient", Err: err}
		}
	}
	s.recorder.note("candidate_stream_01_received", "false")
	return candidateProofResult{CloseSummary: "stream_open_frame_limit", Readiness: "insufficient", Err: fmt.Errorf("stream open acknowledgement not observed")}
}

func (s *candidateProofServer) handleCandidateSessionControl(codec *candidateProofCodec, state *candidateSessionControlState, frame candidateCodecFrame) error {
	action, err := state.handle(frame)
	if err != nil {
		return err
	}
	if action.PeerPing {
		s.recorder.note("candidate_client_00_received", fmt.Sprintf("true body_len=%d", action.ClientFrameBodyLen))
		if err := codec.writeSessionControl(0x08, candidateSessionStreamID, action.PeerPingBody); err != nil {
			s.recorder.note("candidate_client_00_ack_08_sent", "false")
			return err
		}
		state.markPeerPingAckSent()
		s.recorder.note("candidate_client_00_ack_08_sent", fmt.Sprintf("true body_len=%d", action.ClientFrameBodyLen))
		return nil
	}
	if action.OwnPingAck {
		s.recorder.note("candidate_client_08_received", fmt.Sprintf("true body_len=%d", action.ClientFrameBodyLen))
		s.recorder.note("candidate_client_08_matches_server_00", fmt.Sprintf("%t", action.OwnPingAckMatches))
	}
	return nil
}

func (s *candidateProofServer) recordCandidateSessionControlState(state *candidateSessionControlState) {
	if !state.peerPingSeen {
		s.recorder.note("candidate_client_00_received", "false")
	}
	if !state.peerPingAckSent {
		s.recorder.note("candidate_client_00_ack_08_sent", "false")
	}
	if !state.client08Seen {
		s.recorder.note("candidate_client_08_received", "false")
		s.recorder.note("candidate_client_08_matches_server_00", "false")
	}
	s.recorder.note("candidate_peer_ping_seen", fmt.Sprintf("%t", state.peerPingSeen))
	s.recorder.note("candidate_peer_ping_ack_sent", fmt.Sprintf("%t", state.peerPingAckSent))
	s.recorder.note("candidate_own_ping_acked", fmt.Sprintf("%t", state.ownPingAcked))
	s.recorder.note("candidate_session_control_ready", fmt.Sprintf("%t", state.ready()))
	unexpected := state.unexpectedOpcode
	if unexpected == "" {
		unexpected = "none"
	}
	s.recorder.note("candidate_unexpected_opcode", unexpected)
}

func (s *candidateProofServer) recordCandidateStreamOpenUnavailable() {
	s.recorder.note("candidate_stream_06_sent", "false")
	s.recorder.note("candidate_stream_01_received", "false")
}

func (s *candidateProofServer) recordCandidateSessionControlUnavailable() {
	s.recorder.note("candidate_client_00_received", "false")
	s.recorder.note("candidate_client_00_ack_08_sent", "false")
	s.recorder.note("candidate_server_00_sent", "false")
	s.recorder.note("candidate_client_08_received", "false")
	s.recorder.note("candidate_client_08_matches_server_00", "false")
	s.recorder.note("candidate_peer_ping_seen", "false")
	s.recorder.note("candidate_peer_ping_ack_sent", "false")
	s.recorder.note("candidate_own_ping_acked", "false")
	s.recorder.note("candidate_session_control_ready", "false")
	s.recorder.note("candidate_unexpected_opcode", "none")
	s.recorder.note("candidate_stream_06_sent", "false")
	s.recorder.note("candidate_stream_01_received", "false")
}

func (s *candidateProofServer) waitConn(ctx context.Context, npcMonitor *processMonitor, ch <-chan net.Conn, role string) (net.Conn, error) {
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	select {
	case conn := <-ch:
		return conn, nil
	case <-npcMonitor.Done():
		return nil, fmt.Errorf("npc exited before %s ready: status=%s", role, npcMonitor.Status())
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for %s connection", role)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func discardCandidateMain(ctx context.Context, conn net.Conn) {
	var buf [256]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if _, err := conn.Read(buf[:]); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && ctx.Err() == nil {
				continue
			}
			return
		}
	}
}

type candidateProofCodec struct {
	conn     net.Conn
	recorder *observeRecorder
}

type candidateCodecFrame struct {
	Opcode   byte
	StreamID uint32
	Body     []byte
}

func (c *candidateProofCodec) waitForSessionControl(ctx context.Context, opcode byte, streamID uint32, timeout time.Duration) (candidateCodecFrame, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frame, err := c.readFrame(ctx, time.Until(deadline))
		if err != nil {
			return candidateCodecFrame{}, err
		}
		c.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == opcode && frame.StreamID == streamID {
			return frame, nil
		}
	}
	return candidateCodecFrame{}, fmt.Errorf("timeout waiting for session control opcode=0x%02x stream=%d", opcode, streamID)
}

func (c *candidateProofCodec) waitForShort(ctx context.Context, opcode byte, streamID uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frame, err := c.readFrame(ctx, time.Until(deadline))
		if err != nil {
			return err
		}
		c.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == opcode && frame.StreamID == streamID && len(frame.Body) == 0 {
			return nil
		}
	}
	return fmt.Errorf("timeout waiting for opcode=0x%02x stream=%d", opcode, streamID)
}

func (c *candidateProofCodec) waitForPayload(ctx context.Context, streamID uint32, payload []byte, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frame, err := c.readFrame(ctx, time.Until(deadline))
		if err != nil {
			return false, err
		}
		c.logFrame("npc_to_fake_server", frame)
		if frame.Opcode == 0x03 && frame.StreamID == streamID && bytes.Equal(frame.Body, payload) {
			return true, nil
		}
	}
	return false, fmt.Errorf("timeout waiting for response payload")
}

func (c *candidateProofCodec) readFrame(ctx context.Context, timeout time.Duration) (candidateCodecFrame, error) {
	if err := ctx.Err(); err != nil {
		return candidateCodecFrame{}, err
	}
	if timeout <= 0 {
		timeout = time.Millisecond
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	var header [7]byte
	if _, err := io.ReadFull(c.conn, header[:1]); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return candidateCodecFrame{}, osErrTimeout
		}
		return candidateCodecFrame{}, err
	}
	opcode := header[0]
	switch opcode {
	case 0x01, 0x06, 0x07:
		if _, err := io.ReadFull(c.conn, header[1:5]); err != nil {
			return candidateCodecFrame{}, err
		}
		return candidateCodecFrame{Opcode: opcode, StreamID: binary.LittleEndian.Uint32(header[1:5])}, nil
	case 0x05:
		var rest [12]byte
		if _, err := io.ReadFull(c.conn, rest[:]); err != nil {
			return candidateCodecFrame{}, err
		}
		return candidateCodecFrame{Opcode: opcode, StreamID: binary.LittleEndian.Uint32(rest[0:4]), Body: append([]byte(nil), rest[4:]...)}, nil
	case 0x00, 0x03, 0x08:
		if _, err := io.ReadFull(c.conn, header[1:7]); err != nil {
			return candidateCodecFrame{}, err
		}
		streamID := binary.LittleEndian.Uint32(header[1:5])
		bodyLen := binary.LittleEndian.Uint16(header[5:7])
		if bodyLen > 4096 {
			return candidateCodecFrame{}, fmt.Errorf("candidate frame body too large: opcode=0x%02x len=%d", opcode, bodyLen)
		}
		body := make([]byte, int(bodyLen))
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return candidateCodecFrame{}, err
		}
		return candidateCodecFrame{Opcode: opcode, StreamID: streamID, Body: body}, nil
	default:
		return candidateCodecFrame{}, fmt.Errorf("unsupported candidate opcode=0x%02x", opcode)
	}
}

func (c *candidateProofCodec) writeShort(opcode byte, streamID uint32) error {
	var frame [5]byte
	frame[0] = opcode
	binary.LittleEndian.PutUint32(frame[1:5], streamID)
	c.note("candidate_frame_write", fmt.Sprintf("direction=fake_server_to_npc opcode=0x%02x stream=%d bytes=5", opcode, streamID))
	return c.writeBounded(frame[:])
}

func (c *candidateProofCodec) writeSessionControl(opcode byte, streamID uint32, body []byte) error {
	if len(body) > 4096 {
		return fmt.Errorf("candidate session body too large")
	}
	frame := make([]byte, 7+len(body))
	frame[0] = opcode
	binary.LittleEndian.PutUint32(frame[1:5], streamID)
	binary.LittleEndian.PutUint16(frame[5:7], uint16(len(body)))
	copy(frame[7:], body)
	c.note("candidate_frame_write", fmt.Sprintf("direction=fake_server_to_npc opcode=0x%02x stream=%d body_len=%d", opcode, streamID, len(body)))
	return c.writeBounded(frame)
}

func (c *candidateProofCodec) writeData(streamID uint32, body []byte) error {
	return c.writeDataFrame(streamID, body)
}

func (c *candidateProofCodec) writeDataFrame(streamID uint32, body []byte) error {
	frame, err := encodeCandidateDataFrame(streamID, body)
	if err != nil {
		return err
	}
	c.note("candidate_frame_write", fmt.Sprintf("direction=fake_server_to_npc opcode=0x03 stream=%d body_len=%d", streamID, len(body)))
	return c.writeBounded(frame)
}

func (c *candidateProofCodec) writeReplayFrame(frame candidateReplayFrame) error {
	c.note("candidate_frame_write", fmt.Sprintf("direction=fake_server_to_npc opcode=0x%02x stream=%d body_len=%d fixture_seq=%d", frame.Opcode, frame.StreamID, len(frame.Body), frame.Seq))
	return c.writeBounded(frame.Raw)
}

func (c *candidateProofCodec) writeBounded(frame []byte) error {
	if c.conn == nil {
		return errors.New("candidate connection missing")
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	defer c.conn.SetWriteDeadline(time.Time{})
	return writeAll(c.conn, frame)
}

func (c *candidateProofCodec) logFrame(direction string, frame candidateCodecFrame) {
	c.note("candidate_frame_read", fmt.Sprintf("direction=%s opcode=0x%02x stream=%d body_len=%d", direction, frame.Opcode, frame.StreamID, len(frame.Body)))
}

func (c *candidateProofCodec) note(state, message string) {
	if c.recorder != nil {
		c.recorder.note(state, message)
	}
}

type candidateReplayStartup struct {
	Server00    candidateReplayFrame
	Server08    candidateReplayFrame
	Server06    candidateReplayFrame
	Server00Seq int
	Server08Seq int
	Server06Seq int
}

type candidateReplayFrame struct {
	Seq      int
	Opcode   byte
	StreamID uint32
	Body     []byte
	Raw      []byte
}

type candidateReplayFixture struct {
	Frames []candidateReplayFixtureFrame `json:"frames"`
}

type candidateReplayFixtureFrame struct {
	Direction             string `json:"direction"`
	Seq                   int    `json:"seq"`
	ProbeID               int    `json:"probe_id"`
	ByteCount             int    `json:"byte_count"`
	SanitizedHex          string `json:"sanitized_hex"`
	CandidateOpcodeByte   string `json:"candidate_opcode_byte"`
	CandidateStreamIDLE32 uint32 `json:"candidate_stream_id_le32"`
	CandidateLengthLE16   uint16 `json:"candidate_length_le16"`
}

func loadCandidateReplayStartup() (candidateReplayStartup, error) {
	path := filepath.Join("testdata", "stock_nps_v0.26.34", "tcp_echo_chan_frames.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return candidateReplayStartup{}, fmt.Errorf("read fixture: %w", err)
	}
	var fixture candidateReplayFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return candidateReplayStartup{}, fmt.Errorf("parse fixture: %w", err)
	}
	var server00 candidateReplayFrame
	var server08Header candidateReplayFrame
	var server08 candidateReplayFrame
	var server06 candidateReplayFrame
	for _, frame := range fixture.Frames {
		if frame.ProbeID != 1 || frame.Direction != "nps_to_npc" {
			continue
		}
		switch {
		case server00.Raw == nil &&
			frame.CandidateOpcodeByte == "0x00" &&
			frame.CandidateStreamIDLE32 == 0xffffffff &&
			frame.CandidateLengthLE16 == 30 &&
			frame.ByteCount == 37:
			decoded, err := decodeCandidateFixtureHex(frame.SanitizedHex)
			if err != nil {
				return candidateReplayStartup{}, fmt.Errorf("decode fixture server 0x00 seq=%d: %w", frame.Seq, err)
			}
			server00, err = parseCandidateReplayFrame(frame.Seq, decoded)
			if err != nil {
				return candidateReplayStartup{}, fmt.Errorf("parse fixture server 0x00 seq=%d: %w", frame.Seq, err)
			}
		case server08.Raw == nil &&
			frame.CandidateOpcodeByte == "0x08" &&
			frame.CandidateStreamIDLE32 == 0xffffffff &&
			frame.CandidateLengthLE16 == 30:
			decoded, err := decodeCandidateFixtureHex(frame.SanitizedHex)
			if err == nil && len(decoded) == 37 {
				server08, err = parseCandidateReplayFrame(frame.Seq, decoded)
				if err != nil {
					return candidateReplayStartup{}, fmt.Errorf("parse fixture server 0x08 seq=%d: %w", frame.Seq, err)
				}
			} else if err == nil && len(decoded) == 7 && server08Header.Raw == nil {
				server08Header, err = parseCandidateReplayFrame(frame.Seq, decoded)
				if err != nil {
					return candidateReplayStartup{}, fmt.Errorf("parse fixture server 0x08 header seq=%d: %w", frame.Seq, err)
				}
			}
		case server06.Raw == nil &&
			frame.CandidateOpcodeByte == "0x06" &&
			frame.CandidateStreamIDLE32 == candidateProofStreamID &&
			frame.ByteCount == 5:
			decoded, err := decodeCandidateFixtureHex(frame.SanitizedHex)
			if err != nil {
				return candidateReplayStartup{}, fmt.Errorf("decode fixture server 0x06 seq=%d: %w", frame.Seq, err)
			}
			server06, err = parseCandidateReplayFrame(frame.Seq, decoded)
			if err != nil {
				return candidateReplayStartup{}, fmt.Errorf("parse fixture server 0x06 seq=%d: %w", frame.Seq, err)
			}
		}
	}
	if server00.Raw == nil {
		return candidateReplayStartup{}, fmt.Errorf("missing replay server 0x00 frame with preserved bytes")
	}
	if server08.Raw == nil {
		if server08Header.Raw == nil {
			return candidateReplayStartup{}, fmt.Errorf("missing replay server 0x08 frame header")
		}
		if len(server00.Body) != 30 {
			return candidateReplayStartup{}, fmt.Errorf("missing replay server 0x08 body and server 0x00 body length is %d", len(server00.Body))
		}
		server08 = candidateReplayFrame{
			Seq:      server08Header.Seq,
			Opcode:   server08Header.Opcode,
			StreamID: server08Header.StreamID,
			Body:     append([]byte(nil), server00.Body...),
			Raw:      append(append([]byte(nil), server08Header.Raw...), server00.Body...),
		}
	}
	if server06.Raw == nil {
		return candidateReplayStartup{}, fmt.Errorf("missing replay server 0x06 frame with preserved bytes")
	}
	return candidateReplayStartup{
		Server00:    server00,
		Server08:    server08,
		Server06:    server06,
		Server00Seq: server00.Seq,
		Server08Seq: server08.Seq,
		Server06Seq: server06.Seq,
	}, nil
}

func decodeCandidateFixtureHex(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "<") || strings.Contains(value, " ") {
		return nil, fmt.Errorf("fixture frame does not preserve exact non-secret bytes")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func parseCandidateReplayFrame(seq int, raw []byte) (candidateReplayFrame, error) {
	if len(raw) < 5 {
		return candidateReplayFrame{}, fmt.Errorf("frame too short")
	}
	frame := candidateReplayFrame{
		Seq:    seq,
		Opcode: raw[0],
		Raw:    append([]byte(nil), raw...),
	}
	switch raw[0] {
	case 0x00, 0x08:
		if len(raw) < 7 {
			return candidateReplayFrame{}, fmt.Errorf("session frame too short")
		}
		frame.StreamID = binary.LittleEndian.Uint32(raw[1:5])
		bodyLen := binary.LittleEndian.Uint16(raw[5:7])
		if len(raw) != 7+int(bodyLen) && len(raw) != 7 {
			return candidateReplayFrame{}, fmt.Errorf("session frame length mismatch")
		}
		if len(raw) == 7+int(bodyLen) {
			frame.Body = append([]byte(nil), raw[7:]...)
		}
	case 0x06:
		if len(raw) != 5 {
			return candidateReplayFrame{}, fmt.Errorf("short frame length mismatch")
		}
		frame.StreamID = binary.LittleEndian.Uint32(raw[1:5])
	default:
		return candidateReplayFrame{}, fmt.Errorf("unsupported replay opcode=0x%02x", raw[0])
	}
	return frame, nil
}

type candidateOpenMetadata struct {
	ConnType     string              `json:"ConnType"`
	Host         string              `json:"Host"`
	RemoteAddr   string              `json:"RemoteAddr"`
	Compress     bool                `json:"Compress"`
	Crypt        bool                `json:"Crypt"`
	LocalProxy   bool                `json:"LocalProxy"`
	ProtoVersion string              `json:"ProtoVersion"`
	Option       candidateOpenOption `json:"Option"`
}

type candidateOpenOption struct {
	Timeout int64 `json:"Timeout"`
}

func candidateOpenMetadataForTarget(targetAddr string) (candidateOpenMetadata, error) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return candidateOpenMetadata{}, fmt.Errorf("candidate target address is malformed")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return candidateOpenMetadata{}, fmt.Errorf("candidate target address must be loopback")
	}
	return candidateOpenMetadata{
		ConnType:     "tcp",
		Host:         targetAddr,
		RemoteAddr:   "127.0.0.1:0",
		Compress:     false,
		Crypt:        false,
		LocalProxy:   false,
		ProtoVersion: "",
		Option:       candidateOpenOption{Timeout: 5000000000},
	}, nil
}

func candidateMetadataKeySet() string {
	return "ConnType,Host,RemoteAddr,Compress,Crypt,LocalProxy,ProtoVersion,Option.Timeout"
}

func encodeCandidateOpenMetadataBody(metadata candidateOpenMetadata) ([]byte, error) {
	jsonBody, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 4+len(jsonBody))
	binary.LittleEndian.PutUint32(body[:4], uint32(len(jsonBody)))
	copy(body[4:], jsonBody)
	if len(body) > math.MaxUint16 {
		return nil, fmt.Errorf("candidate metadata body exceeds uint16 length")
	}
	return body, nil
}

func encodeCandidateMetadataFrame(streamID uint32, metadata candidateOpenMetadata) ([]byte, error) {
	body, err := encodeCandidateOpenMetadataBody(metadata)
	if err != nil {
		return nil, err
	}
	return encodeCandidateDataFrame(streamID, body)
}

func encodeCandidateDataFrame(streamID uint32, body []byte) ([]byte, error) {
	if len(body) > math.MaxUint16 {
		return nil, fmt.Errorf("candidate data body exceeds uint16 length")
	}
	frame := make([]byte, 7+len(body))
	frame[0] = 0x03
	binary.LittleEndian.PutUint32(frame[1:5], streamID)
	binary.LittleEndian.PutUint16(frame[5:7], uint16(len(body)))
	copy(frame[7:], body)
	return frame, nil
}

func readCandidateLengthPrefixed(r io.Reader, max int) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(prefix[:])
	if size == 0 || int(size) > max {
		return nil, fmt.Errorf("invalid length-prefixed field")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeCandidateLengthPrefixed(w io.Writer, payload []byte) error {
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(payload)))
	if err := writeAll(w, prefix[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func candidateServerSessionBody(now time.Time) []byte {
	body := []byte(now.UTC().Format("2006-01-02T15:04:05.000000000Z"))
	if len(body) != 30 {
		panic("candidate server session body must be 30 bytes")
	}
	return body
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type candidateProofEchoTarget struct {
	listener     net.Listener
	accepted     chan struct{}
	received     chan []byte
	peerClosedCh chan struct{}
	cancel       context.CancelFunc
	mu           sync.Mutex
	conns        map[net.Conn]struct{}
	closeOnce    sync.Once
	peerOnce     sync.Once
}

func startCandidateProofEchoTarget(t *testing.T, ctx context.Context, recorder *observeRecorder) *candidateProofEchoTarget {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	target := &candidateProofEchoTarget{
		listener:     l,
		accepted:     make(chan struct{}, 1),
		received:     make(chan []byte, 1),
		peerClosedCh: make(chan struct{}),
		cancel:       cancel,
		conns:        make(map[net.Conn]struct{}),
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			recorder.note("candidate_target_connection", "seen=true remote=loopback")
			target.mu.Lock()
			target.conns[conn] = struct{}{}
			target.mu.Unlock()
			select {
			case target.accepted <- struct{}{}:
			default:
			}
			go target.serveConn(conn)
		}
	}()
	return target
}

func (t *candidateProofEchoTarget) Addr() string {
	return t.listener.Addr().String()
}

func (t *candidateProofEchoTarget) Close() {
	t.closeOnce.Do(func() {
		t.cancel()
		_ = t.listener.Close()
		t.mu.Lock()
		for conn := range t.conns {
			_ = conn.Close()
		}
		t.mu.Unlock()
	})
}

func (t *candidateProofEchoTarget) serveConn(conn net.Conn) {
	defer func() {
		t.mu.Lock()
		delete(t.conns, conn)
		t.mu.Unlock()
		_ = conn.Close()
	}()
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			select {
			case t.received <- payload:
			default:
			}
			_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if writeErr := writeAll(conn, payload); writeErr != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Time{})
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			t.peerOnce.Do(func() { close(t.peerClosedCh) })
		}
		return
	}
}

func (t *candidateProofEchoTarget) waitForDial(ctx context.Context) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-t.accepted:
		return nil
	case <-timer.C:
		return fmt.Errorf("timeout waiting for target dial")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *candidateProofEchoTarget) waitForPayload(ctx context.Context, want []byte) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case got := <-t.received:
		if !bytes.Equal(got, want) {
			return fmt.Errorf("target payload mismatch: got_len=%d want_len=%d", len(got), len(want))
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("timeout waiting for target payload")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *candidateProofEchoTarget) peerClosed() bool {
	select {
	case <-t.peerClosedCh:
		return true
	default:
		return false
	}
}

func TestCandidateOpenMetadataEncoding(t *testing.T) {
	metadata, err := candidateOpenMetadataForTarget("127.0.0.1:43123")
	if err != nil {
		t.Fatal(err)
	}
	body, err := encodeCandidateOpenMetadataBody(metadata)
	if err != nil {
		t.Fatal(err)
	}
	jsonLength := binary.LittleEndian.Uint32(body[:4])
	if int(jsonLength) != len(body)-4 {
		t.Fatalf("nested json length=%d want=%d", jsonLength, len(body)-4)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body[4:], &decoded); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"Compress", "ConnType", "Crypt", "Host", "LocalProxy", "Option", "ProtoVersion", "RemoteAddr"}
	if len(decoded) != len(wantKeys) {
		t.Fatalf("metadata key count=%d want=%d", len(decoded), len(wantKeys))
	}
	for _, key := range wantKeys {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("metadata missing key %q", key)
		}
	}
	if metadata.ConnType != "tcp" || metadata.Host != "127.0.0.1:43123" || metadata.RemoteAddr != "127.0.0.1:0" || metadata.Compress || metadata.Crypt || metadata.LocalProxy || metadata.ProtoVersion != "" || metadata.Option.Timeout != 5000000000 {
		t.Fatalf("metadata values differ from the bounded candidate: %+v", metadata)
	}
	payload := []byte("kavern-proof-echo-1")
	if bytes.Contains(body, payload) {
		t.Fatal("metadata body must not include application payload bytes")
	}
	frame, err := encodeCandidateMetadataFrame(candidateProofStreamID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if frame[0] != 0x03 || binary.LittleEndian.Uint32(frame[1:5]) != candidateProofStreamID || int(binary.LittleEndian.Uint16(frame[5:7])) != len(body) || !bytes.Equal(frame[7:], body) {
		t.Fatal("metadata frame does not preserve the candidate outer and nested lengths")
	}
}

func TestCandidateOpenMetadataRequiresLoopbackTarget(t *testing.T) {
	if _, err := candidateOpenMetadataForTarget("203.0.113.9:43123"); err == nil {
		t.Fatal("non-loopback target was accepted")
	}
}

func TestCandidateDataFrameRejectsUint16Overflow(t *testing.T) {
	if _, err := encodeCandidateDataFrame(candidateProofStreamID, make([]byte, math.MaxUint16+1)); err == nil {
		t.Fatal("oversized data frame was accepted")
	}
	metadata := candidateOpenMetadata{
		ConnType:     "tcp",
		Host:         "127.0.0.1:" + strings.Repeat("9", math.MaxUint16),
		RemoteAddr:   "127.0.0.1:0",
		ProtoVersion: "",
		Option:       candidateOpenOption{Timeout: 5000000000},
	}
	if _, err := encodeCandidateOpenMetadataBody(metadata); err == nil {
		t.Fatal("oversized metadata body was accepted")
	}
}

func TestCandidatePayloadFrameShape(t *testing.T) {
	payload := []byte("kavern-proof-echo-1")
	frame, err := encodeCandidateDataFrame(candidateProofStreamID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 7+len(payload) || frame[0] != 0x03 || binary.LittleEndian.Uint32(frame[1:5]) != candidateProofStreamID || int(binary.LittleEndian.Uint16(frame[5:7])) != len(payload) || !bytes.Equal(frame[7:], payload) {
		t.Fatal("payload frame shape does not match the candidate grammar")
	}
}

func TestCandidateWriteAllCompletesPartialWrites(t *testing.T) {
	w := &candidatePartialWriter{limit: 3}
	input := []byte("partial-write-proof")
	if err := writeAll(w, input); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes(), input) {
		t.Fatal("writeAll did not complete partial writes")
	}
}

func TestCandidateCodecFailsClosedForMalformedOrUnknownFrames(t *testing.T) {
	for _, raw := range [][]byte{
		{0x7f},
		{0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10},
	} {
		server, peer := net.Pipe()
		done := make(chan struct{})
		go func(frame []byte) {
			_, _ = peer.Write(frame)
			_ = peer.Close()
			close(done)
		}(raw)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := (&candidateProofCodec{conn: server}).readFrame(ctx, time.Second)
		cancel()
		_ = server.Close()
		<-done
		if err == nil {
			t.Fatalf("malformed candidate frame %x was accepted", raw[:1])
		}
	}
	state := candidateRuntimeState{}
	if err := handleCandidateRuntimeControl(context.Background(), &candidateProofCodec{}, candidateCodecFrame{Opcode: 0x01, StreamID: candidateProofStreamID}, &state); err == nil {
		t.Fatal("unexpected repeated stream acknowledgement was accepted")
	}
}

func TestCandidateRuntimeControlAcknowledgesPeerSessionPing(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	body := []byte{0x41, 0x42, 0x43}
	response := make(chan error, 1)
	go func() {
		frame := append([]byte{0x00, 0xff, 0xff, 0xff, 0xff, byte(len(body)), 0x00}, body...)
		if err := writeAll(peer, frame); err != nil {
			response <- err
			return
		}
		got := make([]byte, len(frame))
		_, err := io.ReadFull(peer, got)
		if err == nil && !bytes.Equal(got, append([]byte{0x08, 0xff, 0xff, 0xff, 0xff, byte(len(body)), 0x00}, body...)) {
			err = errors.New("session ping acknowledgement was not exact")
		}
		response <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	codec := &candidateProofCodec{conn: server}
	frame, err := codec.readFrame(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	state := candidateRuntimeState{}
	if err := handleCandidateRuntimeControl(ctx, codec, frame, &state); err != nil {
		t.Fatal(err)
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	if state.SessionPingsAcked != 1 {
		t.Fatalf("session pings acknowledged=%d want=1", state.SessionPingsAcked)
	}
}

func TestCandidateRuntimeControlDoesNotGuessWindowReply(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	readDone := make(chan error, 1)
	go func() {
		frame := make([]byte, 13)
		frame[0] = 0x05
		binary.LittleEndian.PutUint32(frame[1:5], candidateProofStreamID)
		if err := writeAll(peer, frame); err != nil {
			readDone <- err
			return
		}
		_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		var one [1]byte
		_, err := peer.Read(one[:])
		if err == nil {
			readDone <- errors.New("window control unexpectedly received a reply")
			return
		}
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			readDone <- err
			return
		}
		readDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	codec := &candidateProofCodec{conn: server}
	frame, err := codec.readFrame(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	state := candidateRuntimeState{}
	if err := handleCandidateRuntimeControl(ctx, codec, frame, &state); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if state.WindowControls != 1 {
		t.Fatalf("window controls=%d want=1", state.WindowControls)
	}
}

type candidatePartialWriter struct {
	bytes.Buffer
	limit int
}

func (w *candidatePartialWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestCandidateStrictMode(t *testing.T) {
	for _, tc := range []struct {
		value      string
		wantStrict bool
		wantErr    bool
	}{
		{value: "", wantStrict: false},
		{value: "1", wantStrict: true},
		{value: "0", wantErr: true},
		{value: "true", wantErr: true},
	} {
		t.Run(fmt.Sprintf("value_%q", tc.value), func(t *testing.T) {
			t.Setenv("KAVERN_CANDIDATE_REQUIRE_SUFFICIENT", tc.value)
			got, err := candidateStrictMode()
			if (err != nil) != tc.wantErr || got != tc.wantStrict {
				t.Fatalf("candidateStrictMode() = (%t, %v)", got, err)
			}
		})
	}
}

func TestCandidateStrategySelection(t *testing.T) {
	all := append(candidateSuccessfulAttempts(candidateStrategyPeerAckOnly), candidateSuccessfulAttempts(candidateStrategyPeerAckThenPing)...)
	all = append(all, candidateSuccessfulAttempts(candidateStrategyInterleaved)...)
	if got := selectCandidateStrategy(all); got != candidateStrategyPeerAckOnly {
		t.Fatalf("selected strategy=%s want=%s", got, candidateStrategyPeerAckOnly)
	}
	all[0].Result = candidateResultProtocol
	if got := selectCandidateStrategy(all); got != candidateStrategyPeerAckThenPing {
		t.Fatalf("selected strategy after A failure=%s want=%s", got, candidateStrategyPeerAckThenPing)
	}
	for i := range all {
		if all[i].Strategy == candidateStrategyPeerAckThenPing {
			all[i].NearTimeout = true
		}
	}
	if got := selectCandidateStrategy(all); got != candidateStrategyInterleaved {
		t.Fatalf("selected strategy after B near timeout=%s want=%s", got, candidateStrategyInterleaved)
	}
}

func candidateSuccessfulAttempts(strategy candidateStrategy) []candidateStartupObservation {
	attempts := make([]candidateStartupObservation, 0, candidateStartupRounds)
	for round := 1; round <= candidateStartupRounds; round++ {
		attempts = append(attempts, candidateStartupObservation{
			Strategy:         strategy,
			Round:            round,
			Client00BodyLen:  30,
			Client00AckSent:  true,
			Stream06Sent:     true,
			Stream01Received: true,
			AckTo01:          time.Millisecond,
			Stream06To01:     time.Millisecond,
			CleanupBounded:   true,
			Result:           candidateResultSuccess,
		})
	}
	return attempts
}

func TestCandidateChanPumpWriteWhileReaderBlocked(t *testing.T) {
	server, peer := net.Pipe()
	pump := newCandidateChanPump(context.Background(), server, nil)
	defer pump.Close()
	result := make(chan error, 1)
	go func() {
		_, err := pump.submit(context.Background(), "unit_short", candidateShortFrame(0x06, candidateProofStreamID))
		result <- err
	}()
	got := make([]byte, 5)
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, candidateShortFrame(0x06, candidateProofStreamID)) {
		t.Fatal("writer command was not serialized while reader blocked")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
}

func TestCandidateChanPumpAcknowledgesPeerPingWhileWaiting(t *testing.T) {
	server, peer := net.Pipe()
	pump := newCandidateChanPump(context.Background(), server, nil)
	defer pump.Close()
	body := []byte{0x31, 0x32, 0x33}
	ack := make(chan error, 1)
	go func() {
		frame, _ := candidateSessionControlFrame(0x00, candidateSessionStreamID, body)
		if err := writeAll(peer, frame); err != nil {
			ack <- err
			return
		}
		want, _ := candidateSessionControlFrame(0x08, candidateSessionStreamID, body)
		got := make([]byte, len(want))
		_, err := io.ReadFull(peer, got)
		if err == nil && !bytes.Equal(got, want) {
			err = errors.New("peer ping acknowledgement was not exact")
		}
		ack <- err
	}()
	event, err := pump.next(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != candidatePumpPeerPingAck || event.AckCompleted.IsZero() {
		t.Fatalf("event=%+v", event)
	}
	if err := <-ack; err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
}

func TestCandidateChanPumpCancellationAndTerminalRouting(t *testing.T) {
	server, peer := net.Pipe()
	pump := newCandidateChanPump(context.Background(), server, nil)
	closed := make(chan struct{})
	go func() {
		pump.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pump close did not release reader and writer")
	}
	_ = peer.Close()

	server, peer = net.Pipe()
	pump = newCandidateChanPump(context.Background(), server, nil)
	_ = peer.Close()
	select {
	case <-pump.Done():
	case <-time.After(time.Second):
		t.Fatal("terminal read failure did not stop pump")
	}
	if pump.TerminalReports() != 1 {
		t.Fatalf("terminal reports=%d want=1", pump.TerminalReports())
	}
	if pump.Err() == nil {
		t.Fatal("terminal read failure was not routed")
	}
	pump.Close()
}

func TestCandidateChanPumpSoleWriter(t *testing.T) {
	server, peer := net.Pipe()
	tracked := &candidateWriteTrackingConn{Conn: server}
	pump := newCandidateChanPump(context.Background(), tracked, nil)
	defer pump.Close()
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := pump.submit(context.Background(), "unit_short", candidateShortFrame(0x06, candidateProofStreamID))
			results <- err
		}()
	}
	got := make([]byte, 10)
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if tracked.MaxConcurrentWrites() != 1 {
		t.Fatalf("max concurrent writes=%d want=1", tracked.MaxConcurrentWrites())
	}
	_ = peer.Close()
}

type candidateWriteTrackingConn struct {
	net.Conn
	mu     sync.Mutex
	active int
	max    int
}

func (c *candidateWriteTrackingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.active++
	if c.active > c.max {
		c.max = c.active
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
	}()
	return c.Conn.Write(p)
}

func (c *candidateWriteTrackingConn) MaxConcurrentWrites() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}

var osErrTimeout = errors.New("candidate read timeout")
