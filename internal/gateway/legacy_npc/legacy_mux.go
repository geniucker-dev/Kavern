package legacy_npc

import (
	"context"
	"io"
	"math"
	"net"
	"sync"
	"time"
)

const (
	defaultLegacyMuxMaxStreams    = 64
	defaultLegacyMuxWindow        = uint32(122550)
	defaultLegacyMuxQueueFrames   = 2048
	defaultLegacyMuxControlFrames = 160
	defaultLegacyMuxOpenTimeout   = 10 * time.Second
	defaultLegacyMuxPingInterval  = 5 * time.Second
	defaultLegacyMuxPingTimeout   = 15 * time.Second
	defaultLegacyMuxTombstoneTTL  = 30 * time.Second
	defaultLegacyMuxTombstones    = 1024
	legacyPeerMaxWindow           = uint32(1 << 27)
	legacyWindowDeltaMask         = uint64(0x7fffffff)
	legacyControlBurst            = 16
	legacyPingBurst               = 4
	legacyPingPongCapacity        = 16
)

type LegacyMuxConfig struct {
	MaxStreams              int
	FixedReceiveWindowBytes uint32
	HardReceiveBufferBytes  uint32
	MaxBufferedBytesTotal   uint64
	MaxQueuedFramesTotal    int
	MaxControlFrames        int
	OpenTimeout             time.Duration
	PingInterval            time.Duration
	PingTimeout             time.Duration
	TombstoneTTL            time.Duration
	MaxTombstones           int
}

type LegacyMux struct {
	conn net.Conn
	cfg  LegacyMuxConfig

	mu          sync.Mutex
	cond        *sync.Cond
	stateNotify chan struct{}
	closed      bool
	terminalErr error
	done        chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup

	streams    map[int32]*LegacyStream
	tombstones map[int32]*legacyTombstone
	// tombstoneReservations accounts for live streams that may need a
	// tombstone after an open is claimed or after an established stream closes.
	tombstoneReservations int
	nextID                int32

	pingQueue   []legacyOutbound
	openQueue   []legacyOutbound
	windowQueue []*LegacyStream
	dataReady   []int32
	closeReady  []legacyOutbound

	pingCount     int
	openCount     int
	windowCount   int
	dataCount     int
	totalCount    int
	bufferedBytes uint64

	pingStreak      int
	controlBurst    int
	nextControlOpen bool

	localPingQueued  string
	outstandingPings map[string]time.Time
	earlyPongs       map[string]struct{}
}

type legacyStreamState uint8

const (
	legacyStreamPendingOpen legacyStreamState = iota + 1
	legacyStreamOpen
	legacyStreamRemoteClose
	legacyStreamLocalClose
	legacyStreamFullyClosed
	legacyStreamTombstoned
)

type legacyOpenState uint8

const (
	legacyOpenWaiting legacyOpenState = iota + 1
	legacyOpenQueued
	legacyOpenWriterClaimed
	legacyOpenCanceled
	legacyOpenResolved
)

type legacyPendingOpen struct {
	stream         *LegacyStream
	ready          chan struct{}
	result         error
	state          legacyOpenState
	accepted       bool
	readyClosed    bool
	writeInFlight  bool
	writeCompleted bool
}

type legacyTombstone struct {
	expiresAt         time.Time
	openWriteInFlight bool
	cleanupPending    bool
	cleanupInFlight   bool
	cleanupSent       bool
	lateDataNoted     bool
}

type legacyOutboundKind uint8

const (
	legacyOutboundPing legacyOutboundKind = iota + 1
	legacyOutboundPingResponse
	legacyOutboundOpen
	legacyOutboundReject
	legacyOutboundWindow
	legacyOutboundData
	legacyOutboundClose
)

type legacyOutbound struct {
	kind   legacyOutboundKind
	frame  Frame
	stream *LegacyStream
	open   *legacyPendingOpen
	tombID int32
}

func NewLegacyMux(conn net.Conn, cfg LegacyMuxConfig) (*LegacyMux, error) {
	if conn == nil {
		return nil, ErrInvalidLegacyMuxConfig
	}
	cfg, err := normalizeLegacyMuxConfig(cfg)
	if err != nil {
		return nil, err
	}
	mux := &LegacyMux{
		conn:             conn,
		cfg:              cfg,
		stateNotify:      make(chan struct{}),
		done:             make(chan struct{}),
		streams:          make(map[int32]*LegacyStream),
		tombstones:       make(map[int32]*legacyTombstone),
		nextID:           1,
		nextControlOpen:  true,
		outstandingPings: make(map[string]time.Time),
		earlyPongs:       make(map[string]struct{}),
	}
	mux.cond = sync.NewCond(&mux.mu)
	mux.wg.Add(3)
	go mux.readerLoop()
	go mux.writerLoop()
	go mux.pingLoop()
	return mux, nil
}

func normalizeLegacyMuxConfig(cfg LegacyMuxConfig) (LegacyMuxConfig, error) {
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = defaultLegacyMuxMaxStreams
	}
	if cfg.FixedReceiveWindowBytes == 0 {
		cfg.FixedReceiveWindowBytes = defaultLegacyMuxWindow
	}
	if cfg.HardReceiveBufferBytes == 0 {
		if cfg.FixedReceiveWindowBytes > math.MaxUint32-legacyProtocolMaxContentBytes {
			return LegacyMuxConfig{}, ErrInvalidLegacyMuxConfig
		}
		cfg.HardReceiveBufferBytes = cfg.FixedReceiveWindowBytes + legacyProtocolMaxContentBytes
	}
	if cfg.MaxBufferedBytesTotal == 0 {
		cfg.MaxBufferedBytesTotal = uint64(defaultLegacyMuxMaxStreams) * uint64(defaultLegacyMuxWindow+legacyProtocolMaxContentBytes)
	}
	if cfg.MaxQueuedFramesTotal == 0 {
		cfg.MaxQueuedFramesTotal = defaultLegacyMuxQueueFrames
	}
	if cfg.MaxControlFrames == 0 {
		cfg.MaxControlFrames = defaultLegacyMuxControlFrames
	}
	if cfg.OpenTimeout == 0 {
		cfg.OpenTimeout = defaultLegacyMuxOpenTimeout
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = defaultLegacyMuxPingInterval
	}
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = defaultLegacyMuxPingTimeout
	}
	if cfg.TombstoneTTL == 0 {
		cfg.TombstoneTTL = defaultLegacyMuxTombstoneTTL
	}
	if cfg.MaxTombstones == 0 {
		cfg.MaxTombstones = defaultLegacyMuxTombstones
	}

	minimumControlFrames := int64(2)*int64(cfg.MaxStreams) + 24
	minimumHardReceiveBuffer := uint64(cfg.FixedReceiveWindowBytes) + uint64(legacyProtocolMaxContentBytes)
	controlClassFrames := int64(legacyPingPongCapacity) + int64(cfg.MaxStreams) + 8 + int64(cfg.MaxStreams)
	if cfg.MaxStreams <= 0 || cfg.MaxStreams > math.MaxInt32 ||
		cfg.FixedReceiveWindowBytes < defaultLegacyMuxWindow || cfg.FixedReceiveWindowBytes > legacyPeerMaxWindow ||
		uint64(cfg.HardReceiveBufferBytes) < minimumHardReceiveBuffer ||
		cfg.HardReceiveBufferBytes > legacyPeerMaxWindow+legacyProtocolMaxContentBytes ||
		cfg.MaxBufferedBytesTotal < uint64(cfg.HardReceiveBufferBytes) ||
		cfg.MaxQueuedFramesTotal <= cfg.MaxControlFrames || int64(cfg.MaxControlFrames) < minimumControlFrames ||
		cfg.OpenTimeout <= 0 || cfg.PingInterval <= 0 || cfg.PingTimeout < 2*cfg.PingInterval ||
		cfg.TombstoneTTL < cfg.OpenTimeout || cfg.MaxTombstones < cfg.MaxStreams {
		return LegacyMuxConfig{}, ErrInvalidLegacyMuxConfig
	}
	if controlClassFrames > int64(cfg.MaxControlFrames) {
		return LegacyMuxConfig{}, ErrInvalidLegacyMuxConfig
	}
	return cfg, nil
}

func (m *LegacyMux) Done() <-chan struct{} {
	return m.done
}

func (m *LegacyMux) Close() error {
	m.shutdown(ErrLegacyMuxClosed)
	m.wg.Wait()
	return nil
}

func (m *LegacyMux) OpenStream(ctx context.Context) (*LegacyStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	openCtx, cancel := context.WithTimeout(ctx, m.cfg.OpenTimeout)
	defer cancel()

	m.mu.Lock()
	m.purgeTombstonesLocked(time.Now())
	if m.closed {
		err := m.muxErrorLocked()
		m.mu.Unlock()
		return nil, err
	}
	if len(m.streams) >= m.cfg.MaxStreams {
		m.mu.Unlock()
		return nil, ErrLegacyStreamLimit
	}
	if len(m.tombstones)+m.tombstoneReservations >= m.cfg.MaxTombstones {
		m.mu.Unlock()
		return nil, ErrLegacyTombstoneLimit
	}
	if m.nextID <= 0 {
		m.mu.Unlock()
		return nil, ErrLegacyIDExhausted
	}
	id := m.nextID
	m.nextID++
	if _, exists := m.streams[id]; exists {
		m.mu.Unlock()
		return nil, ErrLegacyIDExhausted
	}
	stream := newLegacyStream(m, id)
	stream.state = legacyStreamPendingOpen
	stream.open = &legacyPendingOpen{stream: stream, ready: make(chan struct{}), state: legacyOpenWaiting}
	pending := stream.open
	m.streams[id] = stream
	m.tombstoneReservations++
	m.notifyLocked()
	m.mu.Unlock()

	for {
		m.mu.Lock()
		if opened, err, resolved := pendingOpenOutcomeLocked(pending); resolved {
			m.mu.Unlock()
			return opened, err
		}
		if m.closed {
			m.cancelPendingOpenLocked(pending, m.muxErrorLocked())
			err := m.muxErrorLocked()
			m.mu.Unlock()
			return nil, err
		}
		if pending.state == legacyOpenWaiting && m.openCapacityAvailableLocked() {
			pending.state = legacyOpenQueued
			m.openQueue = append(m.openQueue, legacyOutbound{kind: legacyOutboundOpen, frame: Frame{Flag: FrameFlagStreamOpen, StreamID: id}, stream: stream, open: pending})
			m.openCount++
			m.totalCount++
			m.notifyLocked()
		}
		notify := m.stateNotify
		m.mu.Unlock()

		select {
		case <-pending.ready:
		case <-notify:
		case <-openCtx.Done():
			m.mu.Lock()
			if opened, err, resolved := pendingOpenOutcomeLocked(pending); resolved {
				m.mu.Unlock()
				return opened, err
			}
			m.cancelPendingOpenLocked(pending, openCtx.Err())
			m.mu.Unlock()
			return nil, openCtx.Err()
		}
	}
}

func (m *LegacyMux) readerLoop() {
	defer m.wg.Done()
	for {
		frame, err := ReadFrame(m.conn)
		if err != nil {
			m.shutdown(err)
			return
		}
		if err := m.handleFrame(frame); err != nil {
			m.shutdown(err)
			return
		}
	}
}

func (m *LegacyMux) writerLoop() {
	defer m.wg.Done()
	var pending *legacyOutbound
	for {
		m.mu.Lock()
		for !m.closed && pending == nil {
			pending = m.nextOutboundLocked()
			if pending == nil {
				m.cond.Wait()
			}
		}
		if m.closed {
			m.mu.Unlock()
			return
		}
		item := *pending
		pending = nil
		if item.kind == legacyOutboundOpen && !m.openMayWriteLocked(item.open) {
			m.releaseOpenItemLocked(item.open)
			m.notifyLocked()
			m.mu.Unlock()
			continue
		}
		if item.kind == legacyOutboundOpen && item.open != nil {
			// A peer can acknowledge as soon as it receives the full raw frame, before
			// this goroutine reacquires the state mutex after WriteFrame returns.
			item.open.writeInFlight = true
		}
		m.mu.Unlock()

		err := m.writeFrameBounded(item.frame)
		if err != nil {
			m.shutdown(err)
			return
		}

		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return
		}
		if item.kind == legacyOutboundOpen {
			m.completeOpenWriteLocked(item.open)
		}
		pending = m.completeWrittenLocked(item)
		m.mu.Unlock()
	}
}

func (m *LegacyMux) completeOpenWriteLocked(pending *legacyPendingOpen) {
	if pending == nil {
		return
	}
	pending.writeInFlight = false
	pending.writeCompleted = true
	if tomb := m.tombstones[pending.stream.id]; tomb != nil && tomb.openWriteInFlight {
		tomb.openWriteInFlight = false
		tomb.expiresAt = time.Now().Add(m.cfg.TombstoneTTL)
	}
}

// writeFrameBounded applies one deadline to the full serialized frame. This
// keeps the writer's only blocking raw operation bounded even before ping
// liveness begins tracking a successfully sent ping.
func (m *LegacyMux) writeFrameBounded(frame Frame) error {
	if err := m.conn.SetWriteDeadline(time.Now().Add(m.cfg.PingTimeout)); err != nil {
		return err
	}
	if err := WriteFrame(m.conn, frame); err != nil {
		return err
	}
	return m.conn.SetWriteDeadline(time.Time{})
}

func (m *LegacyMux) pingLoop() {
	defer m.wg.Done()
	m.queueLocalPing()
	ticker := time.NewTicker(m.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case now := <-ticker.C:
			if m.pingExpired(now) {
				m.shutdown(ErrLegacyPingTimeout)
				return
			}
			m.mu.Lock()
			m.purgeTombstonesLocked(now)
			m.mu.Unlock()
			m.queueLocalPing()
		}
	}
}

func (m *LegacyMux) handleFrame(frame Frame) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return m.muxErrorLocked()
	}
	var err error
	switch frame.Flag {
	case FrameFlagPing:
		if !m.enqueuePingResponseLocked(frame.Content) {
			return ErrLegacyProtocol
		}
	case FrameFlagPingResponse:
		m.handlePongLocked(frame.Content)
	case FrameFlagStreamAccepted:
		err = m.handleAcceptedLocked(frame.StreamID)
	case FrameFlagStreamRejected:
		err = m.handleRejectedLocked(frame.StreamID)
	case FrameFlagStreamOpen:
		if !m.enqueuePeerRejectLocked(frame.StreamID) {
			return ErrLegacyProtocol
		}
	case FrameFlagDataFinal, FrameFlagDataContinue:
		err = m.handleDataLocked(frame)
	case FrameFlagWindow:
		err = m.handleWindowLocked(frame)
	case FrameFlagStreamClose:
		err = m.handleRemoteCloseLocked(frame.StreamID)
	default:
		return ErrLegacyProtocol
	}
	if err != nil {
		return err
	}
	m.notifyLocked()
	return nil
}

func (m *LegacyMux) handleAcceptedLocked(id int32) error {
	if stream, ok := m.streams[id]; ok && stream.open != nil {
		pending := stream.open
		if pending.writeInFlight || pending.writeCompleted {
			stream.state = legacyStreamOpen
			stream.open = nil
			resolvePendingOpenLocked(pending, legacyOpenResolved, nil, true)
			return nil
		}
	}
	if tomb, ok := m.tombstones[id]; ok {
		m.requestTombCleanupLocked(id, tomb)
		return nil
	}
	return ErrLegacyProtocol
}

func (m *LegacyMux) handleRejectedLocked(id int32) error {
	if stream, ok := m.streams[id]; ok && stream.open != nil {
		pending := stream.open
		if pending.writeInFlight || pending.writeCompleted {
			m.removeRejectedOpenLocked(pending)
			return nil
		}
	}
	if _, ok := m.tombstones[id]; ok {
		return nil
	}
	return ErrLegacyProtocol
}

func (m *LegacyMux) handleDataLocked(frame Frame) error {
	stream, ok := m.streams[frame.StreamID]
	if !ok {
		if tomb, exists := m.tombstones[frame.StreamID]; exists {
			m.noteLateDataLocked(tomb)
			return nil
		}
		return ErrLegacyProtocol
	}
	if stream.state == legacyStreamRemoteClose || stream.state == legacyStreamLocalClose || stream.state == legacyStreamFullyClosed {
		stream.noteLateData = true
		return nil
	}
	if stream.state != legacyStreamOpen {
		return ErrLegacyProtocol
	}
	if stream.recvBuffered+uint64(len(frame.Content)) > uint64(m.cfg.HardReceiveBufferBytes) || m.bufferedBytes+uint64(len(frame.Content)) > m.cfg.MaxBufferedBytesTotal {
		return ErrLegacyReceiveLimit
	}
	if len(frame.Content) > 0 {
		stream.appendReceiveLocked(frame.Content)
		stream.recvBuffered += uint64(len(frame.Content))
	}
	m.bufferedBytes += uint64(len(frame.Content))
	m.cond.Broadcast()
	return nil
}

func (m *LegacyMux) handleWindowLocked(frame Frame) error {
	stream, ok := m.streams[frame.StreamID]
	if !ok {
		if _, exists := m.tombstones[frame.StreamID]; exists {
			return nil
		}
		return ErrLegacyProtocol
	}
	if stream.state != legacyStreamOpen {
		return nil
	}
	state := frame.WindowState
	if state&(uint64(1)<<31) != 0 {
		return ErrLegacyProtocol
	}
	max := uint32((state >> 32) & legacyWindowDeltaMask)
	consumed := state & legacyWindowDeltaMask
	if max == 0 || max > legacyPeerMaxWindow || consumed > stream.outstanding {
		return ErrLegacyProtocol
	}
	stream.outstanding -= consumed
	stream.peerMax = max
	m.cond.Broadcast()
	return nil
}

func (m *LegacyMux) handleRemoteCloseLocked(id int32) error {
	stream, ok := m.streams[id]
	if !ok {
		// A close is idempotent even after a tombstone has expired. It carries
		// no payload and never allocates state for an unknown stream ID.
		return nil
	}
	if stream.state == legacyStreamRemoteClose || stream.state == legacyStreamLocalClose || stream.state == legacyStreamFullyClosed {
		return nil
	}
	if stream.state != legacyStreamOpen {
		return ErrLegacyProtocol
	}
	stream.state = legacyStreamRemoteClose
	stream.remoteEOF = true
	stream.closePending = true
	m.cond.Broadcast()
	return nil
}

func (m *LegacyMux) enqueuePingResponseLocked(body []byte) bool {
	if m.pingCount >= legacyPingPongCapacity || m.totalCount >= m.cfg.MaxQueuedFramesTotal || m.pingCount+m.openCount+m.windowCount >= m.cfg.MaxControlFrames {
		return false
	}
	copyBody := append([]byte(nil), body...)
	m.pingQueue = append(m.pingQueue, legacyOutbound{kind: legacyOutboundPingResponse, frame: Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: copyBody}})
	m.pingCount++
	m.totalCount++
	return true
}

func (m *LegacyMux) enqueuePeerRejectLocked(id int32) bool {
	if m.openCount >= m.cfg.MaxStreams+8 || m.totalCount >= m.cfg.MaxQueuedFramesTotal || m.pingCount+m.openCount+m.windowCount >= m.cfg.MaxControlFrames {
		return false
	}
	m.openQueue = append(m.openQueue, legacyOutbound{kind: legacyOutboundReject, frame: Frame{Flag: FrameFlagStreamRejected, StreamID: id}})
	m.openCount++
	m.totalCount++
	return true
}

func (m *LegacyMux) queueLocalPing() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.localPingQueued != "" || len(m.outstandingPings) >= int(m.cfg.PingTimeout/m.cfg.PingInterval) {
		return
	}
	// Preserve a ping/pong slot for a required peer-ping response.
	if m.pingCount >= legacyPingPongCapacity-1 || m.totalCount >= m.cfg.MaxQueuedFramesTotal || m.pingCount+m.openCount+m.windowCount >= m.cfg.MaxControlFrames {
		return
	}
	body := []byte(time.Now().UTC().Format(time.RFC3339Nano))
	key := string(body)
	m.localPingQueued = key
	m.pingQueue = append(m.pingQueue, legacyOutbound{kind: legacyOutboundPing, frame: Frame{Flag: FrameFlagPing, StreamID: -1, Content: body}})
	m.pingCount++
	m.totalCount++
	m.notifyLocked()
}

func (m *LegacyMux) pingExpired(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sentAt := range m.outstandingPings {
		if now.Sub(sentAt) >= m.cfg.PingTimeout {
			return true
		}
	}
	return false
}

func (m *LegacyMux) handlePongLocked(body []byte) {
	key := string(body)
	if _, ok := m.outstandingPings[key]; ok {
		delete(m.outstandingPings, key)
		return
	}
	if m.localPingQueued == key {
		m.earlyPongs[key] = struct{}{}
	}
}

func (m *LegacyMux) nextOutboundLocked() *legacyOutbound {
	if m.closed {
		return nil
	}
	if m.controlBurst < legacyControlBurst {
		if item := m.nextControlLocked(); item != nil {
			m.controlBurst++
			return item
		}
	}
	if item := m.nextDataLocked(); item != nil {
		m.controlBurst = 0
		return item
	}
	if item := m.nextControlLocked(); item != nil {
		m.controlBurst++
		return item
	}
	return nil
}

func (m *LegacyMux) nextControlLocked() *legacyOutbound {
	if len(m.pingQueue) > 0 && m.pingStreak < legacyPingBurst {
		item := m.pingQueue[0]
		m.pingQueue[0] = legacyOutbound{}
		m.pingQueue = m.pingQueue[1:]
		if len(m.pingQueue) == 0 {
			m.pingQueue = nil
		}
		m.pingStreak++
		return &item
	}
	if len(m.openQueue) > 0 || len(m.windowQueue) > 0 {
		if m.nextControlOpen && len(m.openQueue) > 0 || len(m.windowQueue) == 0 {
			item := m.openQueue[0]
			m.openQueue[0] = legacyOutbound{}
			m.openQueue = m.openQueue[1:]
			if len(m.openQueue) == 0 {
				m.openQueue = nil
			}
			m.nextControlOpen = false
			m.pingStreak = 0
			if item.kind == legacyOutboundOpen && item.open != nil && item.open.state == legacyOpenQueued {
				item.open.state = legacyOpenWriterClaimed
			}
			return &item
		}
		for len(m.windowQueue) > 0 {
			stream := m.windowQueue[0]
			m.windowQueue[0] = nil
			m.windowQueue = m.windowQueue[1:]
			if len(m.windowQueue) == 0 {
				m.windowQueue = nil
			}
			m.nextControlOpen = true
			m.pingStreak = 0
			if !stream.windowQueued || stream.windowInFlight {
				continue
			}
			amount := stream.pendingConsumed
			if amount > legacyWindowDeltaMask {
				amount = legacyWindowDeltaMask
			}
			stream.pendingConsumed -= amount
			stream.inFlightConsumed = amount
			stream.windowQueued = false
			stream.windowInFlight = true
			item := legacyOutbound{kind: legacyOutboundWindow, frame: Frame{Flag: FrameFlagWindow, StreamID: stream.id, WindowState: packWindowState(stream.mux.cfg.FixedReceiveWindowBytes, amount)}, stream: stream}
			return &item
		}
	}
	if len(m.pingQueue) > 0 {
		item := m.pingQueue[0]
		m.pingQueue[0] = legacyOutbound{}
		m.pingQueue = m.pingQueue[1:]
		if len(m.pingQueue) == 0 {
			m.pingQueue = nil
		}
		m.pingStreak++
		return &item
	}
	return nil
}

func (m *LegacyMux) nextDataLocked() *legacyOutbound {
	m.materializeOneCloseLocked()
	if len(m.closeReady) > 0 {
		item := m.closeReady[0]
		m.closeReady[0] = legacyOutbound{}
		m.closeReady = m.closeReady[1:]
		if len(m.closeReady) == 0 {
			m.closeReady = nil
		}
		return &item
	}
	for len(m.dataReady) > 0 {
		id := m.dataReady[0]
		m.dataReady[0] = 0
		m.dataReady = m.dataReady[1:]
		if len(m.dataReady) == 0 {
			m.dataReady = nil
		}
		stream, ok := m.streams[id]
		if !ok || len(stream.dataQueue) == 0 {
			continue
		}
		frame := stream.dataQueue[0]
		stream.dataQueue[0] = Frame{}
		stream.dataQueue = stream.dataQueue[1:]
		if len(stream.dataQueue) > 0 {
			m.dataReady = append(m.dataReady, id)
		} else {
			stream.dataQueue = nil
			stream.dataReady = false
		}
		return &legacyOutbound{kind: legacyOutboundData, frame: frame, stream: stream}
	}
	return nil
}

func (m *LegacyMux) completeWrittenLocked(item legacyOutbound) *legacyOutbound {
	switch item.kind {
	case legacyOutboundPing:
		m.pingCount--
		m.totalCount--
		key := string(item.frame.Content)
		if m.localPingQueued == key {
			m.localPingQueued = ""
			if _, early := m.earlyPongs[key]; early {
				delete(m.earlyPongs, key)
			} else {
				m.outstandingPings[key] = time.Now()
			}
		}
	case legacyOutboundPingResponse:
		m.pingCount--
		m.totalCount--
	case legacyOutboundOpen, legacyOutboundReject:
		m.openCount--
		m.totalCount--
	case legacyOutboundWindow:
		stream := item.stream
		stream.windowInFlight = false
		stream.inFlightConsumed = 0
		if stream.pendingConsumed > 0 && stream.state == legacyStreamOpen {
			stream.windowQueued = true
			m.windowQueue = append(m.windowQueue, stream)
		} else {
			m.windowCount--
			m.totalCount--
		}
	case legacyOutboundData:
		m.dataCount--
		m.totalCount--
	case legacyOutboundClose:
		m.dataCount--
		m.totalCount--
		m.finishCloseLocked(item)
	}
	// Reserve one close before capacity waiters are notified. This is the
	// close barrier: later data cannot take the slot released by prior data.
	m.materializeOneCloseLocked()
	m.notifyLocked()
	return nil
}

func (m *LegacyMux) materializeOneCloseLocked() bool {
	if m.dataCount >= m.dataCapacityLocked() {
		return false
	}
	for _, stream := range m.streams {
		if stream.closePending && !stream.closeSent && !stream.closeInFlight && len(stream.dataQueue) == 0 {
			m.materializeCloseForStreamLocked(stream)
			return true
		}
	}
	for id, tomb := range m.tombstones {
		if tomb.cleanupPending && !tomb.cleanupInFlight && !tomb.cleanupSent {
			tomb.cleanupPending = false
			tomb.cleanupInFlight = true
			m.dataCount++
			m.totalCount++
			m.closeReady = append(m.closeReady, legacyOutbound{kind: legacyOutboundClose, frame: Frame{Flag: FrameFlagStreamClose, StreamID: id}, tombID: id})
			return true
		}
	}
	return false
}

func (m *LegacyMux) materializeCloseForStreamLocked(stream *LegacyStream) {
	stream.closeInFlight = true
	m.dataCount++
	m.totalCount++
	m.closeReady = append(m.closeReady, legacyOutbound{kind: legacyOutboundClose, frame: Frame{Flag: FrameFlagStreamClose, StreamID: stream.id}, stream: stream})
}

func (m *LegacyMux) finishCloseLocked(item legacyOutbound) {
	if item.stream == nil {
		m.finishTombstoneCleanupLocked(item.tombID)
		return
	}
	stream := item.stream
	stream.closeInFlight = false
	stream.closeSent = true
	if stream.state == legacyStreamLocalClose || (stream.state == legacyStreamRemoteClose && stream.recvBuffered == 0) {
		m.removeStreamToTombstoneLocked(stream)
	}
}

func (m *LegacyMux) finishTombstoneCleanupLocked(id int32) {
	tomb := m.tombstones[id]
	if tomb == nil {
		return
	}
	tomb.cleanupInFlight = false
	tomb.cleanupSent = true
	tomb.expiresAt = time.Now().Add(m.cfg.TombstoneTTL)
}

func (m *LegacyMux) openMayWriteLocked(pending *legacyPendingOpen) bool {
	return pending != nil && pending.state == legacyOpenWriterClaimed && !m.closed
}

func (m *LegacyMux) releaseOpenItemLocked(pending *legacyPendingOpen) {
	if m.openCount > 0 {
		m.openCount--
		m.totalCount--
	}
	if pending != nil && pending.state == legacyOpenWriterClaimed {
		pending.state = legacyOpenCanceled
	}
}

func (m *LegacyMux) openCapacityAvailableLocked() bool {
	return m.openCount < m.cfg.MaxStreams+8 && m.pingCount+m.openCount+m.windowCount < m.cfg.MaxControlFrames && m.totalCount < m.cfg.MaxQueuedFramesTotal
}

func (m *LegacyMux) dataCapacityLocked() int {
	return m.cfg.MaxQueuedFramesTotal - m.cfg.MaxControlFrames
}

func (m *LegacyMux) dataAdmissionAvailableLocked() bool {
	return m.dataCount < m.dataCapacityLocked() && !m.hasMaterializableCloseLocked()
}

func (m *LegacyMux) hasMaterializableCloseLocked() bool {
	if len(m.closeReady) > 0 {
		return true
	}
	if m.dataCount >= m.dataCapacityLocked() {
		return false
	}
	for _, stream := range m.streams {
		if stream.closePending && !stream.closeSent && !stream.closeInFlight && len(stream.dataQueue) == 0 {
			return true
		}
	}
	for _, tomb := range m.tombstones {
		if tomb.cleanupPending && !tomb.cleanupInFlight && !tomb.cleanupSent {
			return true
		}
	}
	return false
}

func (m *LegacyMux) cancelPendingOpenLocked(pending *legacyPendingOpen, err error) {
	if pending == nil || pending.result != nil || pending.state == legacyOpenResolved {
		return
	}
	switch pending.state {
	case legacyOpenWaiting:
		m.removePendingOpenWithoutTombstoneLocked(pending, err)
	case legacyOpenQueued:
		for index := range m.openQueue {
			if m.openQueue[index].open == pending {
				copy(m.openQueue[index:], m.openQueue[index+1:])
				last := len(m.openQueue) - 1
				m.openQueue[last] = legacyOutbound{}
				m.openQueue = m.openQueue[:last]
				if len(m.openQueue) == 0 {
					m.openQueue = nil
				}
				m.openCount--
				m.totalCount--
				break
			}
		}
		m.removePendingOpenWithoutTombstoneLocked(pending, err)
	case legacyOpenWriterClaimed:
		resolvePendingOpenLocked(pending, legacyOpenCanceled, err, false)
		m.removeStreamToTombstoneLocked(pending.stream)
	}
	m.notifyLocked()
}

func (m *LegacyMux) removePendingOpenWithoutTombstoneLocked(pending *legacyPendingOpen, err error) {
	delete(m.streams, pending.stream.id)
	pending.stream.state = legacyStreamFullyClosed
	pending.stream.open = nil
	m.releaseTombstoneReservationLocked(pending.stream)
	resolvePendingOpenLocked(pending, legacyOpenCanceled, err, false)
}

func (m *LegacyMux) removeRejectedOpenLocked(pending *legacyPendingOpen) {
	stream := pending.stream
	delete(m.streams, stream.id)
	stream.state = legacyStreamFullyClosed
	stream.open = nil
	m.releaseTombstoneReservationLocked(stream)
	resolvePendingOpenLocked(pending, legacyOpenResolved, ErrLegacyStreamRejected, false)
}

func pendingOpenOutcomeLocked(pending *legacyPendingOpen) (*LegacyStream, error, bool) {
	if pending == nil {
		return nil, ErrLegacyMuxClosed, true
	}
	if pending.result != nil {
		return nil, pending.result, true
	}
	if pending.accepted {
		return pending.stream, nil, true
	}
	return nil, nil, false
}

func resolvePendingOpenLocked(pending *legacyPendingOpen, state legacyOpenState, err error, accepted bool) {
	if pending == nil || pending.readyClosed {
		return
	}
	pending.state = state
	pending.result = err
	pending.accepted = accepted
	pending.readyClosed = true
	close(pending.ready)
}

func (m *LegacyMux) removeStreamToTombstoneLocked(stream *LegacyStream) {
	if stream == nil {
		return
	}
	if _, exists := m.streams[stream.id]; !exists {
		return
	}
	delete(m.streams, stream.id)
	stream.state = legacyStreamTombstoned
	buffered := stream.discardReceiveLocked()
	stream.pendingConsumed = 0
	m.cancelQueuedWindowLocked(stream)
	stream.inFlightConsumed = 0
	stream.windowInFlight = false
	m.clearStreamDataQueueLocked(stream)
	if m.bufferedBytes >= buffered {
		m.bufferedBytes -= buffered
	} else {
		m.bufferedBytes = 0
	}
	m.releaseTombstoneReservationLocked(stream)
	// A successfully transmitted close is the lifecycle's one cleanup close.
	// A canceled pending open has no closeSent marker, so it retains permission
	// to send one cleanup close if a late acceptance arrives.
	openWriteInFlight := stream.open != nil && stream.open.writeInFlight
	m.tombstones[stream.id] = &legacyTombstone{
		expiresAt:         time.Now().Add(m.cfg.TombstoneTTL),
		openWriteInFlight: openWriteInFlight,
		cleanupSent:       stream.closeSent,
	}
	m.purgeTombstonesLocked(time.Now())
}

func (m *LegacyMux) releaseTombstoneReservationLocked(stream *LegacyStream) {
	if stream != nil && stream.tombstoneReserved {
		stream.tombstoneReserved = false
		if m.tombstoneReservations > 0 {
			m.tombstoneReservations--
		}
	}
}

func (m *LegacyMux) requestTombCleanupLocked(id int32, tomb *legacyTombstone) {
	if tomb != nil && !tomb.cleanupPending && !tomb.cleanupInFlight && !tomb.cleanupSent {
		tomb.cleanupPending = true
	}
}

func (m *LegacyMux) noteLateDataLocked(tomb *legacyTombstone) {
	if tomb != nil {
		tomb.lateDataNoted = true
		if !tomb.cleanupPending && !tomb.cleanupInFlight && !tomb.cleanupSent {
			tomb.cleanupPending = true
		}
	}
}

func (m *LegacyMux) purgeTombstonesLocked(now time.Time) {
	for id, tomb := range m.tombstones {
		if !tomb.openWriteInFlight && !tomb.cleanupPending && !tomb.cleanupInFlight && now.After(tomb.expiresAt) {
			delete(m.tombstones, id)
		}
	}
}

func (m *LegacyMux) notifyLocked() {
	if !m.closed {
		close(m.stateNotify)
		m.stateNotify = make(chan struct{})
	}
	m.cond.Broadcast()
}

func (m *LegacyMux) muxErrorLocked() error {
	if m.terminalErr != nil {
		return m.terminalErr
	}
	return ErrLegacyMuxClosed
}

func (m *LegacyMux) shutdown(err error) {
	if err == nil {
		err = ErrLegacyMuxClosed
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.terminalErr = err
		for _, stream := range m.streams {
			if stream.open != nil {
				resolvePendingOpenLocked(stream.open, legacyOpenCanceled, err, false)
				stream.open = nil
			}
			stream.state = legacyStreamFullyClosed
			stream.discardReceiveLocked()
			m.clearStreamDataQueueLocked(stream)
			stream.tombstoneReserved = false
			stream.remoteEOF = false
			stream.peerMax = 0
			stream.outstanding = 0
			stream.pendingConsumed = 0
			stream.inFlightConsumed = 0
			stream.windowQueued = false
			stream.windowInFlight = false
			stream.closePending = false
			stream.closeInFlight = false
			stream.closeSent = false
			stream.noteLateData = false
		}
		m.pingQueue = nil
		m.openQueue = nil
		m.windowQueue = nil
		m.dataReady = nil
		m.closeReady = nil
		m.outstandingPings = nil
		m.earlyPongs = nil
		m.localPingQueued = ""
		m.streams = nil
		m.tombstones = nil
		m.tombstoneReservations = 0
		m.bufferedBytes = 0
		m.pingCount = 0
		m.openCount = 0
		m.windowCount = 0
		m.dataCount = 0
		m.totalCount = 0
		m.pingStreak = 0
		m.controlBurst = 0
		close(m.done)
		close(m.stateNotify)
		m.cond.Broadcast()
		m.mu.Unlock()
		_ = m.conn.Close()
	})
}

func packWindowState(max uint32, consumed uint64) uint64 {
	return uint64(max)<<32 | consumed
}

var _ io.Closer = (*LegacyMux)(nil)
