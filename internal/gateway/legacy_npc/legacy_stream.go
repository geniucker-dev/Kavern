package legacy_npc

import (
	"io"
	"sync"
)

type LegacyStream struct {
	mux *LegacyMux
	id  int32

	writeMu sync.Mutex

	state legacyStreamState
	open  *legacyPendingOpen
	// A live stream holds one tombstone reservation from creation until it is
	// either removed unsent or converted into a bounded tombstone.
	tombstoneReserved bool
	remoteEOF         bool
	readEOFObserved   bool
	localClosed       bool

	peerMax     uint32
	outstanding uint64

	recvBlocks   []legacyReceiveBlock
	recvBuffered uint64

	pendingConsumed  uint64
	inFlightConsumed uint64
	windowQueued     bool
	windowInFlight   bool

	dataQueue []Frame
	dataReady bool

	closePending  bool
	closeInFlight bool
	closeSent     bool
	noteLateData  bool
}

// legacyReceiveBlock is a fixed-size, Kavern-owned byte block. It deliberately
// does not retain wire-frame bodies, which prevents tiny frames from growing an
// unbounded number of slice headers while their total payload remains bounded.
type legacyReceiveBlock struct {
	data        []byte
	readOffset  int
	writeOffset int
}

func newLegacyStream(mux *LegacyMux, id int32) *LegacyStream {
	return &LegacyStream{mux: mux, id: id, peerMax: defaultLegacyMuxWindow, tombstoneReserved: true}
}

func (s *LegacyStream) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	mux := s.mux
	mux.mu.Lock()
	defer mux.mu.Unlock()
	for {
		if s.localClosed {
			return 0, ErrLegacyStreamClosed
		}
		if s.readEOFObserved {
			return 0, io.EOF
		}
		if mux.closed {
			return 0, mux.muxErrorLocked()
		}
		if s.state == legacyStreamTombstoned && s.remoteEOF {
			s.readEOFObserved = true
			return 0, io.EOF
		}
		if s.state == legacyStreamLocalClose || s.state == legacyStreamFullyClosed || s.state == legacyStreamTombstoned {
			return 0, ErrLegacyStreamClosed
		}
		if s.recvBuffered > 0 {
			n := s.readBlocksLocked(payload)
			if mux.bufferedBytes >= uint64(n) {
				mux.bufferedBytes -= uint64(n)
			} else {
				mux.bufferedBytes = 0
			}
			s.pendingConsumed += uint64(n)
			mux.ensureWindowDescriptorLocked(s)
			if s.state == legacyStreamRemoteClose && s.recvBuffered == 0 && s.closeSent {
				mux.removeStreamToTombstoneLocked(s)
			}
			mux.notifyLocked()
			return n, nil
		}
		if s.state == legacyStreamRemoteClose {
			if s.closeSent {
				mux.removeStreamToTombstoneLocked(s)
			}
			s.readEOFObserved = true
			return 0, io.EOF
		}
		mux.cond.Wait()
	}
}

func (s *LegacyStream) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	accepted := 0
	for accepted < len(payload) {
		segmentLength := len(payload) - accepted
		if segmentLength > legacyProtocolMaxContentBytes {
			segmentLength = legacyProtocolMaxContentBytes
		}
		final := accepted+segmentLength == len(payload)

		mux := s.mux
		mux.mu.Lock()
		for {
			if mux.closed {
				err := mux.muxErrorLocked()
				mux.mu.Unlock()
				return accepted, err
			}
			if s.state != legacyStreamOpen {
				mux.mu.Unlock()
				return accepted, ErrLegacyStreamClosed
			}
			if uint64(segmentLength)+s.outstanding <= uint64(s.peerMax) && mux.dataAdmissionAvailableLocked() {
				body := append([]byte(nil), payload[accepted:accepted+segmentLength]...)
				flag := FrameFlagDataContinue
				if final {
					flag = FrameFlagDataFinal
				}
				s.outstanding += uint64(segmentLength)
				s.dataQueue = append(s.dataQueue, Frame{Flag: flag, StreamID: s.id, Content: body})
				if !s.dataReady {
					s.dataReady = true
					mux.dataReady = append(mux.dataReady, s.id)
				}
				mux.dataCount++
				mux.totalCount++
				mux.notifyLocked()
				mux.mu.Unlock()
				accepted += segmentLength
				break
			}
			mux.cond.Wait()
		}
	}
	return accepted, nil
}

func (s *LegacyStream) Close() error {
	mux := s.mux
	mux.mu.Lock()
	if s.localClosed || s.state == legacyStreamLocalClose {
		mux.mu.Unlock()
		return nil
	}
	if s.state == legacyStreamFullyClosed || s.state == legacyStreamTombstoned {
		// Wire cleanup is complete or owned by mux shutdown. Only establish
		// caller-visible local close; leave wire state and accounting unchanged.
		s.localClosed = true
		mux.cond.Broadcast()
		mux.notifyLocked()
		mux.mu.Unlock()
		return nil
	}
	s.localClosed = true
	s.state = legacyStreamLocalClose
	released := s.discardReceiveLocked()
	if mux.bufferedBytes >= released {
		mux.bufferedBytes -= released
	} else {
		mux.bufferedBytes = 0
	}
	s.pendingConsumed = 0
	s.remoteEOF = false
	mux.cancelQueuedWindowLocked(s)
	mux.cond.Broadcast()
	mux.notifyLocked()
	mux.mu.Unlock()

	s.writeMu.Lock()
	s.writeMu.Unlock()

	mux.mu.Lock()
	if mux.closed || s.state == legacyStreamFullyClosed || mux.streams == nil || mux.streams[s.id] != s {
		mux.mu.Unlock()
		return nil
	}
	if s.closeSent {
		mux.removeStreamToTombstoneLocked(s)
	} else {
		s.closePending = true
	}
	mux.notifyLocked()
	mux.mu.Unlock()
	return nil
}

func (s *LegacyStream) readBlocksLocked(payload []byte) int {
	read := 0
	for read < len(payload) && len(s.recvBlocks) > 0 {
		block := &s.recvBlocks[0]
		if block.readOffset >= block.writeOffset {
			s.popReceiveBlockLocked()
			continue
		}
		n := copy(payload[read:], block.data[block.readOffset:block.writeOffset])
		read += n
		block.readOffset += n
		s.recvBuffered -= uint64(n)
		if block.readOffset == block.writeOffset {
			s.popReceiveBlockLocked()
		}
	}
	return read
}

func (s *LegacyStream) appendReceiveLocked(content []byte) {
	for len(content) > 0 {
		if len(s.recvBlocks) == 0 || s.recvBlocks[len(s.recvBlocks)-1].writeOffset == legacyProtocolMaxContentBytes {
			s.recvBlocks = append(s.recvBlocks, legacyReceiveBlock{data: make([]byte, legacyProtocolMaxContentBytes)})
		}
		tail := &s.recvBlocks[len(s.recvBlocks)-1]
		available := len(tail.data) - tail.writeOffset
		n := len(content)
		if n > available {
			n = available
		}
		copy(tail.data[tail.writeOffset:tail.writeOffset+n], content[:n])
		tail.writeOffset += n
		content = content[n:]
	}
}

func (s *LegacyStream) popReceiveBlockLocked() {
	if len(s.recvBlocks) == 0 {
		return
	}
	s.recvBlocks[0] = legacyReceiveBlock{}
	s.recvBlocks = s.recvBlocks[1:]
	if len(s.recvBlocks) == 0 {
		s.recvBlocks = nil
	}
}

func (s *LegacyStream) discardReceiveLocked() uint64 {
	released := s.recvBuffered
	for index := range s.recvBlocks {
		s.recvBlocks[index] = legacyReceiveBlock{}
	}
	s.recvBlocks = nil
	s.recvBuffered = 0
	return released
}

func (m *LegacyMux) clearStreamDataQueueLocked(stream *LegacyStream) {
	if stream == nil {
		return
	}
	queued := len(stream.dataQueue)
	for index := range stream.dataQueue {
		stream.dataQueue[index] = Frame{}
	}
	stream.dataQueue = nil
	stream.dataReady = false
	if queued > 0 {
		if m.dataCount >= queued {
			m.dataCount -= queued
		} else {
			m.dataCount = 0
		}
		if m.totalCount >= queued {
			m.totalCount -= queued
		} else {
			m.totalCount = 0
		}
	}
}

func (m *LegacyMux) ensureWindowDescriptorLocked(stream *LegacyStream) {
	if stream.pendingConsumed == 0 || stream.windowQueued || stream.windowInFlight || stream.state != legacyStreamOpen {
		return
	}
	// At most one descriptor exists per active stream, so MaxStreams reserves
	// enough window-control slots under validated configuration.
	stream.windowQueued = true
	m.windowQueue = append(m.windowQueue, stream)
	m.windowCount++
	m.totalCount++
}

func (m *LegacyMux) cancelQueuedWindowLocked(stream *LegacyStream) {
	if stream == nil || !stream.windowQueued {
		return
	}
	stream.windowQueued = false
	if m.windowCount > 0 {
		m.windowCount--
	}
	if m.totalCount > 0 {
		m.totalCount--
	}
}
