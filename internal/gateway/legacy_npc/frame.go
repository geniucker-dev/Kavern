package legacy_npc

import (
	"encoding/binary"
	"errors"
	"io"
)

const legacyProtocolMaxContentBytes = 4085

var (
	ErrInvalidFrame  = errors.New("invalid legacy npc frame")
	ErrFrameTooLarge = errors.New("legacy npc frame content exceeds protocol maximum")
)

type FrameFlag byte

const (
	FrameFlagPing           FrameFlag = 0x00
	FrameFlagStreamAccepted FrameFlag = 0x01
	FrameFlagStreamRejected FrameFlag = 0x02
	FrameFlagDataFinal      FrameFlag = 0x03
	FrameFlagDataContinue   FrameFlag = 0x04
	FrameFlagWindow         FrameFlag = 0x05
	FrameFlagStreamOpen     FrameFlag = 0x06
	FrameFlagStreamClose    FrameFlag = 0x07
	FrameFlagPingResponse   FrameFlag = 0x08
)

// Frame is one legacy npc mux wire frame. Mux lifecycle behavior is deliberately
// outside this codec.
type Frame struct {
	Flag        FrameFlag
	StreamID    int32
	Content     []byte
	WindowState uint64
}

func ReadFrame(r io.Reader) (Frame, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}

	frame := Frame{
		Flag:     FrameFlag(header[0]),
		StreamID: int32(binary.LittleEndian.Uint32(header[1:])),
	}
	switch frameLayout(frame.Flag) {
	case frameLayoutContent:
		var lengthBytes [2]byte
		if _, err := io.ReadFull(r, lengthBytes[:]); err != nil {
			return Frame{}, err
		}
		length := int(binary.LittleEndian.Uint16(lengthBytes[:]))
		if length > legacyProtocolMaxContentBytes {
			return Frame{}, ErrFrameTooLarge
		}
		if length > 0 {
			frame.Content = make([]byte, length)
			if _, err := io.ReadFull(r, frame.Content); err != nil {
				return Frame{}, err
			}
		}
	case frameLayoutWindow:
		var windowBytes [8]byte
		if _, err := io.ReadFull(r, windowBytes[:]); err != nil {
			return Frame{}, err
		}
		frame.WindowState = binary.LittleEndian.Uint64(windowBytes[:])
	case frameLayoutControl:
	default:
		return Frame{}, ErrInvalidFrame
	}
	if err := validateFrame(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func WriteFrame(w io.Writer, frame Frame) error {
	if err := validateFrame(frame); err != nil {
		return err
	}

	var header [5]byte
	header[0] = byte(frame.Flag)
	binary.LittleEndian.PutUint32(header[1:], uint32(frame.StreamID))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}

	switch frameLayout(frame.Flag) {
	case frameLayoutContent:
		var lengthBytes [2]byte
		binary.LittleEndian.PutUint16(lengthBytes[:], uint16(len(frame.Content)))
		if err := writeAll(w, lengthBytes[:]); err != nil {
			return err
		}
		return writeAll(w, frame.Content)
	case frameLayoutWindow:
		var windowBytes [8]byte
		binary.LittleEndian.PutUint64(windowBytes[:], frame.WindowState)
		return writeAll(w, windowBytes[:])
	case frameLayoutControl:
		return nil
	default:
		return ErrInvalidFrame
	}
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if n < 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

type legacyFrameLayout uint8

const (
	frameLayoutInvalid legacyFrameLayout = iota
	frameLayoutContent
	frameLayoutWindow
	frameLayoutControl
)

func frameLayout(flag FrameFlag) legacyFrameLayout {
	switch flag {
	case FrameFlagPing, FrameFlagDataFinal, FrameFlagDataContinue, FrameFlagPingResponse:
		return frameLayoutContent
	case FrameFlagWindow:
		return frameLayoutWindow
	case FrameFlagStreamAccepted, FrameFlagStreamRejected, FrameFlagStreamOpen, FrameFlagStreamClose:
		return frameLayoutControl
	default:
		return frameLayoutInvalid
	}
}

func validateFrame(frame Frame) error {
	switch frameLayout(frame.Flag) {
	case frameLayoutContent:
		if len(frame.Content) > legacyProtocolMaxContentBytes || frame.WindowState != 0 {
			if len(frame.Content) > legacyProtocolMaxContentBytes {
				return ErrFrameTooLarge
			}
			return ErrInvalidFrame
		}
		if frame.Flag == FrameFlagPing || frame.Flag == FrameFlagPingResponse {
			if frame.StreamID != -1 {
				return ErrInvalidFrame
			}
			return nil
		}
		if frame.StreamID <= 0 {
			return ErrInvalidFrame
		}
		return nil
	case frameLayoutWindow:
		if frame.StreamID <= 0 || len(frame.Content) != 0 {
			return ErrInvalidFrame
		}
		return nil
	case frameLayoutControl:
		if frame.StreamID <= 0 || len(frame.Content) != 0 || frame.WindowState != 0 {
			return ErrInvalidFrame
		}
		return nil
	default:
		return ErrInvalidFrame
	}
}
