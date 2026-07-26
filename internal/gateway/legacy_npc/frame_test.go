package legacy_npc

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestFrameGoldenLayoutsAndFlags(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		want  []byte
	}{
		{
			name:  "ping content",
			frame: Frame{Flag: FrameFlagPing, StreamID: -1, Content: []byte("p")},
			want:  []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 'p'},
		},
		{
			name:  "stream accepted control",
			frame: Frame{Flag: FrameFlagStreamAccepted, StreamID: 1},
			want:  []byte{0x01, 0x01, 0x00, 0x00, 0x00},
		},
		{
			name:  "stream rejected control",
			frame: Frame{Flag: FrameFlagStreamRejected, StreamID: 2},
			want:  []byte{0x02, 0x02, 0x00, 0x00, 0x00},
		},
		{
			name:  "final data content",
			frame: Frame{Flag: FrameFlagDataFinal, StreamID: 0x12345678, Content: []byte("ok")},
			want:  []byte{0x03, 0x78, 0x56, 0x34, 0x12, 0x02, 0x00, 'o', 'k'},
		},
		{
			name:  "continuation data content",
			frame: Frame{Flag: FrameFlagDataContinue, StreamID: 4, Content: []byte("c")},
			want:  []byte{0x04, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 'c'},
		},
		{
			name:  "window",
			frame: Frame{Flag: FrameFlagWindow, StreamID: 5, WindowState: 0x0102030405060708},
			want:  []byte{0x05, 0x05, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
		},
		{
			name:  "stream open control",
			frame: Frame{Flag: FrameFlagStreamOpen, StreamID: 6},
			want:  []byte{0x06, 0x06, 0x00, 0x00, 0x00},
		},
		{
			name:  "stream close control",
			frame: Frame{Flag: FrameFlagStreamClose, StreamID: 7},
			want:  []byte{0x07, 0x07, 0x00, 0x00, 0x00},
		},
		{
			name:  "ping response content",
			frame: Frame{Flag: FrameFlagPingResponse, StreamID: -1, Content: []byte("r")},
			want:  []byte{0x08, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 'r'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := WriteFrame(&encoded, tt.frame); err != nil {
				t.Fatalf("WriteFrame() error = %v", err)
			}
			if !bytes.Equal(encoded.Bytes(), tt.want) {
				t.Fatalf("encoded = %x, want %x", encoded.Bytes(), tt.want)
			}
			got, err := ReadFrame(bytes.NewReader(tt.want))
			if err != nil {
				t.Fatalf("ReadFrame() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.frame) {
				t.Fatalf("ReadFrame() = %#v, want %#v", got, tt.frame)
			}
		})
	}
}

func TestFrameContentLengthBounds(t *testing.T) {
	for _, content := range [][]byte{nil, bytes.Repeat([]byte{'x'}, legacyProtocolMaxContentBytes)} {
		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, Frame{Flag: FrameFlagDataFinal, StreamID: 1, Content: content}); err != nil {
			t.Fatalf("WriteFrame(len=%d) error = %v", len(content), err)
		}
		got, err := ReadFrame(&encoded)
		if err != nil {
			t.Fatalf("ReadFrame(len=%d) error = %v", len(content), err)
		}
		if !bytes.Equal(got.Content, content) {
			t.Fatalf("ReadFrame content length = %d, want %d", len(got.Content), len(content))
		}
	}

	overflow := bytes.Repeat([]byte{'x'}, legacyProtocolMaxContentBytes+1)
	if err := WriteFrame(io.Discard, Frame{Flag: FrameFlagDataFinal, StreamID: 1, Content: overflow}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame(overflow) error = %v, want ErrFrameTooLarge", err)
	}
	encodedOverflow := append([]byte{0x03, 0x01, 0x00, 0x00, 0x00, 0xf6, 0x0f}, overflow...)
	if _, err := ReadFrame(bytes.NewReader(encodedOverflow)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame(overflow) error = %v, want ErrFrameTooLarge", err)
	}
}

func TestFrameRejectsInvalidFlagSpecificFields(t *testing.T) {
	tests := []Frame{
		{Flag: FrameFlagPing, StreamID: 1},
		{Flag: FrameFlagPingResponse, StreamID: 0},
		{Flag: FrameFlagDataFinal, StreamID: -1},
		{Flag: FrameFlagWindow, StreamID: -1},
		{Flag: FrameFlagWindow, StreamID: 1, Content: []byte("unexpected")},
		{Flag: FrameFlagStreamOpen, StreamID: 0},
		{Flag: FrameFlagStreamClose, StreamID: 1, Content: []byte("unexpected")},
		{Flag: FrameFlag(0x09), StreamID: 1},
	}
	for _, frame := range tests {
		if err := WriteFrame(io.Discard, frame); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("WriteFrame(%#v) error = %v, want ErrInvalidFrame", frame, err)
		}
	}

	for _, wire := range [][]byte{
		{0x09, 0x01, 0x00, 0x00, 0x00},
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x05, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	} {
		if _, err := ReadFrame(bytes.NewReader(wire)); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("ReadFrame(%x) error = %v, want ErrInvalidFrame", wire, err)
		}
	}
}

func TestReadFrameHandlesFragmentedAndCoalescedFrames(t *testing.T) {
	first := []byte{0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 'a'}
	second := []byte{0x07, 0x01, 0x00, 0x00, 0x00}
	reader := &oneByteReader{payload: append(first, second...)}
	gotFirst, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame(first) error = %v", err)
	}
	gotSecond, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame(second) error = %v", err)
	}
	if gotFirst.Flag != FrameFlagDataFinal || string(gotFirst.Content) != "a" || gotSecond.Flag != FrameFlagStreamClose {
		t.Fatalf("frames = %#v, %#v", gotFirst, gotSecond)
	}
}

func TestReadFrameRejectsTruncatedWireData(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "common header", wire: []byte{0x03, 0x01, 0x00, 0x00}},
		{name: "content length", wire: []byte{0x03, 0x01, 0x00, 0x00, 0x00, 0x01}},
		{name: "content body", wire: []byte{0x03, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 'a'}},
		{name: "window body", wire: []byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tt.wire))
			if err == nil {
				t.Fatal("ReadFrame() succeeded for truncated wire data")
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("ReadFrame() error = %v, want EOF-style error", err)
			}
		})
	}
}

func TestWriteAllHandlesPartialWritesAndErrors(t *testing.T) {
	t.Run("one byte at a time", func(t *testing.T) {
		writer := &limitedWriter{limit: 1}
		if err := writeAll(writer, []byte("abcdef")); err != nil {
			t.Fatalf("writeAll() error = %v", err)
		}
		if got := writer.buffer.String(); got != "abcdef" {
			t.Fatalf("written = %q, want abcdef", got)
		}
	})

	t.Run("multi step partial", func(t *testing.T) {
		writer := &limitedWriter{limit: 3}
		if err := writeAll(writer, []byte("abcdefg")); err != nil {
			t.Fatalf("writeAll() error = %v", err)
		}
		if got := writer.buffer.String(); got != "abcdefg" {
			t.Fatalf("written = %q, want abcdefg", got)
		}
	})

	t.Run("partial write followed by error", func(t *testing.T) {
		want := errors.New("writer failed")
		writer := &partialErrorWriter{err: want}
		if err := writeAll(writer, []byte("abcdef")); !errors.Is(err, want) {
			t.Fatalf("writeAll() error = %v, want %v", err, want)
		}
		if got := writer.buffer.String(); got != "ab" {
			t.Fatalf("written prefix = %q, want ab", got)
		}
	})

	t.Run("partial result with error", func(t *testing.T) {
		want := errors.New("writer failed")
		writer := &partialResultErrorWriter{err: want}
		if err := writeAll(writer, []byte("abcdef")); !errors.Is(err, want) {
			t.Fatalf("writeAll() error = %v, want %v", err, want)
		}
		if got := writer.buffer.String(); got != "ab" {
			t.Fatalf("written prefix = %q, want ab", got)
		}
	})

	t.Run("zero progress", func(t *testing.T) {
		if err := writeAll(zeroProgressWriter{}, []byte("a")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writeAll() error = %v, want io.ErrShortWrite", err)
		}
	})
}

type oneByteReader struct {
	payload []byte
}

func (r *oneByteReader) Read(dst []byte) (int, error) {
	if len(r.payload) == 0 {
		return 0, io.EOF
	}
	dst[0] = r.payload[0]
	r.payload = r.payload[1:]
	return 1, nil
}

type limitedWriter struct {
	limit  int
	buffer bytes.Buffer
}

func (w *limitedWriter) Write(payload []byte) (int, error) {
	n := w.limit
	if n > len(payload) {
		n = len(payload)
	}
	_, _ = w.buffer.Write(payload[:n])
	return n, nil
}

type partialErrorWriter struct {
	buffer bytes.Buffer
	err    error
	calls  int
}

func (w *partialErrorWriter) Write(payload []byte) (int, error) {
	w.calls++
	if w.calls > 1 {
		return 0, w.err
	}
	n := 2
	if n > len(payload) {
		n = len(payload)
	}
	_, _ = w.buffer.Write(payload[:n])
	return n, nil
}

type partialResultErrorWriter struct {
	buffer bytes.Buffer
	err    error
}

func (w *partialResultErrorWriter) Write(payload []byte) (int, error) {
	n := 2
	if n > len(payload) {
		n = len(payload)
	}
	_, _ = w.buffer.Write(payload[:n])
	return n, w.err
}

type zeroProgressWriter struct{}

func (zeroProgressWriter) Write([]byte) (int, error) {
	return 0, nil
}
