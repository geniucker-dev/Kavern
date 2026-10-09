package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type recordMemory struct{ bytes.Buffer }

func (s *recordMemory) Close() error { return nil }
func TestStreamRecordParserBoundsAndMissingEOF(t *testing.T) {
	for _, n := range []uint32{maxStreamRecord + 1, 0xffffffff} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], n)
		raw := &recordMemory{}
		raw.Write(prefix[:])
		s := &framedStream{Stream: raw}
		if _, err := s.Read(make([]byte, 1)); err == nil {
			t.Fatal("oversized record accepted")
		}
	}
	s := &framedStream{Stream: &recordMemory{}}
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("missing logical EOF=%v", err)
	}
}
func TestStreamRecordsRoundTripLargePayloadAndEOF(t *testing.T) {
	raw := &recordMemory{}
	writer := &framedStream{Stream: raw}
	payload := bytes.Repeat([]byte("record"), 50000)
	if n, err := writer.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write=%d %v", n, err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after EOF=%v", err)
	}
	reader := &framedStream{Stream: raw}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read=%d %v", len(got), err)
	}
}
