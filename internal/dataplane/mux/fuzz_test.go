package mux

import (
	"bytes"
	"io"
	"testing"
)

func FuzzNativeRecords(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255})
	f.Add([]byte{0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		s := &framedStream{Stream: &recordMemory{Buffer: *bytes.NewBuffer(b)}}
		_, _ = io.Copy(io.Discard, s)
	})
}
