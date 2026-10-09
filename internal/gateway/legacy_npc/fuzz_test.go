package legacy_npc

import (
	"bytes"
	"testing"
)

func FuzzLegacyFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Add([]byte{3, 1, 0, 0, 0, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		frame, err := ReadFrame(bytes.NewReader(b))
		if err == nil {
			var out bytes.Buffer
			if err := WriteFrame(&out, frame); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadFrame(&out); err != nil {
				t.Fatal(err)
			}
		}
	})
}
