package config_test

import (
	"bytes"
	"github.com/geniucker-dev/kavern/internal/config"
	"testing"
)

func FuzzStrictJSON(f *testing.F) {
	f.Add([]byte(`{"device_id":"device"}`))
	f.Add([]byte(`{"device_id":"one","DEVICE_ID":"two"}`))
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > config.MaxJSONBytes+1 {
			return
		}
		var c config.Agent
		_ = config.DecodeJSON(bytes.NewReader(b), &c)
	})
}
