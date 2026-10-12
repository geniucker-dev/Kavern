package agent_v1

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSyncHandshakeStrictSchemaFramesAndBounds(t *testing.T) {
	start := authFrame("auth_start")
	start.DeviceID = "device-1"
	start.ClientNonce = mustNonce(t)
	challenge := authFrame("auth_challenge")
	challenge.DeviceID = start.DeviceID
	challenge.ServerNonce = mustNonce(t)
	challenge.ChallengeID = mustNonce(t)
	finish := authFrame("auth_finish")
	finish.DeviceID = start.DeviceID
	finish.ChallengeID = challenge.ChallengeID
	finish.Response = strings.Repeat("a", 64)
	accepted := authFrame("auth_ok")
	accepted.DeviceID = start.DeviceID
	accepted.SessionID = codecAuth(t).SessionID
	reject := authFrame("auth_reject")
	reject.Code = "upgrade_required"
	for _, frame := range []syncAuthFrame{start, challenge, finish, accepted, reject} {
		var wire bytes.Buffer
		if err := writeSyncAuth(&wire, frame); err != nil {
			t.Fatal(err)
		}
		if _, err := readSyncAuth(fragmentReader{bytes.NewReader(wire.Bytes())}); err != nil {
			t.Fatal("fragmented auth frame rejected", err)
		}
		for _, n := range []int{3, wire.Len() - 1} {
			if _, err := readSyncAuth(bytes.NewReader(wire.Bytes()[:n])); err == nil {
				t.Fatal("truncated auth frame accepted")
			}
		}
	}
	var wire bytes.Buffer
	_ = writeSyncAuth(&wire, start)
	payload := wire.Bytes()[4:]
	for _, bad := range [][]byte{
		bytes.Replace(payload, []byte(`"config_sync_version":1`), []byte(`"config_sync_version":null`), 1),
		bytes.Replace(payload, []byte(`"config_sync_version":1`), []byte(`"config_sync_version":2`), 1),
		bytes.Replace(payload, []byte(`"config_sync_version":1`), []byte(`"config_sync_version":1,"CONFIG_SYNC_VERSION":1`), 1),
		bytes.Replace(payload, []byte(`"role":"control"`), []byte(`"role":"data_carrier"`), 1),
		bytes.Replace(payload, []byte(`"type":"auth_start"`), []byte(`"type":"auth_start","session_id":"not-a-session"`), 1),
		append(append([]byte(nil), payload...), []byte(`{}`)...),
		bytes.Repeat([]byte(" "), MaxControlFrameBytes+1),
	} {
		if _, err := decodeSyncAuth(bad); err == nil {
			t.Fatal("malformed or incompatible auth frame accepted")
		}
	}
	if err := writeSyncAuth(syncShortWriter{}, start); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short auth write ignored", err)
	}
}
