package domain

import (
	"encoding/json"
	"math"
	"testing"
)

func TestConfigRevisionCanonicalJSON(t *testing.T) {
	for _, value := range []string{`0`, `1`, `"0"`, `"01"`, `"+1"`, `"-1"`, `" 1"`, `"18446744073709551616"`, `null`} {
		var r ConfigRevision
		if json.Unmarshal([]byte(value), &r) == nil {
			t.Fatalf("accepted noncanonical revision %s", value)
		}
	}
	for _, want := range []ConfigRevision{1, 2, ConfigRevision(math.MaxUint64)} {
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		var got ConfigRevision
		if err = json.Unmarshal(data, &got); err != nil || got != want {
			t.Fatal("revision round trip")
		}
	}
	if _, err := json.Marshal(ConfigRevision(0)); err == nil {
		t.Fatal("zero revision encoded")
	}
}
