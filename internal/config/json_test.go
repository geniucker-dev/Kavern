package config

import (
	"strings"
	"testing"
)

func TestDecodeJSONRejectsAmbiguousInput(t *testing.T) {
	type settings struct {
		Name string `json:"name"`
	}
	for _, input := range []string{`{"name":"a","name":"b"}`, `{"name":"a","Name":"b"}`, `{"extra":1}`, `{"name":"a"} {}`, `{"name":"` + string([]byte{0xff}) + `"}`, strings.Repeat("[", 34) + strings.Repeat("]", 34), strings.Repeat(" ", MaxJSONBytes+1)} {
		var c settings
		if err := DecodeJSON(strings.NewReader(input), &c); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	var c settings
	if err := DecodeJSON(strings.NewReader(`{"name":"ok"}`), &c); err != nil || c.Name != "ok" {
		t.Fatalf("valid decode=%v", err)
	}
}
