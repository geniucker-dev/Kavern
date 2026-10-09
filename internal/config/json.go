package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxJSONBytes = 1 << 20

var ErrInvalidJSON = errors.New("invalid configuration JSON")

// DecodeJSON rejects unknown fields, duplicate keys (including case aliases),
// excessive nesting, invalid UTF-8, oversized input, and trailing documents.
func DecodeJSON(r io.Reader, dst any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxJSONBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxJSONBytes || !utf8.Valid(data) {
		return ErrInvalidJSON
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	if err := scanValue(scan, 0); err != nil {
		return ErrInvalidJSON
	}
	if _, err := scan.Token(); err != io.EOF {
		return ErrInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return ErrInvalidJSON
	}
	return nil
}
func scanValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalidJSON
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			text, ok := key.(string)
			if !ok {
				return ErrInvalidJSON
			}
			text = strings.ToLower(text)
			if seen[text] {
				return ErrInvalidJSON
			}
			seen[text] = true
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidJSON
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidJSON
		}
	default:
		return ErrInvalidJSON
	}
	return nil
}
