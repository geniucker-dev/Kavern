package legacy_npc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxLinkMetadataBytes   = 16 * 1024
	maxLegacyAddressBytes  = 1024
	legacyLinkTimeoutNanos = int64(5_000_000_000)
)

type legacyLinkMetadata struct {
	ConnType     string            `json:"ConnType"`
	Host         string            `json:"Host"`
	Crypt        bool              `json:"Crypt"`
	Compress     bool              `json:"Compress"`
	LocalProxy   bool              `json:"LocalProxy"`
	RemoteAddr   string            `json:"RemoteAddr"`
	ProtoVersion string            `json:"ProtoVersion"`
	Option       legacyLinkOptions `json:"Option"`
}

type legacyLinkOptions struct {
	Timeout int64 `json:"Timeout"`
}

func encodeLegacyLinkMetadata(host, remoteAddr string) ([]byte, error) {
	if !isValidLegacyTargetAddress(host) {
		return nil, ErrLegacyInvalidTargetAddress
	}
	if !isValidLegacyRemoteAddress(remoteAddr) {
		return nil, ErrLegacyInvalidRemoteAddress
	}
	encoded, err := json.Marshal(legacyLinkMetadata{
		ConnType:     "tcp",
		Host:         host,
		Crypt:        false,
		Compress:     false,
		LocalProxy:   false,
		RemoteAddr:   remoteAddr,
		ProtoVersion: "",
		Option:       legacyLinkOptions{Timeout: legacyLinkTimeoutNanos},
	})
	if err != nil {
		return nil, ErrLegacyLinkMetadataWrite
	}
	if len(encoded) > maxLinkMetadataBytes {
		return nil, ErrLegacyLinkMetadataTooLarge
	}
	payload := make([]byte, 4+len(encoded))
	binary.LittleEndian.PutUint32(payload[:4], uint32(int32(len(encoded))))
	copy(payload[4:], encoded)
	return payload, nil
}

func writeLegacyLinkMetadata(ctx context.Context, stream *LegacyStream, payload []byte) error {
	result := make(chan error, 1)
	go func() {
		result <- writeAll(stream, payload)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		_ = stream.Close()
		<-result
		return ctx.Err()
	}
}

func isValidLegacyTargetAddress(address string) bool {
	if !isValidLegacyMetadataText(address, false) {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || !isDecimalPort(port) {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || parsedPort > 65535 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if strings.Contains(host, ":") || isInvalidIPv4LikeHost(host) {
		return false
	}
	return isValidLegacyHostname(host)
}

func isValidLegacyRemoteAddress(address string) bool {
	return isValidLegacyMetadataText(address, true)
}

func isValidLegacyMetadataText(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	if len(value) > maxLegacyAddressBytes || !utf8.ValidString(value) || strings.Contains(value, "://") || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func isDecimalPort(port string) bool {
	if port == "" {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isInvalidIPv4LikeHost(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

func isValidLegacyHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
