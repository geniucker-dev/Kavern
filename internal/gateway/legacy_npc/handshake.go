package legacy_npc

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
)

const (
	connTypeMain = "main"
	connTypeChan = "chan"

	legacyCoreVersion   = "0.26.0"
	legacyClientVersion = "0.26.34"

	defaultMaxHandshakeBytes = 4096
	defaultHandshakeTimeout  = 5 * time.Second
)

type handshakeResult struct {
	connType  string
	deviceID  domain.DeviceID
	lookupKey string
}

func (g *Gateway) readHandshake(ctx context.Context, conn net.Conn) (handshakeResult, error) {
	if err := ctx.Err(); err != nil {
		return handshakeResult{}, err
	}
	if err := conn.SetDeadline(time.Now().Add(g.handshakeTimeout)); err != nil {
		return handshakeResult{}, fmt.Errorf("set handshake deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	return g.readStockHandshake(ctx, conn)
}

func (g *Gateway) readStockHandshake(ctx context.Context, conn net.Conn) (handshakeResult, error) {
	var preface [3]byte
	if _, err := io.ReadFull(conn, preface[:]); err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	if string(preface[:]) != "TST" {
		return handshakeResult{}, ErrInvalidHandshake
	}
	// These declarations are opaque bounded metadata, not admission rules.
	if _, err := readLengthPrefixedBytes(conn, g.maxHandshakeBytes); err != nil {
		return handshakeResult{}, err
	}
	if _, err := readLengthPrefixedBytes(conn, g.maxHandshakeBytes); err != nil {
		return handshakeResult{}, err
	}
	if err := writeAll(conn, legacyServerVersionField()); err != nil {
		return handshakeResult{}, err
	}
	var tokenBytes [32]byte
	defer clear(tokenBytes[:])
	if _, err := io.ReadFull(conn, tokenBytes[:]); err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	deviceID, lookupKey, err := g.resolveLegacyCredential(ctx, tokenBytes[:])
	if err != nil {
		_ = writeAll(conn, []byte("vkey"))
		return handshakeResult{}, ErrInvalidHandshake
	}
	if err := writeAll(conn, []byte("sucs")); err != nil {
		return handshakeResult{}, err
	}
	var connTypeBytes [4]byte
	if _, err := io.ReadFull(conn, connTypeBytes[:]); err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	connType := string(connTypeBytes[:])
	if connType != connTypeMain && connType != connTypeChan {
		return handshakeResult{}, ErrUnsupportedConnection
	}
	return handshakeResult{connType: connType, deviceID: deviceID, lookupKey: lookupKey}, nil
}

func (g *Gateway) resolveLegacyToken(ctx context.Context, token []byte) (domain.DeviceID, error) {
	id, _, err := g.resolveLegacyCredential(ctx, token)
	return id, err
}
func (g *Gateway) resolveLegacyCredential(ctx context.Context, token []byte) (domain.DeviceID, string, error) {
	if !isStrictLegacyWireToken(token) {
		return "", "", ErrInvalidHandshake
	}
	normalized, err := security.NormalizeLegacyWireToken(string(token))
	if err != nil {
		return "", "", ErrInvalidHandshake
	}
	lookupKey, err := security.LegacyLookupKey(g.serverSecret, normalized)
	if err != nil {
		return "", "", ErrInvalidHandshake
	}
	device, err := g.store.ResolveLegacyDeviceForAuth(ctx, lookupKey)
	if err != nil {
		return "", "", ErrInvalidHandshake
	}
	return device.ID, lookupKey, nil
}

func readLengthPrefixedString(r io.Reader, max int) (string, error) {
	payload, err := readLengthPrefixedBytes(r, max)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func readLengthPrefixedBytes(r io.Reader, max int) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, ErrInvalidHandshake
	}
	size := int32(binary.LittleEndian.Uint32(prefix[:]))
	if size <= 0 || int(size) > max {
		return nil, ErrInvalidHandshake
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, ErrInvalidHandshake
	}
	return payload, nil
}

func legacyServerVersionField() []byte {
	sum := md5.Sum([]byte(legacyCoreVersion))
	field := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(field, sum[:])
	return field
}

func isStrictLegacyWireToken(token []byte) bool {
	if len(token) != 32 {
		return false
	}
	for _, value := range token {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}
