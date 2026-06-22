package legacy_npc

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/security"
)

const (
	connTypeMain = "main"
	connTypeChan = "chan"

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
	if _, err := readLengthPrefixedString(conn, g.maxHandshakeBytes); err != nil {
		return handshakeResult{}, err
	}
	if _, err := readLengthPrefixedString(conn, g.maxHandshakeBytes); err != nil {
		return handshakeResult{}, err
	}
	// Observed stock npc v0.26.34 version-test acknowledgement.
	if _, err := conn.Write([]byte("TST")); err != nil {
		return handshakeResult{}, err
	}
	challenge, err := g.newAuthChallenge()
	if err != nil {
		return handshakeResult{}, err
	}
	if len(challenge) != 32 {
		return handshakeResult{}, ErrInvalidConfig
	}
	// Observed stock npc v0.26.34 auth challenge: uint32_le length + 32 bytes.
	if err := writeLengthPrefixedBytes(conn, challenge, g.maxHandshakeBytes); err != nil {
		return handshakeResult{}, err
	}

	var auth [36]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	token := string(auth[:32])
	connType := string(auth[32:])
	return g.resolveHandshake(ctx, connType, token)
}

func (g *Gateway) readSyntheticLineHandshake(ctx context.Context, conn net.Conn) (handshakeResult, error) {
	line, err := readBoundedLine(conn, g.maxHandshakeBytes)
	if err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	connType, token, err := parseHandshakeLine(line)
	if err != nil {
		return handshakeResult{}, err
	}
	if connType != connTypeMain && connType != connTypeChan {
		return handshakeResult{}, ErrUnsupportedConnection
	}
	return g.resolveHandshake(ctx, connType, token)
}

func (g *Gateway) resolveHandshake(ctx context.Context, connType, token string) (handshakeResult, error) {
	if connType != connTypeMain && connType != connTypeChan {
		return handshakeResult{}, ErrUnsupportedConnection
	}
	normalized, err := security.NormalizeLegacyWireToken(token)
	if err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	lookupKey, err := security.LegacyLookupKey(g.serverSecret, normalized)
	if err != nil {
		return handshakeResult{}, ErrInvalidHandshake
	}
	device, err := g.store.ResolveLegacyDeviceForAuth(ctx, lookupKey)
	if err != nil {
		return handshakeResult{}, err
	}
	return handshakeResult{connType: connType, deviceID: device.ID, lookupKey: lookupKey}, nil
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
	size := binary.LittleEndian.Uint32(prefix[:])
	if size == 0 || int(size) > max {
		return nil, ErrInvalidHandshake
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, ErrInvalidHandshake
	}
	return payload, nil
}

func writeLengthPrefixedBytes(w io.Writer, payload []byte, max int) error {
	if len(payload) == 0 || len(payload) > max {
		return ErrInvalidHandshake
	}
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readBoundedLine(r io.Reader, max int) (string, error) {
	limited := io.LimitReader(r, int64(max)+1)
	reader := bufio.NewReader(limited)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(line) > max {
		return "", ErrInvalidHandshake
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", ErrInvalidHandshake
	}
	return line, nil
}

func parseHandshakeLine(line string) (connType, token string, err error) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", "", ErrInvalidHandshake
	}
	if len(fields[0]) > 16 {
		return "", "", ErrUnsupportedConnection
	}
	return fields[0], fields[1], nil
}
