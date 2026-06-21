package security

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const vkeyRandomBytes = 32

func GenerateVKey() (string, error) {
	raw := make([]byte, vkeyRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate vkey: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func LegacyWireTokenFromVKey(vkey string) (string, error) {
	if vkey == "" {
		return "", errors.New("vkey is required")
	}
	sum := md5.Sum([]byte(vkey))
	return hex.EncodeToString(sum[:]), nil
}

func NormalizeLegacyWireToken(token string) (string, error) {
	if len(token) != md5.Size*2 {
		return "", errors.New("legacy wire token must be exactly 32 hex characters")
	}
	decoded, err := hex.DecodeString(token)
	if err != nil {
		return "", errors.New("legacy wire token must be hex")
	}
	return hex.EncodeToString(decoded), nil
}

func LegacyLookupKey(serverSecret []byte, wireToken string) (string, error) {
	if len(serverSecret) == 0 {
		return "", errors.New("server secret is required")
	}
	normalized, err := NormalizeLegacyWireToken(wireToken)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, serverSecret)
	_, _ = mac.Write([]byte(normalized))
	return strings.ToLower(hex.EncodeToString(mac.Sum(nil))), nil
}
