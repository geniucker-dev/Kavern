package agent_v1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/zhuhaoyu/kavern/internal/domain"
)

func CanonicalAuthMessage(deviceID domain.DeviceID, clientNonce, serverNonce, protocolVersion, transportRole string) ([]byte, error) {
	if deviceID == "" || clientNonce == "" || serverNonce == "" || protocolVersion == "" || transportRole == "" {
		return nil, ErrInvalidInput
	}
	return []byte(fmt.Sprintf("device_id=%s\nclient_nonce=%s\nserver_nonce=%s\nprotocol_version=%s\ntransport_role=%s\n",
		deviceID, clientNonce, serverNonce, protocolVersion, transportRole)), nil
}

func SignAuthResponse(deviceSecret []byte, deviceID domain.DeviceID, clientNonce, serverNonce, protocolVersion, transportRole string) (string, error) {
	message, err := CanonicalAuthMessage(deviceID, clientNonce, serverNonce, protocolVersion, transportRole)
	if err != nil {
		return "", err
	}
	return signHMAC(deviceSecret, message)
}

func VerifyAuthResponse(deviceSecret []byte, responseHex string, deviceID domain.DeviceID, clientNonce, serverNonce, protocolVersion, transportRole string) error {
	message, err := CanonicalAuthMessage(deviceID, clientNonce, serverNonce, protocolVersion, transportRole)
	if err != nil {
		return err
	}
	return verifyHMAC(deviceSecret, responseHex, message)
}

func CanonicalCarrierBindMessage(sessionID domain.SessionID, deviceID domain.DeviceID, carrierNonce, protocolVersion, transportRole string) ([]byte, error) {
	if sessionID == "" || deviceID == "" || carrierNonce == "" || protocolVersion == "" || transportRole == "" {
		return nil, ErrInvalidInput
	}
	return []byte(fmt.Sprintf("session_id=%s\ndevice_id=%s\ncarrier_nonce=%s\nprotocol_version=%s\ntransport_role=%s\n",
		sessionID, deviceID, carrierNonce, protocolVersion, transportRole)), nil
}

func SignCarrierBind(deviceSecret []byte, sessionID domain.SessionID, deviceID domain.DeviceID, carrierNonce, protocolVersion, transportRole string) (string, error) {
	message, err := CanonicalCarrierBindMessage(sessionID, deviceID, carrierNonce, protocolVersion, transportRole)
	if err != nil {
		return "", err
	}
	return signHMAC(deviceSecret, message)
}

func VerifyCarrierBind(deviceSecret []byte, responseHex string, sessionID domain.SessionID, deviceID domain.DeviceID, carrierNonce, protocolVersion, transportRole string) error {
	message, err := CanonicalCarrierBindMessage(sessionID, deviceID, carrierNonce, protocolVersion, transportRole)
	if err != nil {
		return err
	}
	return verifyHMAC(deviceSecret, responseHex, message)
}

func generateToken() (string, error) {
	raw := make([]byte, randomTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func signHMAC(secret, message []byte) (string, error) {
	if len(secret) == 0 {
		return "", ErrInvalidInput
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func verifyHMAC(secret []byte, responseHex string, message []byte) error {
	if len(secret) == 0 || responseHex == "" {
		return ErrAuthFailed
	}
	response, err := hex.DecodeString(responseHex)
	if err != nil {
		return ErrAuthFailed
	}
	if len(response) != sha256.Size {
		return ErrAuthFailed
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(message)
	expected := mac.Sum(nil)
	if !hmac.Equal(response, expected) {
		return ErrAuthFailed
	}
	return nil
}

func containsSecret(err error, secret []byte) bool {
	if err == nil || len(secret) == 0 {
		return false
	}
	return strings.Contains(err.Error(), string(secret))
}

var _ = errors.Is
