package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// NativeServer is transport/storage bootstrap, not per-device carrier policy.
type NativeServer struct {
	AdminSocket     string `json:"admin_socket,omitempty"`
	ControlListen   string `json:"control_listen"`
	LegacyListen    string `json:"legacy_listen,omitempty"`
	CertFile        string `json:"cert_file"`
	KeyFile         string `json:"key_file"`
	StateFile       string `json:"state_file"`
	MasterKeyEnv    string `json:"master_key_env"`
	ServerSecretEnv string `json:"server_secret_env,omitempty"`
}

func bootstrapFile(path string) ([]byte, map[string]json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxJSONBytes+1))
	if err != nil || len(data) > MaxJSONBytes {
		return nil, nil, errors.New("invalid bootstrap JSON")
	}
	var keys map[string]json.RawMessage
	if DecodeJSON(bytes.NewReader(data), &keys) != nil || keys == nil {
		return nil, nil, errors.New("invalid bootstrap JSON")
	}
	return data, keys, nil
}
func LoadNativeServer(path string) (NativeServer, error) {
	var c NativeServer
	data, keys, err := bootstrapFile(path)
	if err != nil {
		return c, err
	}
	if _, ok := keys["limits"]; ok {
		return c, errors.New("remove server limits from bootstrap; configure carrier policy in server-owned device state")
	}
	if DecodeJSON(bytes.NewReader(data), &c) != nil {
		return c, errors.New("invalid server bootstrap fields")
	}
	if c.ControlListen == "" {
		c.ControlListen = "127.0.0.1:8024"
	}
	if ValidateAddress(c.ControlListen) != nil || (c.LegacyListen != "" && ValidateAddress(c.LegacyListen) != nil) || c.CertFile == "" || c.KeyFile == "" || c.StateFile == "" || !ValidID(c.MasterKeyEnv) || (c.LegacyListen != "" && !ValidID(c.ServerSecretEnv)) || (c.ServerSecretEnv != "" && !ValidID(c.ServerSecretEnv)) || (c.AdminSocket != "" && (!filepath.IsAbs(c.AdminSocket) || filepath.Clean(c.AdminSocket) != c.AdminSocket || len(c.AdminSocket) > 100)) {
		return c, errors.New("invalid server bootstrap settings")
	}
	return c, nil
}
