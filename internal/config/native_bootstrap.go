package config

import (
	"bytes"
	"errors"
)

// NativeBootstrap contains transport trust and device identity only. Business
// targets and carrier policy are supplied by the authenticated server snapshot.
type NativeBootstrap struct {
	Server     string `json:"server"`
	DeviceID   string `json:"device_id"`
	SecretEnv  string `json:"secret_env"`
	CAFile     string `json:"ca_file"`
	ServerName string `json:"server_name,omitempty"`
}

func (c NativeBootstrap) Validate() error {
	if ValidateAddress(c.Server) != nil || !ValidID(c.DeviceID) || !ValidID(c.SecretEnv) || c.CAFile == "" {
		return errors.New("invalid native bootstrap settings")
	}
	return nil
}
func LoadNativeBootstrap(path string) (NativeBootstrap, error) {
	var c NativeBootstrap
	data, keys, err := bootstrapFile(path)
	if err != nil {
		return c, err
	}
	for _, key := range []string{"targets", "carriers", "limits"} {
		if _, ok := keys[key]; ok {
			return c, errors.New("remove targets, carriers and limits from agent config; configure tunnels and carrier policy on the server; upgrade both native commands together")
		}
	}
	if DecodeJSON(bytes.NewReader(data), &c) != nil {
		return c, errors.New("invalid native bootstrap fields; use server, device_id, secret_env, ca_file and optional server_name")
	}
	return c, c.Validate()
}
