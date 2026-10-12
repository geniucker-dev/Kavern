package config

import (
	"errors"
	"os"
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
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	if err = DecodeJSON(f, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
