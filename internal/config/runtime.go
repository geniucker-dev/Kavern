package config

import (
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
)

type Limits struct {
	MaxStreams  int `json:"max_streams"`
	MaxInflight int `json:"max_inflight"`
	MaxBuffer   int `json:"max_buffer"`
}

func (l *Limits) Validate() error {
	if l.MaxStreams == 0 {
		l.MaxStreams = 64
	}
	if l.MaxInflight == 0 {
		l.MaxInflight = 1 << 20
	}
	if l.MaxBuffer == 0 {
		l.MaxBuffer = 8 << 20
	}
	if l.MaxStreams < 1 || l.MaxStreams > 1024 || l.MaxInflight < 16384 || l.MaxInflight > 16<<20 || l.MaxBuffer < l.MaxInflight+131072 || l.MaxBuffer > 64<<20 {
		return errors.New("invalid carrier limits")
	}
	return nil
}

type Server struct {
	ControlListen   string `json:"control_listen"`
	LegacyListen    string `json:"legacy_listen,omitempty"`
	CertFile        string `json:"cert_file"`
	KeyFile         string `json:"key_file"`
	StateFile       string `json:"state_file"`
	MasterKeyEnv    string `json:"master_key_env"`
	ServerSecretEnv string `json:"server_secret_env,omitempty"`
	Limits          Limits `json:"limits"`
}
type Agent struct {
	Server     string            `json:"server"`
	DeviceID   string            `json:"device_id"`
	SecretEnv  string            `json:"secret_env"`
	CAFile     string            `json:"ca_file"`
	ServerName string            `json:"server_name,omitempty"`
	Targets    map[string]string `json:"targets"`
	Carriers   int               `json:"carriers"`
	Limits     Limits            `json:"limits"`
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

func ValidID(id string) bool { return len(id) <= 128 && idPattern.MatchString(id) }
func ValidateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return errors.New("invalid TCP address")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return errors.New("invalid TCP port")
	}
	return nil
}
func LoadServer(path string) (Server, error) {
	var c Server
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	if err = DecodeJSON(f, &c); err != nil {
		return c, err
	}
	if c.ControlListen == "" {
		c.ControlListen = "127.0.0.1:8024"
	}
	if err = ValidateAddress(c.ControlListen); err != nil {
		return c, err
	}
	if c.LegacyListen != "" {
		if err = ValidateAddress(c.LegacyListen); err != nil {
			return c, err
		}
	}
	if c.CertFile == "" || c.KeyFile == "" || c.StateFile == "" || !ValidID(c.MasterKeyEnv) || (c.LegacyListen != "" && !ValidID(c.ServerSecretEnv)) {
		return c, errors.New("missing server settings")
	}
	return c, c.Limits.Validate()
}
func LoadAgent(path string) (Agent, error) {
	var c Agent
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	if err = DecodeJSON(f, &c); err != nil {
		return c, err
	}
	if err = ValidateAddress(c.Server); err != nil {
		return c, err
	}
	if !ValidID(c.DeviceID) || !ValidID(c.SecretEnv) || c.CAFile == "" || len(c.Targets) == 0 || len(c.Targets) > 1024 {
		return c, errors.New("invalid agent settings")
	}
	for id, addr := range c.Targets {
		if !ValidID(id) {
			return c, errors.New("invalid tunnel ID")
		}
		if err = ValidateAddress(addr); err != nil {
			return c, err
		}
	}
	if c.Carriers == 0 {
		c.Carriers = 2
	}
	if c.Carriers < 1 || c.Carriers > 4 {
		return c, errors.New("invalid carrier count")
	}
	return c, c.Limits.Validate()
}

func ValidCredentialID(id string) bool { return len(id) <= 256 && idPattern.MatchString(id) }
