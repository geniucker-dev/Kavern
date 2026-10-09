package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/store"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(out, "Kavern offline administration\nCommands: validate, init-state, add-device, rotate-device, add-tunnel, set-device-enabled, set-tunnel-enabled\nUse <command> -h for flags. Stop kavernd before changing state; restart to apply changes.")
		return nil
	}
	if args[0] == "version" {
		fmt.Fprintln(out, "kavernctl MVP KAPv1")
		return nil
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	enabled := fs.Bool("enabled", false, "explicit enabled state for set-*-enabled")
	state := fs.String("state", "", "private local state path")
	master := fs.String("master-key-env", "KAVERN_MASTER_KEY", "environment variable holding 32-byte base64url master key")
	id := fs.String("id", "", "device or tunnel ID")
	project := fs.String("project", "", "project ID")
	user := fs.String("user", "", "user ID")
	kind := fs.String("kind", "kapv1", "credential kind: kapv1 or legacy")
	serverSecret := fs.String("server-secret-env", "KAVERN_SERVER_SECRET", "legacy lookup HMAC key environment")
	device := fs.String("device", "", "tunnel device ID")
	listen := fs.String("listen", "", "public TCP listener address")
	target := fs.String("target", "", "stored TCP target address")
	cfgPath := fs.String("config", "", "JSON configuration path")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "validate" {
		switch *kind {
		case "server":
			_, err := config.LoadServer(*cfgPath)
			return err
		case "agent":
			_, err := config.LoadAgent(*cfgPath)
			return err
		default:
			return errors.New("validate requires -kind server or agent")
		}
	}
	if *state == "" {
		return errors.New("-state is required")
	}
	key, err := store.MasterKeyFromEnv(*master)
	if err != nil {
		return err
	}
	unlock, err := store.LockState(*state)
	if err != nil {
		return err
	}
	defer unlock()
	ctx := context.Background()
	var s *store.MemoryStore
	if args[0] == "init-state" {
		if _, err := os.Lstat(*state); !os.IsNotExist(err) {
			return errors.New("state already exists or cannot be inspected")
		}
		if !config.ValidID(*user) || !config.ValidID(*project) {
			return errors.New("valid -user and -project are required")
		}
		s = store.NewMemoryStore()
		_ = s.CreateUser(ctx, domain.User{ID: domain.UserID(*user)})
		_ = s.CreateProject(ctx, domain.Project{ID: domain.ProjectID(*project), UserID: domain.UserID(*user)})
	} else {
		s, err = store.LoadState(*state, key)
		if err != nil {
			return err
		}
	}
	var issued any
	switch args[0] {
	case "init-state":
	case "add-device", "rotate-device":
		if !config.ValidID(*id) {
			return errors.New("valid -id is required")
		}
		deviceID := domain.DeviceID(*id)
		if args[0] == "add-device" {
			if _, err := s.GetDevice(ctx, deviceID); err == nil {
				return errors.New("device already exists")
			}
			if _, err := s.GetProject(ctx, domain.ProjectID(*project)); err != nil {
				return errors.New("unknown project")
			}
			_ = s.CreateDevice(ctx, domain.Device{ID: deviceID, ProjectID: domain.ProjectID(*project), Enabled: true})
		} else {
			if _, err := s.GetDevice(ctx, deviceID); err != nil {
				return err
			}
		}
		switch *kind {
		case "kapv1":
			secret := make([]byte, 32)
			if _, err = rand.Read(secret); err != nil {
				return err
			}
			if err = s.SetKAPv1DeviceSecret(ctx, deviceID, secret); err != nil {
				return err
			}
			issued = struct {
				DeviceID string `json:"device_id"`
				Secret   string `json:"device_secret"`
			}{*id, base64.RawURLEncoding.EncodeToString(secret)}
		case "legacy":
			secret, err := base64.RawURLEncoding.DecodeString(os.Getenv(*serverSecret))
			if err != nil || len(secret) < 32 {
				return errors.New("legacy server secret must contain at least 32 base64url bytes")
			}
			var credential store.IssuedLegacyCredential
			if args[0] == "rotate-device" {
				credential, err = s.RotateLegacyCredential(ctx, deviceID, secret)
			} else {
				credential, err = s.IssueLegacyCredential(ctx, deviceID, secret)
			}
			if err != nil {
				return err
			}
			issued = struct {
				DeviceID string `json:"device_id"`
				VKey     string `json:"vkey"`
			}{*id, credential.VKey}
		default:
			return errors.New("unsupported credential kind")
		}
	case "set-device-enabled", "set-tunnel-enabled":
		explicit := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "enabled" {
				explicit = true
			}
		})
		if !explicit || !config.ValidID(*id) {
			return errors.New("valid -id and explicit -enabled=true or -enabled=false are required")
		}
		if args[0] == "set-device-enabled" {
			v, err := s.GetDevice(ctx, domain.DeviceID(*id))
			if err != nil {
				return err
			}
			v.Enabled = *enabled
			_ = s.CreateDevice(ctx, v)
		} else {
			v, err := s.GetTunnel(ctx, domain.TunnelID(*id))
			if err != nil {
				return err
			}
			v.Enabled = *enabled
			_ = s.CreateTunnel(ctx, v)
		}
	case "add-tunnel":
		if !config.ValidID(*id) || !config.ValidID(*device) || config.ValidateAddress(*listen) != nil || config.ValidateAddress(*target) != nil {
			return errors.New("valid tunnel ID, device, listener and target are required")
		}
		if _, err := s.GetDevice(ctx, domain.DeviceID(*device)); err != nil {
			return errors.New("unknown device")
		}
		if _, err := s.GetTunnel(ctx, domain.TunnelID(*id)); err == nil {
			return errors.New("tunnel already exists")
		}
		if _, err := s.FindTunnelByListener(ctx, domain.ListenerRef(*listen)); err == nil {
			return errors.New("listener already exists")
		}
		_ = s.CreateTunnel(ctx, domain.Tunnel{ID: domain.TunnelID(*id), DeviceID: domain.DeviceID(*device), Protocol: domain.TunnelProtocolTCP, Listener: domain.ListenerRef(*listen), TargetAddr: *target, Enabled: true})
	default:
		return errors.New("unknown command")
	}
	if err = s.SaveState(*state, key); err != nil {
		return err
	}
	if issued != nil {
		return json.NewEncoder(out).Encode(issued)
	}
	fmt.Fprintln(out, "state saved; restart kavernd to apply")
	return nil
}
