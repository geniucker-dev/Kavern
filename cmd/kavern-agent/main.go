package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/geniucker-dev/kavern/internal/domain"
	"os"
	"os/signal"
	"syscall"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/gateway/agent_v1"
)

func main() {
	path := flag.String("config", "", "strict agent JSON configuration")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("kavern-agent KAPv1 config-sync=1")
		return
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(path string) error {
	cfg, err := config.LoadNativeBootstrap(path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err = agent_v1.RunBootstrapAgent(ctx, cfg, func(revision domain.ConfigRevision) {
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			Event    string                `json:"event"`
			Revision domain.ConfigRevision `json:"revision"`
		}{"agent_ready", revision})
	}, func() {
		fmt.Println(`{"event":"agent_reconnecting","code":"check_server_identity_and_native_version","message":"check server availability, enabled device credentials and trust; upgrade kavernd and kavern-agent together for config-sync=1"}`)
	})
	if ctx.Err() != nil {
		return nil
	}
	return err
}
