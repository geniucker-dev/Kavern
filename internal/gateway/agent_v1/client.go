package agent_v1

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/dataplane/carrier"
	"github.com/geniucker-dev/kavern/internal/dataplane/mux"
	"github.com/geniucker-dev/kavern/internal/domain"
)

// RunAgent reconnects complete control sessions with bounded backoff. An existing
// stream is never retried automatically because doing so could duplicate bytes.
func RunAgent(ctx context.Context, cfg config.Agent, tlsConfig *tls.Config, secret []byte, ready func()) error {
	if len(secret) != 32 || tlsConfig == nil || tlsConfig.InsecureSkipVerify || cfg.Carriers < 1 || cfg.Carriers > 4 || cfg.Limits.Validate() != nil || !config.ValidID(cfg.DeviceID) || config.ValidateAddress(cfg.Server) != nil {
		return ErrInvalidInput
	}
	delay := 100 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = runAgentSession(ctx, cfg, tlsConfig, secret, ready)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 5*time.Second)
	}
}
func runAgentSession(ctx context.Context, cfg config.Agent, tlsConfig *tls.Config, secret []byte, ready func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dial := func() (net.Conn, error) {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: tlsConfig}
		return d.DialContext(ctx, "tcp", cfg.Server)
	}
	conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	nonce, err := GenerateNonce()
	if err != nil {
		return err
	}
	if err = writeControl(conn, controlFrame{Role: TransportRoleControl, Type: "auth_start", DeviceID: domain.DeviceID(cfg.DeviceID), ClientNonce: nonce}); err != nil {
		return err
	}
	challenge, err := readControl(conn)
	if err != nil {
		return err
	}
	if challenge.Type != "auth_challenge" {
		return ErrAuthFailed
	}
	response, err := SignAuthResponse(secret, domain.DeviceID(cfg.DeviceID), nonce, challenge.ServerNonce, ProtocolVersion, TransportRoleControl)
	if err != nil {
		return err
	}
	if err = writeControl(conn, controlFrame{Type: "auth_finish", ChallengeID: challenge.ChallengeID, Response: response}); err != nil {
		return err
	}
	result, err := readControl(conn)
	if err != nil {
		return err
	}
	if result.Type != "auth_ok" || result.DeviceID != domain.DeviceID(cfg.DeviceID) || validateToken(string(result.SessionID)) != nil {
		return ErrAuthFailed
	}
	var wg sync.WaitGroup
	var sessions []mux.Session
	defer func() {
		cancel()
		for _, s := range sessions {
			_ = s.Close()
		}
		wg.Wait()
	}()
	failures := make(chan error, cfg.Carriers)
	targets := TargetMap{}
	for id, target := range cfg.Targets {
		targets[domain.TunnelID(id)] = target
	}
	for range cfg.Carriers {
		data, err := dial()
		if err != nil {
			return err
		}
		_ = data.SetDeadline(time.Now().Add(5 * time.Second))
		nonce, err := GenerateNonce()
		if err != nil {
			data.Close()
			return err
		}
		signature, err := SignCarrierBind(secret, result.SessionID, result.DeviceID, nonce, ProtocolVersion, TransportRoleDataCarrier)
		if err != nil {
			data.Close()
			return err
		}
		if err = writeControl(data, controlFrame{Role: TransportRoleDataCarrier, Type: "carrier_bind", SessionID: result.SessionID, CarrierNonce: nonce, Response: signature}); err != nil {
			data.Close()
			return err
		}
		ack, err := readControl(data)
		if err != nil {
			data.Close()
			return err
		}
		if ack.Type != "carrier_ok" || ack.Limits == nil || ack.Limits.Validate() != nil {
			data.Close()
			return ErrInvalidInput
		}
		limits := *ack.Limits
		if limits.MaxStreams > cfg.Limits.MaxStreams || limits.MaxInflight > cfg.Limits.MaxInflight || limits.MaxBuffer > cfg.Limits.MaxBuffer {
			data.Close()
			return errors.New("server limits exceed agent configuration")
		}
		_ = data.SetDeadline(time.Time{})
		ms, err := mux.NewSmuxBackend().Server(data, muxLimits(limits))
		if err != nil {
			data.Close()
			return err
		}
		sessions = append(sessions, ms)
		c, err := carrier.New(ms, carrier.Config{MaxStreamsPerCarrier: limits.MaxStreams, MaxInflight: limits.MaxInflight, MaxBuffer: limits.MaxBuffer})
		if err != nil {
			return err
		}
		loop := &AgentDataLoop{Session: ms, Carrier: c, MaxHandlers: limits.MaxStreams, Targets: targets}
		wg.Add(1)
		go func() { defer wg.Done(); defer c.Close(); err := loop.Run(ctx); failures <- err; cancel() }()
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = writeControl(conn, controlFrame{Type: "ready", SessionID: result.SessionID, CarrierCount: cfg.Carriers}); err != nil {
		return err
	}
	readyAck, err := readControl(conn)
	if err != nil {
		return err
	}
	if readyAck.Type != "ready_ok" {
		return ErrInvalidInput
	}
	if ready != nil {
		ready()
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failures:
			return err
		case <-ticker.C:
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			if err = writeControl(conn, controlFrame{Type: "ping", SessionID: result.SessionID}); err != nil {
				return err
			}
			pong, err := readControl(conn)
			if err != nil {
				return err
			}
			if pong.Type != "pong" {
				return ErrInvalidInput
			}
		}
	}
}
