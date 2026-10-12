package agent_v1

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"net"
	"sync"
	"time"
)

var ErrNativeMigration = errors.New("native synchronization rejected; upgrade kavernd and kavern-agent together and keep targets/carrier policy on the server")

// RunBootstrapAgent creates a fresh authenticated receiver on each reconnect.
// Application streams belong to one session and are never reconnected/replayed.
func RunBootstrapAgent(ctx context.Context, cfg config.NativeBootstrap, ready func(domain.ConfigRevision), unavailable func()) error {
	secret, trust, err := bootstrapMaterial(cfg)
	if err != nil {
		return errors.New("invalid bootstrap identity/trust; provide a 32-byte base64url secret environment and trusted CA")
	}
	defer clear(secret)
	delay := 100 * time.Millisecond
	reported := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		reached, err := runBootstrapSession(ctx, cfg, secret, trust, ready)
		if err := ctx.Err(); err != nil {
			return err
		}
		if errors.Is(err, ErrSyncSchema) || errors.Is(err, ErrSyncTransfer) || errors.Is(err, ErrLifecycle) {
			return ErrNativeMigration
		}
		if reached {
			delay = 100 * time.Millisecond
			reported = false
		}
		if !reported && unavailable != nil {
			unavailable()
			reported = true
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, 5*time.Second)
	}
}
func runBootstrapSession(parent context.Context, cfg config.NativeBootstrap, secret []byte, trust *tls.Config, ready func(domain.ConfigRevision)) (reached bool, result error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	receiver, control, err := openBootstrapWithMaterial(ctx, cfg, secret, trust)
	if err != nil {
		return false, err
	}
	var workers sync.WaitGroup
	var carriers []*SyncClientCarrier
	var controlErr error
	workers.Add(1)
	go func() { defer workers.Done(); controlErr = receiver.Run(ctx, control); cancel() }()
	defer func() {
		cancel()
		_ = control.Close()
		receiver.Close()
		for _, c := range carriers {
			_ = c.Close()
		}
		workers.Wait()
		if result == nil {
			result = controlErr
		}
	}()
	wait, cancelWait := context.WithTimeout(ctx, SyncTransferTimeout)
	snapshot, err := receiver.WaitApplied(wait, 0)
	cancelWait()
	if err != nil {
		return false, err
	}
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: syncHandshakeTimeout}, Config: trust}
	for i := 0; i < snapshot.Policy.Carriers; i++ {
		connected, err := dial.DialContext(ctx, "tcp", cfg.Server)
		if err != nil {
			return false, err
		}
		c, err := receiver.BindSyncCarrierTLS(ctx, connected.(*tls.Conn), secret)
		if err != nil {
			return false, err
		}
		carriers = append(carriers, c)
		workers.Add(1)
		go func(c *SyncClientCarrier) { defer workers.Done(); _ = c.Run(ctx, nil); cancel() }(c)
	}
	var after domain.ConfigRevision
	for {
		if err := receiver.RequestReady(ctx); err != nil {
			return reached, err
		}
		current, ok := receiver.ReadySnapshot()
		if ok {
			reached = true
			after = current.Revision
			if ready != nil {
				ready(after)
			}
		}
		if _, err := receiver.WaitApplied(ctx, after); err != nil {
			return reached, err
		}
	}
}

// ReadySnapshot exposes only projected business state after exact scoped ready.
func (r *ConfigReceiver) ReadySnapshot() (domain.NativeSnapshot, bool) {
	return r.observeSnapshot(true)
}

// Lease precedes receiver state in this observation guard. Check the clock after
// acquiring both guards; delayed worker cleanup cannot supply ready authority.
// Terminal cleanup runs only after both guards have been released.
func (r *ConfigReceiver) observeSnapshot(requireReady bool) (domain.NativeSnapshot, bool) {
	lease := r.lifecycle
	if lease != nil {
		lease.mu.Lock()
	}
	r.mu.Lock()
	live := r.auth.LifecycleVersion == 0 || lease != nil
	if lease != nil {
		live = lease.liveLocked(lease.clock.Now()) == nil
	}
	var snapshot domain.NativeSnapshot
	valid := live && !r.closed && r.applied.Revision != 0
	if requireReady {
		valid = valid && r.stage == nil && r.ackDeadline.IsZero() && r.ready.Revision != 0 && r.ready == r.currentTupleLocked() && r.liveCarriersLocked() == r.applied.Policy.Carriers
	}
	if valid {
		snapshot = r.applied
		snapshot.Tunnels = append([]domain.NativeTunnel(nil), snapshot.Tunnels...)
	}
	r.mu.Unlock()
	if lease != nil {
		lease.mu.Unlock()
		lease.finish()
	}
	return snapshot, valid
}
