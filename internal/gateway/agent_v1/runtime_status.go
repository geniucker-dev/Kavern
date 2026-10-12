package agent_v1

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
)

// DeviceRuntimeStatus exposes only sampled facts. It never exposes session IDs,
// auth challenges, HMACs, credential bytes or gateway-private inspection state.
func (s *AuthService) DeviceRuntimeStatus(ctx context.Context, id domain.DeviceID) domain.AgentRuntimeStatus {
	current, e := s.sessions.CurrentForDevice(ctx, id)
	if e != nil {
		return domain.AgentRuntimeStatus{}
	}
	select {
	case <-current.Done():
		return domain.AgentRuntimeStatus{}
	default:
	}
	result := domain.AgentRuntimeStatus{Present: true, Protocol: current.Protocol()}
	native, ok := current.(*agentSession)
	if !ok {
		return result
	}
	data := native.syncController()
	if data == nil {
		return result
	}
	data.mu.Lock()
	auth, applied, ready := data.auth, data.applied, data.ready
	data.mu.Unlock()
	if e = s.withSyncSession(ctx, auth, func() error { return nil }); e != nil {
		return domain.AgentRuntimeStatus{}
	}
	result.AppliedRevision = applied.Revision
	result.Carriers = native.pool.LiveCount()
	if ready == applied && ready.Revision != 0 {
		if snapshot, e := data.current(ctx, ready, true); e == nil && result.Carriers == snapshot.Policy.Carriers {
			result.Ready = true
		}
	}
	return result
}
