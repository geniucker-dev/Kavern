package domain

import "errors"

var (
	ErrDisabledTunnel = errors.New("disabled tunnel")
	ErrDisabledDevice = errors.New("disabled device")
	ErrStaleAdmission = errors.New("stale desired-state admission")
)

// RouteView is read from one desired-state generation, never from caller flags.
type RouteView struct {
	Device   Device
	Tunnel   Tunnel
	Revision ConfigRevision
}
type WorkScope struct {
	DeviceID     DeviceID
	TunnelID     TunnelID
	Revision     ConfigRevision
	TargetAddr   string
	Listener     ListenerRef
	Protocol     TunnelProtocol
	SessionOwner bool
	Policy       NativePolicy
}

func (v RouteView) WorkScope() WorkScope {
	return WorkScope{DeviceID: v.Device.ID, TunnelID: v.Tunnel.ID, Revision: v.Revision, TargetAddr: v.Tunnel.TargetAddr, Listener: v.Tunnel.Listener, Protocol: v.Tunnel.Protocol}
}
