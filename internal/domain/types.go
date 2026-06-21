package domain

import "time"

type UserID string
type ProjectID string
type DeviceID string
type TunnelID string
type CredentialID string
type SessionID string
type ListenerRef string

type TunnelProtocol string

const (
	TunnelProtocolTCP  TunnelProtocol = "tcp"
	TunnelProtocolHTTP TunnelProtocol = "http"
)

type AgentProtocol string

const (
	AgentProtocolLegacyNPC AgentProtocol = "legacy_npc"
	AgentProtocolKAPv1     AgentProtocol = "kapv1"
)

type CredentialKind string

const (
	CredentialKindLegacyNPC         CredentialKind = "legacy_npc"
	CredentialKindKAPv1DeviceSecret CredentialKind = "kapv1_device_secret"
)

type User struct {
	ID   UserID
	Name string
}

type Project struct {
	ID     ProjectID
	UserID UserID
	Name   string
}

type Device struct {
	ID        DeviceID
	ProjectID ProjectID
	Name      string
	Enabled   bool
}

type Tunnel struct {
	ID         TunnelID
	DeviceID   DeviceID
	Protocol   TunnelProtocol
	Listener   ListenerRef
	TargetAddr string
	Enabled    bool
}

type DeviceCredential struct {
	ID              CredentialID
	DeviceID        DeviceID
	Kind            CredentialKind
	LegacyLookupKey string
	CreatedAt       time.Time
	RotatedAt       time.Time
}

type StreamOpenRequest struct {
	TunnelID   TunnelID
	Protocol   TunnelProtocol
	TargetAddr string
}
