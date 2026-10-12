package domain

// AgentRuntimeStatus is a sampled observation, never a bearer or admission proof.
type AgentRuntimeStatus struct {
	Present         bool           `json:"present"`
	Protocol        AgentProtocol  `json:"protocol,omitempty"`
	AppliedRevision ConfigRevision `json:"applied_revision,omitempty"`
	Ready           bool           `json:"ready"`
	RenewalCount    uint64         `json:"renewal_count,omitempty"`
	Carriers        int            `json:"carriers"`
}
