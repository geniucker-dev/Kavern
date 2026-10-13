package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"github.com/geniucker-dev/kavern/internal/session"
	"math"
	"reflect"
	"sort"
	"unicode/utf8"
)

const MaxMutationReceipts = 256
const MaxMutationTombstones = 2048

var (
	ErrRecordConflict    = errors.New("record already exists")
	ErrOperationExpired  = errors.New("operation expired or unknown; refresh management epoch")
	ErrOperationReuse    = errors.New("operation ID reused with different request")
	ErrTombstoneCapacity = errors.New("deletion identity capacity exhausted")
	ErrCascadeRequired   = errors.New("explicit device cascade required")
)

type ManagementWindow struct {
	Lineage string
	Epoch   uint64
}
type Mutation struct {
	Window           ManagementWindow
	OperationID      string
	Kind             string
	User             *domain.User
	Project          *domain.Project
	Device           *domain.Device
	Configuration    *domain.DeviceConfiguration
	DeviceID         domain.DeviceID
	ExpectedRevision domain.ConfigRevision `json:",omitempty"`
	CredentialKind   domain.CredentialKind
	Cascade          bool
}

// Credential is delivery-only: it is excluded from persisted receipts and logs.
// Saved confirms durable desired state, never applied ACK/listener/carrier readiness.
// Cleanup describes only the fresh transaction's joined revocation work; retries
// report unknown because runtime cleanup status is not persisted in receipts.
type MutationResult struct {
	Saved      bool
	Cleanup    string
	Window     ManagementWindow
	Kind       string
	RecordID   string
	Revision   domain.ConfigRevision `json:",omitempty"`
	Replay     bool
	Credential string `json:"-"`
}
type mutationReceipt struct {
	RequestWindow ManagementWindow
	OperationID   string
	Digest        string
	Epoch         uint64
	Kind          string
	RecordID      string
	Revision      domain.ConfigRevision `json:",omitempty"`
}
type tombstone struct {
	Kind string
	ID   string
}
type managementState struct {
	Lineage    string
	Epoch      uint64
	Receipts   []mutationReceipt
	Tombstones []tombstone
}

func (m managementState) clone() managementState {
	m.Receipts = append([]mutationReceipt(nil), m.Receipts...)
	m.Tombstones = append([]tombstone(nil), m.Tombstones...)
	return m
}
func (m *managementState) advance() error {
	if m.Epoch == math.MaxUint64 {
		return ErrRevisionOverflow
	}
	m.Epoch++
	return nil
}
func (m managementState) validate(s *MemoryStore) error {
	if s.stateVersion < 3 {
		if m.Lineage != "" || m.Epoch != 0 || len(m.Receipts) != 0 || len(m.Tombstones) != 0 {
			return ErrInvalidState
		}
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(m.Lineage)
	if m.Epoch == 0 || err != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != m.Lineage || len(m.Receipts) > MaxMutationReceipts || len(m.Tombstones) > MaxMutationTombstones {
		return ErrInvalidState
	}
	ops := map[string]bool{}
	var epoch uint64
	for _, r := range m.Receipts {
		if r.RequestWindow.Epoch == math.MaxUint64 || r.RequestWindow.Epoch+1 != r.Epoch || (r.RequestWindow.Lineage != m.Lineage && !(r.RequestWindow.Lineage == "" && r.RequestWindow.Epoch == 0)) || !config.ValidID(r.OperationID) || ops[r.OperationID] || r.Epoch <= epoch || r.Epoch > m.Epoch || !mutationKind(r.Kind) || !config.ValidID(r.RecordID) {
			return ErrInvalidState
		}
		hash, err := hex.DecodeString(r.Digest)
		if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != r.Digest {
			return ErrInvalidState
		}
		if (r.Kind == "create_user" || r.Kind == "create_project") != (r.Revision == 0) {
			return ErrInvalidState
		}
		ops[r.OperationID] = true
		epoch = r.Epoch
	}
	deleted := map[tombstone]bool{}
	for _, t := range m.Tombstones {
		if !config.ValidID(t.ID) || deleted[t] {
			return ErrInvalidState
		}
		deleted[t] = true
		switch t.Kind {
		case "device":
			if _, ok := s.devices[domain.DeviceID(t.ID)]; ok {
				return ErrInvalidState
			}
		case "tunnel":
			if _, ok := s.tunnels[domain.TunnelID(t.ID)]; ok {
				return ErrInvalidState
			}
		default:
			return ErrInvalidState
		}
	}
	return nil
}
func mutationKind(k string) bool {
	switch k {
	case "create_user", "create_project", "create_device", "put_device", "rotate_credential", "delete_device":
		return true
	}
	return false
}
func (o *ConfigOwner) ManagementWindow(ctx context.Context) (ManagementWindow, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return ManagementWindow{}, err
	}
	if o.closed {
		return ManagementWindow{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return ManagementWindow{}, ErrCommitUncertain
	}
	return ManagementWindow{o.current.management.Lineage, o.current.management.Epoch}, nil
}

// Lookup never treats missing receipts as rollback, especially during uncertainty.
func (o *ConfigOwner) LookupOperation(ctx context.Context, window ManagementWindow, id string) (MutationResult, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return MutationResult{}, err
	}
	if o.closed {
		return MutationResult{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return MutationResult{}, ErrCommitUncertain
	}
	for _, r := range o.current.management.Receipts {
		if r.OperationID == id && window == r.RequestWindow {
			return receiptResult(o.current.management, r), nil
		}
	}
	return MutationResult{}, ErrOperationExpired
}
func receiptResult(m managementState, r mutationReceipt) MutationResult {
	return MutationResult{Saved: true, Cleanup: "unknown", Window: ManagementWindow{m.Lineage, r.Epoch}, Kind: r.Kind, RecordID: r.RecordID, Revision: r.Revision, Replay: true}
}

// legacyKey is trusted daemon bootstrap, never an API DTO/client credential.
func (o *ConfigOwner) ApplyMutation(ctx context.Context, m Mutation, legacyKey []byte) (MutationResult, error) {
	if !config.ValidID(m.OperationID) || !mutationKind(m.Kind) || !boundedMutation(m) || len(legacyKey) > 4096 {
		return MutationResult{}, config.ErrInvalidBusinessConfig
	}
	data, err := json.Marshal(m)
	if err != nil || len(data) > config.MaxJSONBytes {
		return MutationResult{}, config.ErrInvalidBusinessConfig
	}
	var owned Mutation
	if config.DecodeJSON(bytes.NewReader(data), &owned) != nil {
		return MutationResult{}, config.ErrInvalidBusinessConfig
	}
	key := append([]byte(nil), legacyKey...)
	defer clear(key)
	result := o.submit(configRequest{ctx: ctx, mutation: &owned, legacyKey: key, result: make(chan configResult, 1)})
	return result.mutationResult, result.err
}
func (o *ConfigOwner) processMutation(ctx context.Context, current *MemoryStore, m Mutation, legacyKey []byte) configResult {
	data, _ := json.Marshal(m)
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	ledger := current.management
	for _, r := range ledger.Receipts {
		if r.OperationID == m.OperationID {
			if r.Digest != hash {
				return configResult{err: ErrOperationReuse}
			}
			return configResult{mutationResult: receiptResult(ledger, r)}
		}
	}
	if m.Window.Lineage != ledger.Lineage || m.Window.Epoch != ledger.Epoch {
		return configResult{err: ErrOperationExpired}
	}
	current.mu.RLock()
	next := current.cloneLocked()
	current.mu.RUnlock()
	if next.stateVersion < 3 {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return configResult{err: err}
		}
		next.management.Lineage = base64.RawURLEncoding.EncodeToString(raw)
		next.stateVersion = 3
	}
	if err := next.management.advance(); err != nil {
		return configResult{err: err}
	}
	var id string
	var revision domain.ConfigRevision
	var credential string
	conflict := func(kind, id string) bool {
		for _, t := range next.management.Tombstones {
			if t.Kind == kind && t.ID == id {
				return true
			}
		}
		return false
	}
	addDeleted := func(kind, id string) error {
		if conflict(kind, id) {
			return nil
		}
		if len(next.management.Tombstones) >= MaxMutationTombstones {
			return ErrTombstoneCapacity
		}
		next.management.Tombstones = append(next.management.Tombstones, tombstone{kind, id})
		return nil
	}
	switch m.Kind {
	case "create_user":
		if m.User == nil || m.Project != nil || m.Device != nil || m.Configuration != nil || m.DeviceID != "" || m.ExpectedRevision != 0 || m.CredentialKind != "" || m.Cascade {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		u := *m.User
		id = string(u.ID)
		if !config.ValidID(id) || !utf8.ValidString(u.Name) || len(u.Name) > 256 {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		if _, ok := next.users[u.ID]; ok {
			return configResult{err: ErrRecordConflict}
		}
		next.users[u.ID] = u
	case "create_project":
		if m.Project == nil || m.User != nil || m.Device != nil || m.Configuration != nil || m.DeviceID != "" || m.ExpectedRevision != 0 || m.CredentialKind != "" || m.Cascade {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		p := *m.Project
		id = string(p.ID)
		if !config.ValidID(id) || !utf8.ValidString(p.Name) || len(p.Name) > 256 {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		if _, ok := next.projects[p.ID]; ok {
			return configResult{err: ErrRecordConflict}
		}
		if _, ok := next.users[p.UserID]; !ok {
			return configResult{err: ErrNotFound}
		}
		next.projects[p.ID] = p
	case "create_device":
		if m.Device == nil || m.User != nil || m.Project != nil || m.Configuration != nil || m.DeviceID != "" || m.ExpectedRevision != 0 || m.Cascade {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		d := *m.Device
		id = string(d.ID)
		if !config.ValidID(id) || !utf8.ValidString(d.Name) || len(d.Name) > 256 {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		if _, ok := next.devices[d.ID]; ok || conflict("device", id) {
			return configResult{err: ErrRecordConflict}
		}
		if _, ok := next.projects[d.ProjectID]; !ok {
			return configResult{err: ErrNotFound}
		}
		next.devices[d.ID] = d
		next.revisions[d.ID] = 1
		next.policies[d.ID] = o.defaults
		revision = 1
		var err error
		credential, err = issueMutationCredential(ctx, next, d.ID, m.CredentialKind, legacyKey, false)
		if err != nil {
			return configResult{err: err}
		}
	case "put_device", "rotate_credential", "delete_device":
		if m.User != nil || m.Project != nil || m.Device != nil || !config.ValidID(string(m.DeviceID)) {
			return configResult{err: config.ErrInvalidBusinessConfig}
		}
		old, err := next.configurationLocked(m.DeviceID)
		if err != nil {
			return configResult{err: err}
		}
		if old.Revision != m.ExpectedRevision {
			return configResult{err: ErrRevisionConflict}
		}
		id = string(m.DeviceID)
		revision = old.Revision
		switch m.Kind {
		case "put_device":
			if m.Configuration == nil || m.CredentialKind != "" || m.Cascade {
				return configResult{err: config.ErrInvalidBusinessConfig}
			}
			c := *m.Configuration
			if c.Device.ID != old.Device.ID || c.Device.ProjectID != old.Device.ProjectID {
				return configResult{err: ErrTunnelOwnership}
			}
			if c.Revision != old.Revision {
				return configResult{err: ErrRevisionConflict}
			}
			_, native := next.kapv1Secret[m.DeviceID]
			if err = config.ValidateDeviceConfiguration(c, native); err != nil {
				return configResult{err: err}
			}
			if len(c.Tunnels) == 0 {
				c.Tunnels = nil
			}
			if len(old.Tunnels) == 0 {
				old.Tunnels = nil
			}
			sort.Slice(c.Tunnels, func(i, j int) bool { return c.Tunnels[i].ID < c.Tunnels[j].ID })
			if !reflect.DeepEqual(c, old) {
				if revision == domain.ConfigRevision(math.MaxUint64) {
					return configResult{err: ErrRevisionOverflow}
				}
				revision++
			}
			present := map[domain.TunnelID]bool{}
			for _, t := range c.Tunnels {
				if existing, ok := current.tunnels[t.ID]; ok && existing.DeviceID != m.DeviceID {
					return configResult{err: ErrTunnelOwnership}
				}
				if conflict("tunnel", string(t.ID)) {
					return configResult{err: ErrRecordConflict}
				}
				present[t.ID] = true
			}
			for tid, t := range next.tunnels {
				if t.DeviceID == m.DeviceID {
					if !present[tid] {
						if err = addDeleted("tunnel", string(tid)); err != nil {
							return configResult{err: err}
						}
					}
					delete(next.tunnels, tid)
				}
			}
			for _, t := range c.Tunnels {
				next.tunnels[t.ID] = t
			}
			next.devices[m.DeviceID] = c.Device
			next.policies[m.DeviceID] = c.Policy
			next.revisions[m.DeviceID] = revision
		case "rotate_credential":
			if m.Configuration != nil || m.Cascade {
				return configResult{err: config.ErrInvalidBusinessConfig}
			}
			if revision == domain.ConfigRevision(math.MaxUint64) {
				return configResult{err: ErrRevisionOverflow}
			}
			credential, err = issueMutationCredential(ctx, next, m.DeviceID, m.CredentialKind, legacyKey, true)
			if err != nil {
				return configResult{err: err}
			}
			revision++
			next.revisions[m.DeviceID] = revision
		case "delete_device":
			if m.Configuration != nil || m.CredentialKind != "" {
				return configResult{err: config.ErrInvalidBusinessConfig}
			}
			if len(old.Tunnels) > 0 && !m.Cascade {
				return configResult{err: ErrCascadeRequired}
			}
			if revision == domain.ConfigRevision(math.MaxUint64) {
				return configResult{err: ErrRevisionOverflow}
			}
			revision++
			if err = addDeleted("device", id); err != nil {
				return configResult{err: err}
			}
			for tid, t := range next.tunnels {
				if t.DeviceID == m.DeviceID {
					if err = addDeleted("tunnel", string(tid)); err != nil {
						return configResult{err: err}
					}
					delete(next.tunnels, tid)
				}
			}
			for cid, c := range next.credentials {
				if c.DeviceID == m.DeviceID {
					delete(next.legacyIndex, c.LegacyLookupKey)
					delete(next.credentials, cid)
				}
			}
			delete(next.kapv1Secret, m.DeviceID)
			delete(next.devices, m.DeviceID)
			delete(next.revisions, m.DeviceID)
			delete(next.policies, m.DeviceID)
		}
	}
	next.listeners = make(map[domain.ListenerRef]domain.TunnelID, len(next.tunnels))
	for tid, t := range next.tunnels {
		if _, ok := next.listeners[t.Listener]; ok {
			return configResult{err: ErrListenerConflict}
		}
		next.listeners[t.Listener] = tid
	}
	receipt := mutationReceipt{RequestWindow: m.Window, OperationID: m.OperationID, Digest: hash, Epoch: next.management.Epoch, Kind: m.Kind, RecordID: id, Revision: revision}
	next.management.Receipts = append(next.management.Receipts, receipt)
	if len(next.management.Receipts) > MaxMutationReceipts {
		next.management.Receipts = append([]mutationReceipt(nil), next.management.Receipts[len(next.management.Receipts)-MaxMutationReceipts:]...)
	}
	if err := next.validateState(true); err != nil {
		return configResult{err: err}
	}
	result := o.persistCandidate(ctx, next, map[domain.DeviceID]domain.ConfigRevision{m.DeviceID: revision})
	if result.err != nil && result.revisions == nil {
		return result
	}
	result.mutationResult = receiptResult(next.management, receipt)
	result.mutationResult.Replay = false
	result.mutationResult.Cleanup = "complete"
	if errors.Is(result.err, session.ErrWorkCleanupPending) {
		result.mutationResult.Cleanup = "pending"
	}
	result.mutationResult.Credential = credential
	return result
}
func issueMutationCredential(ctx context.Context, next *MemoryStore, id domain.DeviceID, kind domain.CredentialKind, key []byte, rotate bool) (string, error) {
	switch kind {
	case domain.CredentialKindKAPv1DeviceSecret:
		if _, exists := next.kapv1Secret[id]; rotate && !exists {
			return "", ErrNotFound
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		defer clear(raw)
		if err := next.SetKAPv1DeviceSecret(ctx, id, raw); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(raw), nil
	case domain.CredentialKindLegacyNPC:
		if len(key) < 32 {
			return "", ErrMissingSecret
		}
		if rotate && len(next.legacyCredentialIDsForDeviceLocked(id)) == 0 {
			return "", ErrNotFound
		}
		var issued IssuedLegacyCredential
		var err error
		if rotate {
			issued, err = next.RotateLegacyCredential(ctx, id, key)
		} else {
			issued, err = next.IssueLegacyCredential(ctx, id, key)
		}
		return issued.VKey, err
	default:
		return "", config.ErrInvalidBusinessConfig
	}
}

// Bound caller-owned strings/slices before allocating the encoded request copy.
func boundedMutation(m Mutation) bool {
	size := 0
	add := func(values ...string) bool {
		for _, v := range values {
			if !utf8.ValidString(v) || len(v) > config.MaxJSONBytes {
				return false
			}
			size += len(v)
			if size > config.MaxJSONBytes {
				return false
			}
		}
		return true
	}
	if !add(m.Window.Lineage, m.OperationID, m.Kind, string(m.DeviceID), string(m.CredentialKind)) {
		return false
	}
	if u := m.User; u != nil && !add(string(u.ID), u.Name) {
		return false
	}
	if p := m.Project; p != nil && !add(string(p.ID), string(p.UserID), p.Name) {
		return false
	}
	if d := m.Device; d != nil && !add(string(d.ID), string(d.ProjectID), d.Name) {
		return false
	}
	if c := m.Configuration; c != nil {
		if len(c.Tunnels) > config.MaxJSONBytes/128 || !add(string(c.Device.ID), string(c.Device.ProjectID), c.Device.Name) {
			return false
		}
		for _, t := range c.Tunnels {
			if !add(string(t.ID), string(t.DeviceID), string(t.Protocol), string(t.Listener), t.TargetAddr) {
				return false
			}
		}
	}
	return true
}

// Existing complete-device actor commits must honor the same identity retention.
func retainDeletedTunnels(prior, next *MemoryStore) error {
	if next.stateVersion < 3 {
		return nil
	}
	known := map[tombstone]bool{}
	for _, t := range next.management.Tombstones {
		known[t] = true
	}
	for id := range prior.tunnels {
		if _, exists := next.tunnels[id]; !exists {
			t := tombstone{"tunnel", string(id)}
			if !known[t] {
				if len(next.management.Tombstones) >= MaxMutationTombstones {
					return ErrTombstoneCapacity
				}
				next.management.Tombstones = append(next.management.Tombstones, t)
				known[t] = true
			}
		}
	}
	return nil
}

// LookupMutation verifies the retained canonical request digest without submitting
// actor work. Missing/expired receipts never authorize a new mutation.
func (o *ConfigOwner) LookupMutation(ctx context.Context, m Mutation) (MutationResult, error) {
	if !boundedMutation(m) || !config.ValidID(m.OperationID) {
		return MutationResult{}, config.ErrInvalidBusinessConfig
	}
	data, e := json.Marshal(m)
	if e != nil || len(data) > config.MaxJSONBytes {
		return MutationResult{}, config.ErrInvalidBusinessConfig
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	o.mu.RLock()
	defer o.mu.RUnlock()
	if e := ctx.Err(); e != nil {
		return MutationResult{}, e
	}
	if o.closed {
		return MutationResult{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return MutationResult{}, ErrCommitUncertain
	}
	for _, r := range o.current.management.Receipts {
		if r.OperationID == m.OperationID && r.RequestWindow == m.Window {
			if r.Digest != hash {
				return MutationResult{}, ErrOperationReuse
			}
			return receiptResult(o.current.management, r), nil
		}
	}
	return MutationResult{}, ErrOperationExpired
}
