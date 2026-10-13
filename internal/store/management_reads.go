package store

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/config"
	"github.com/geniucker-dev/kavern/internal/domain"
	"sort"
)

type RecordPage struct {
	Users    []domain.User
	Projects []domain.Project
	Devices  []domain.Device
	Next     string
}

func (o *ConfigOwner) ManagementHealth(ctx context.Context) (string, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if ctx.Err() != nil {
		return "unavailable", o.work.RevokedCount() > 0
	}
	if o.closed {
		return "closed", o.work.RevokedCount() > 0
	}
	if o.uncertain {
		return "commit_uncertain", o.work.RevokedCount() > 0
	}
	return "running", o.work.RevokedCount() > 0
}
func (o *ConfigOwner) ListRecords(ctx context.Context, kind, after, parent string) (RecordPage, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if e := ctx.Err(); e != nil {
		return RecordPage{}, e
	}
	if o.closed {
		return RecordPage{}, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return RecordPage{}, ErrCommitUncertain
	}
	if (after != "" && !config.ValidID(after)) || (parent != "" && !config.ValidID(parent)) {
		return RecordPage{}, config.ErrInvalidBusinessConfig
	}
	ids := []string{}
	switch kind {
	case "users":
		if parent != "" {
			return RecordPage{}, config.ErrInvalidBusinessConfig
		}
		for id := range o.current.users {
			if string(id) > after {
				ids = append(ids, string(id))
			}
		}
	case "projects":
		for id, p := range o.current.projects {
			if string(id) > after && (parent == "" || string(p.UserID) == parent) {
				ids = append(ids, string(id))
			}
		}
	case "devices":
		for id, d := range o.current.devices {
			if string(id) > after && (parent == "" || string(d.ProjectID) == parent) {
				ids = append(ids, string(id))
			}
		}
	default:
		return RecordPage{}, config.ErrInvalidBusinessConfig
	}
	sort.Strings(ids)
	p := RecordPage{}
	if len(ids) > config.AdminPageSize {
		ids = ids[:config.AdminPageSize]
		p.Next = ids[len(ids)-1]
	}
	for _, id := range ids {
		switch kind {
		case "users":
			p.Users = append(p.Users, o.current.users[domain.UserID(id)])
		case "projects":
			p.Projects = append(p.Projects, o.current.projects[domain.ProjectID(id)])
		case "devices":
			p.Devices = append(p.Devices, o.current.devices[domain.DeviceID(id)])
		}
	}
	return p, nil
}
func (o *ConfigOwner) DeviceUser(ctx context.Context, id domain.DeviceID) (domain.UserID, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if o.closed {
		return "", ErrConfigOwnerClosed
	}
	if o.uncertain {
		return "", ErrCommitUncertain
	}
	d, ok := o.current.devices[id]
	if !ok {
		return "", ErrNotFound
	}
	p, ok := o.current.projects[d.ProjectID]
	if !ok {
		return "", ErrNotFound
	}
	return p.UserID, nil
}

func (o *ConfigOwner) DeviceCleanupPending(id domain.DeviceID) bool {
	return o.work.RevokedDeviceCount(id) > 0
}

// DeviceCredentialKinds reports stored kinds even when offline or disabled. It
// never authenticates, resolves enabled-only credentials or returns material.
func (o *ConfigOwner) DeviceCredentialKinds(ctx context.Context, id domain.DeviceID) ([]domain.CredentialKind, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if o.closed {
		return nil, ErrConfigOwnerClosed
	}
	if o.uncertain {
		return nil, ErrCommitUncertain
	}
	if _, ok := o.current.devices[id]; !ok {
		return nil, ErrNotFound
	}
	kinds := []domain.CredentialKind{}
	if _, ok := o.current.kapv1Secret[id]; ok {
		kinds = append(kinds, domain.CredentialKindKAPv1DeviceSecret)
	}
	for _, c := range o.current.credentials {
		if c.DeviceID == id && c.Kind == domain.CredentialKindLegacyNPC {
			kinds = append(kinds, domain.CredentialKindLegacyNPC)
			break
		}
	}
	return kinds, nil
}
