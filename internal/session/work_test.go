package session

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
	"testing"
)

func TestWorkRegistryCollectGatesReuseAndSupportsCleanupRetry(t *testing.T) {
	s := NewWorkSet(1)
	scope := domain.WorkScope{DeviceID: "d", TunnelID: "t"}
	w, err := s.Register(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if s.Existing(w.Context, scope) != w {
		t.Fatal("registration not reused")
	}
	selected := s.Collect(func(domain.WorkScope) bool { return true })
	if w.Context.Err() != nil {
		t.Fatal("publication canceled inside guard")
	}
	if s.Existing(w.Context, scope) != nil {
		t.Fatal("revoked work reused")
	}
	if len(s.Collect(func(domain.WorkScope) bool { return true })) != 1 {
		t.Fatal("cleanup retry lost outstanding work")
	}
	go func() { <-w.Context.Done(); w.Finish() }()
	if err = CancelAndJoin(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	w.Finish()
	if s.Count() != 0 {
		t.Fatal("registration leaked")
	}
}
