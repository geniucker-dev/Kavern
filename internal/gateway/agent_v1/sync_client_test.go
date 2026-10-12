package agent_v1

import (
	"context"
	"github.com/geniucker-dev/kavern/internal/domain"
	"testing"
	"time"
)

func TestWaitAppliedRequiresACKAndReturnsCopy(t *testing.T) {
	auth := codecAuth(t)
	r := receiverFixture(t, auth, nil)
	p := planFixture(t, auth, 1, 1, "a")
	result := make(chan domain.NativeSnapshot, 1)
	go func() { snapshot, _ := r.WaitApplied(context.Background(), 0); result <- snapshot }()
	for i := 0; i < p.frames(); i++ {
		e := wireEvent(t, p.frame(i))
		if _, err := r.accept(e.frame, e.bytes); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-result:
		t.Fatal("partial/unacknowledged snapshot exposed")
	default:
	}
	r.ackSent()
	select {
	case snapshot := <-result:
		snapshot.Tunnels[0].TargetAddr = "caller"
		current, _ := r.Snapshot()
		if current.Tunnels[0].TargetAddr == "caller" {
			t.Fatal("resolver aliases caller")
		}
	case <-time.After(time.Second):
		t.Fatal("ACK did not wake supervisor")
	}
	if _, ok := r.ReadySnapshot(); ok {
		t.Fatal("ACK mistaken for readiness")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.WaitApplied(ctx, 1); err == nil {
		t.Fatal("canceled supervisor waits")
	}
	r.Close()
	if _, err := r.WaitApplied(context.Background(), 1); err == nil {
		t.Fatal("closed receiver waits")
	}
}
