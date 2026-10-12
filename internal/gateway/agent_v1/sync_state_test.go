package agent_v1

import (
	"errors"
	"testing"
	"time"

	"github.com/geniucker-dev/kavern/internal/domain"
)

func receiverFixture(t *testing.T, auth SyncAuthResult, budget *SyncStagingBudget) *ConfigReceiver {
	t.Helper()
	r, err := NewConfigReceiver(auth, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}
func acceptEvent(t *testing.T, r *ConfigReceiver, f syncFrame) *syncFrame {
	t.Helper()
	e := wireEvent(t, f)
	ack, err := r.accept(e.frame, e.bytes)
	if err != nil {
		t.Fatal(err)
	}
	return ack
}
func installPlan(t *testing.T, r *ConfigReceiver, p *syncPlan) syncFrame {
	t.Helper()
	var ack *syncFrame
	for i := 0; i < p.frames(); i++ {
		ack = acceptEvent(t, r, p.frame(i))
	}
	if ack == nil || ack.tuple() != p.tuple {
		t.Fatal("missing exact application ACK")
	}
	r.ackSent()
	return *ack
}

func TestSyncReceiverAtomicReplacementEmptyReconnectAndCopies(t *testing.T) {
	auth := codecAuth(t)
	budget := &SyncStagingBudget{}
	r := receiverFixture(t, auth, budget)
	first := planFixture(t, auth, 1, 1, "a", "b")
	installPlan(t, r, first)
	second := planFixture(t, auth, 2, 2, "b")
	acceptEvent(t, r, second.frame(0))
	acceptEvent(t, r, second.frame(1))
	got, ok := r.Snapshot()
	if !ok || got.Revision != 1 || len(got.Tunnels) != 2 {
		t.Fatal("partial transfer changed applied map")
	}
	got.Tunnels[0].TargetAddr = "caller mutation"
	got, _ = r.Snapshot()
	if got.Tunnels[0].TargetAddr == "caller mutation" {
		t.Fatal("applied map aliases caller")
	}
	ack := acceptEvent(t, r, second.frame(2))
	if ack == nil || ack.tuple() != second.tuple {
		t.Fatal("wrong replacement ACK")
	}
	r.ackSent()
	got, ok = r.Snapshot()
	if !ok || got.Revision != 2 || len(got.Tunnels) != 1 || got.Tunnels[0].ID != "b" {
		t.Fatal("omission did not replace full map")
	}
	installPlan(t, r, planFixture(t, auth, 3, 3))
	got, ok = r.Snapshot()
	if !ok || got.Revision != 3 || len(got.Tunnels) != 0 {
		t.Fatal("empty configuration not installed")
	}
	if budget.Used() != 0 {
		t.Fatal("completed transfer retained reservation")
	}
	r.Close()
	if _, ok = r.Snapshot(); ok {
		t.Fatal("closed receiver retained applied map")
	}
	reconnected := codecAuth(t)
	fresh := receiverFixture(t, reconnected, budget)
	if _, ok = fresh.Snapshot(); ok {
		t.Fatal("reconnect inherited applied state")
	}
	installPlan(t, fresh, planFixture(t, reconnected, 3, 1))
	got, ok = fresh.Snapshot()
	if !ok || got.Revision != 3 {
		t.Fatal("same revision reconnect did not resync")
	}
}

func TestSyncReceiverRejectsMalformedOrderAndStaleTuples(t *testing.T) {
	for name, mutate := range map[string]func(*syncFrame){
		"wrong-device":   func(f *syncFrame) { f.DeviceID = "other" },
		"wrong-session":  func(f *syncFrame) { f.SessionID = domain.SessionID(mustNonce(t)) },
		"wrong-revision": func(f *syncFrame) { r := domain.ConfigRevision(2); f.Revision = &r },
		"wrong-transfer": func(f *syncFrame) { r := domain.ConfigRevision(2); f.TransferID = &r },
		"wrong-index":    func(f *syncFrame) { index := uint16(1); f.Index = &index },
	} {
		t.Run(name, func(t *testing.T) {
			auth := codecAuth(t)
			budget := &SyncStagingBudget{}
			r := receiverFixture(t, auth, budget)
			p := planFixture(t, auth, 1, 1, "a", "b")
			acceptEvent(t, r, p.frame(0))
			frame := p.frame(1)
			mutate(&frame)
			e := wireEvent(t, frame)
			if _, err := r.accept(e.frame, e.bytes); err == nil {
				t.Fatal("invalid transfer accepted")
			}
			if budget.Used() != 0 {
				t.Fatal("failed transfer retained budget")
			}
			if _, ok := r.Snapshot(); ok {
				t.Fatal("failed transfer installed map")
			}
		})
	}
	for _, kind := range []string{"premature-end", "duplicate-entry", "duplicate-begin", "wrong-total"} {
		t.Run(kind, func(t *testing.T) {
			auth := codecAuth(t)
			budget := &SyncStagingBudget{}
			r := receiverFixture(t, auth, budget)
			p := planFixture(t, auth, 1, 1, "a", "b")
			acceptEvent(t, r, p.frame(0))
			var f syncFrame
			switch kind {
			case "premature-end":
				f = p.frame(p.frames() - 1)
			case "duplicate-begin":
				f = p.frame(0)
			case "duplicate-entry":
				acceptEvent(t, r, p.frame(1))
				f = p.frame(1)
			case "wrong-total":
				acceptEvent(t, r, p.frame(1))
				acceptEvent(t, r, p.frame(2))
				f = p.frame(3)
				n := *f.TotalBytes + 1
				f.TotalBytes = &n
			}
			e := wireEvent(t, f)
			if _, err := r.accept(e.frame, e.bytes); err == nil {
				t.Fatal("malformed sequence accepted")
			}
			if budget.Used() != 0 {
				t.Fatal("malformed sequence leaked budget")
			}
		})
	}
}

func TestSyncReceiverAbsoluteDeadlineAndBackloggedBegin(t *testing.T) {
	auth := codecAuth(t)
	budget := &SyncStagingBudget{}
	r := receiverFixture(t, auth, budget)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	p := planFixture(t, auth, 1, 1, "a", "b")
	acceptEvent(t, r, p.frame(0))
	deadline := r.deadline()
	now = now.Add(9 * time.Second)
	acceptEvent(t, r, p.frame(1))
	if r.deadline() != deadline {
		t.Fatal("progress extended absolute deadline")
	}
	now = now.Add(time.Second)
	e := wireEvent(t, p.frame(2))
	if _, err := r.accept(e.frame, e.bytes); !errors.Is(err, ErrSyncDeadline) {
		t.Fatal("deadline boundary accepted", err)
	}
	if budget.Used() != 0 {
		t.Fatal("timeout retained budget")
	}
	r = receiverFixture(t, auth, budget)
	r.now = func() time.Time { return now }
	begin := wireEvent(t, p.frame(0))
	if _, err := r.acceptAt(begin.frame, begin.bytes, now.Add(-11*time.Second)); !errors.Is(err, ErrSyncDeadline) {
		t.Fatal("backlogged begin got fresh deadline", err)
	}
}

func TestSyncAggregateStagingCapacityAndDeclaredCountLowerBound(t *testing.T) {
	budget := &SyncStagingBudget{}
	var receivers []*ConfigReceiver
	for i := 0; i < MaxSyncStagingBytes/MaxSyncTransferBytes; i++ {
		auth := codecAuth(t)
		r := receiverFixture(t, auth, budget)
		p := planFixture(t, auth, 1, 1)
		begin := p.frame(0)
		n := uint32(MaxSyncTransferBytes)
		begin.TotalBytes = &n
		acceptEvent(t, r, begin)
		receivers = append(receivers, r)
	}
	if budget.Used() != MaxSyncStagingBytes {
		t.Fatal("aggregate reservation wrong")
	}
	auth := codecAuth(t)
	extra := receiverFixture(t, auth, budget)
	p := planFixture(t, auth, 1, 1)
	begin := p.frame(0)
	n := uint32(MaxSyncTransferBytes)
	begin.TotalBytes = &n
	e := wireEvent(t, begin)
	if _, err := extra.accept(e.frame, e.bytes); !errors.Is(err, ErrSyncCapacity) {
		t.Fatal("aggregate limit bypassed", err)
	}
	for _, r := range receivers {
		r.Close()
	}
	if budget.Used() != 0 {
		t.Fatal("disconnect leaked aggregate reservation")
	}
	r := receiverFixture(t, auth, budget)
	begin = p.frame(0)
	count := uint16(1024)
	begin.Count = &count
	e = wireEvent(t, begin)
	if _, err := r.accept(e.frame, e.bytes); !errors.Is(err, ErrSyncTransfer) {
		t.Fatal("small declaration allocated large staging map", err)
	}
	if budget.Used() != 0 {
		t.Fatal("invalid declaration reserved memory")
	}
}
