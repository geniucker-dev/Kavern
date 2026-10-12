package agent_v1

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestRuntimeStatusIsRedactedAndSeparatesACKFromReady(t *testing.T) {
	owner, svc, _, secret := syncOwnedFixture(t)
	ctx := context.Background()
	auth := syncAuthFixture(t, svc, secret)
	if _, e := svc.NewConfigServer(ctx, auth, owner, nil); e != nil {
		t.Fatal(e)
	}
	entry, _ := svc.registry.lookup(auth.SessionID)
	snapshot, e := owner.NativeSnapshot(ctx, auth.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	tuple := syncTuple{DeviceID: auth.DeviceID, SessionID: auth.SessionID, Revision: snapshot.Revision, TransferID: 1}
	data := entry.session.syncController()
	data.install(tuple, snapshot)
	data.ack(tuple)
	status := svc.DeviceRuntimeStatus(ctx, auth.DeviceID)
	if !status.Present || status.AppliedRevision != snapshot.Revision || status.Ready || status.Carriers != 0 {
		t.Fatal("ACK mislabeled ready")
	}
	encoded, e := json.Marshal(status)
	if e != nil || bytes.Contains(encoded, secret) || bytes.Contains(encoded, []byte(auth.SessionID)) {
		t.Fatal("private authentication state exposed")
	}
	svc.CloseSession(ctx, auth.SessionID)
	if svc.DeviceRuntimeStatus(ctx, auth.DeviceID).Present {
		t.Fatal("closed session reported present")
	}
}
