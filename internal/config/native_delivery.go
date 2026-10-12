package config

import (
	"encoding/json"
	"github.com/geniucker-dev/kavern/internal/domain"
)

// Delivery reservations make accepted native projections sendable at every
// revision/transfer counter width. Business state retains no wire frame types,
// session identities or negotiated state. These fixed reservations cover the
// current lifecycle-v1 adapter; its codec tests prove they dominate real bytes.
// Record overhead includes a 43-character session, two maximal uint64 counters,
// index 1023, TCP and all fixed envelope keys/versions. Bookends include count
// 1024, seven-digit total, maximal counters, session and bounded carrier policy.
const nativeDeliveryRecordOverhead = 300
const nativeDeliveryBookendsOverhead = 1024

func ValidateNativeDeliveryCapacity(s domain.NativeSnapshot) error {
	device, err := json.Marshal(s.DeviceID)
	if err != nil {
		return ErrInvalidBusinessConfig
	}
	total := nativeDeliveryBookendsOverhead + 2*len(device)
	for _, t := range s.Tunnels {
		id, e := json.Marshal(t.ID)
		if e != nil {
			return ErrInvalidBusinessConfig
		}
		target, e := json.Marshal(t.TargetAddr)
		if e != nil {
			return ErrInvalidBusinessConfig
		}
		total += nativeDeliveryRecordOverhead + len(device) + len(id) + len(target)
		if total > MaxNativeSnapshotBytes {
			return ErrInvalidBusinessConfig
		}
	}
	if total > MaxNativeSnapshotBytes {
		return ErrInvalidBusinessConfig
	}
	return nil
}
