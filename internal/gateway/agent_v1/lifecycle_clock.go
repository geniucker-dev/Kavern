package agent_v1

import (
	"time"
)

// Clock deadlines are process-local monotonic instants. AfterFunc must not run
// its callback inline; callbacks run without clock locks and may race Stop.
// Stop is nonblocking, so generation tickets still guard already-fired callbacks.
type LifecycleTimer interface{ Stop() bool }
type LifecycleClock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) LifecycleTimer
}
type realLifecycleClock struct{}

func (realLifecycleClock) Now() time.Time { return time.Now() }
func (realLifecycleClock) AfterFunc(d time.Duration, f func()) LifecycleTimer {
	return time.AfterFunc(d, f)
}
func NewLifecycleClock() LifecycleClock { return realLifecycleClock{} }
