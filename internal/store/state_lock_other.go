//go:build !linux

package store

import "errors"

func LockState(string) (func() error, error) {
	return nil, errors.New("local state locking is supported on Linux only")
}
