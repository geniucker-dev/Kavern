package store

import (
	"errors"
	"os"
	"syscall"
)

// LockState is held throughout daemon execution and each offline CLI mutation.
// Mutations while the daemon is running fail instead of silently losing updates.
func LockState(path string) (func() error, error) {
	if err := secureStateDir(path); err != nil {
		return nil, err
	}
	lockPath := path + ".lock"
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), lockPath)
	if err = privateFile(lockPath); err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("local state is already in use")
	}
	return func() error { _ = syscall.Flock(fd, syscall.LOCK_UN); return f.Close() }, nil
}
