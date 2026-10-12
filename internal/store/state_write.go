package store

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrCommitUncertain = errors.New("state commit uncertain; recovery required")

type stateTemp interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}
type stateDirectory interface {
	Sync() error
	Close() error
}
type stateFiles struct {
	createTemp func(string, string) (stateTemp, error)
	rename     func(string, string) error
	openDir    func(string) (stateDirectory, error)
	remove     func(string) error
}

func defaultStateFiles() stateFiles {
	return stateFiles{
		createTemp: func(dir, pattern string) (stateTemp, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
		openDir:    func(dir string) (stateDirectory, error) { return os.Open(dir) },
		remove:     os.Remove,
	}
}

func syncStateDirectory(path string, files stateFiles) error {
	dir, err := files.openDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	// Once Sync succeeds, a later Close error cannot undo confirmed durability.
	return dir.Sync()
}

func writeState(ctx context.Context, path string, data []byte, files stateFiles) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := secureStateDir(path); err != nil {
		return err
	}
	if err := privateFile(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := files.createTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer files.remove(f.Name())
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = files.rename(f.Name(), path); err != nil {
		return err
	}
	// Rename has succeeded. Cancellation no longer establishes an abort: every
	// failure until directory Sync confirmation has uncertain durable outcome.
	if err = syncStateDirectory(path, files); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}
