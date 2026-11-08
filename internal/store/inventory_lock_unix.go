//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const localConditionsSupported = true

func localLock(ctx context.Context, path string, fn func() error) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		err = syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer syscall.Flock(int(dir.Fd()), syscall.LOCK_UN) //nolint:errcheck
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}
