//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package store

import "context"

// Ordinary link-not-replace writes and unconditioned deletes are atomic without a lock.
// Conditional cleanup is unavailable on platforms without the directory-lock implementation.
const localConditionsSupported = false

func localLock(ctx context.Context, _ string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}
