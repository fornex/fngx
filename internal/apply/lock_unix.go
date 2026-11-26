//go:build unix

package apply

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// fileLock is an exclusive flock(2) on a file. flock locks belong to the
// open file description, so two opens of the same file conflict even within
// one process; this serialises goroutines and processes alike (A-6).
type fileLock struct {
	f *os.File
}

func lockFile(ctx context.Context, path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600) //nolint:gosec // path comes from engine config
	if err != nil {
		return nil, err
	}
	delay := 10 * time.Millisecond
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // fd fits in int
		if err == nil {
			return &fileLock{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, err
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = f.Close()
			return nil, ctx.Err()
		case <-t.C:
		}
		if delay < 200*time.Millisecond {
			delay *= 2
		}
	}
}

// unlock releases the lock. Closing the descriptor releases it as well; the
// explicit LOCK_UN only makes the intent obvious.
func (l *fileLock) unlock() error {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) //nolint:gosec // fd fits in int
	return l.f.Close()
}
