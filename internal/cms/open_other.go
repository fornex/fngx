// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package cms

import "golang.org/x/sys/unix"

// noatime is Linux-only.
const noatime = 0

// openRegular opens name relative to dirfd for reading and rejects it if
// check fails on the opened file. Without O_PATH the open itself happens
// before the check: O_NONBLOCK keeps a FIFO from blocking, but a device
// node's open routine runs. Production runs on Linux (open_linux.go).
func openRegular(dirfd int, name string, check func(*unix.Stat_t) error) (int, error) {
	fd, err := openRetry(dirfd, name, fileFlags)
	if err != nil {
		return -1, err
	}
	if err := fstatCheck(fd, check); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
