// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

// noatime keeps reads from updating the access time, so detection
// leaves no trace in the client's files. Root may set it on any file.
const noatime = unix.O_NOATIME

// openRegular opens name relative to dirfd for reading without ever
// opening anything that check rejects. The entry is first opened with
// O_PATH, which pins the inode without calling the file's open routine
// (no FIFO wait, no device driver side effects); check sees its fstat;
// only then is the same inode reopened for reading through
// /proc/self/fd.
func openRegular(dirfd int, name string, check func(*unix.Stat_t) error) (int, error) {
	pfd, err := openRetry(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(pfd) }()
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return -1, err
	}
	if err := check(&st); err != nil {
		return -1, err
	}
	proc := "/proc/self/fd/" + strconv.Itoa(pfd)
	fd, err := openRetry(unix.AT_FDCWD, proc, fileFlags&^unix.O_NOFOLLOW)
	if errors.Is(err, unix.EPERM) {
		// O_NOATIME needs file ownership or CAP_FOWNER.
		fd, err = openRetry(unix.AT_FDCWD, proc, fileFlags&^(unix.O_NOFOLLOW|unix.O_NOATIME))
	}
	if err != nil {
		return -1, err
	}
	// /proc/self/fd/N refers to the pinned inode, so this cannot differ;
	// checked anyway in case /proc is not what it should be.
	if err := fstatCheck(fd, check); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
