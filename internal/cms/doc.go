// SPDX-License-Identifier: GPL-3.0-or-later

// Package cms detects which web application is installed in a site's
// document root and suggests a matching application template (T-2, T-10).
//
// Detection only suggests: it never writes, renames, chmods or otherwise
// changes anything, and it never assigns a template. The caller shows the
// suggestion; the administrator or the client decides.
//
// The rules, the files they look for and the public sources they are
// based on are listed in rules.go and in docs/cms-detection.md.
//
// # Threat model
//
// Detection runs as root over directories that belong to untrusted
// hosting clients, on servers with up to 10,000 sites (N-1). A client
// controls every name, link, file type and byte under the document root
// and may change them while detection runs. The package therefore:
//
//   - takes the site owner's uid from the caller (the system user
//     database), never from the tree: the document root must be owned by
//     that uid; below it, a directory is entered and a file is read only
//     if the uid owns it or everyone may search or read it, so detection
//     sees nothing the client could not. A hard link to root's or another
//     user's private file, or another user's private directory moved into
//     the client's tree, is skipped;
//   - wraps every error in ErrUnavailable; the details are for the
//     server log, not for the client;
//   - never follows symbolic links: the document root must be a clean
//     path (a trailing "/" or "/." would make the kernel follow a final
//     symlink despite O_NOFOLLOW) and is opened with O_NOFOLLOW; every
//     directory below it is opened with openat and O_NOFOLLOW relative to
//     its parent's file descriptor, and every marker is checked with
//     fstatat and AT_SYMLINK_NOFOLLOW. A symlink in place of a marker
//     counts as absent and is reported in Result.Ignored. Paths are never
//     resolved by name below the document root, and ".." is never walked;
//   - never lists a directory and never recurses: it probes a fixed list
//     of relative paths, so the number of system calls per site has a
//     fixed upper bound (maxOps) whatever the tree looks like;
//   - reads file contents only where a layout check is not enough (two
//     files: index.php and index.html), only the first few KiB, only
//     regular files, and never configuration files with secrets
//     (wp-config.php, configuration.php, config.php, .env are only
//     checked for presence);
//   - on Linux opens a file first with O_PATH, which runs no open routine,
//     checks type, owner, device and inode with fstat, and only then
//     reopens that same inode for reading through /proc/self/fd with
//     O_NONBLOCK, O_NOCTTY and O_NOATIME. A FIFO or device node is never
//     opened for reading and the access time is not changed. (Other
//     systems, used only for development, open first and check after.)
//   - treats file contents as untrusted bytes: it only searches the
//     prefix for fixed substrings, it does not parse PHP, HTML or JSON;
//   - never puts file contents into its result: only relative marker
//     paths that the rules themselves define.
//
// # Races (TOCTOU)
//
// Covered: a marker swapped for a symlink, a FIFO, a device or another
// file between the fstatat and the open is caught by O_NOFOLLOW and by
// comparing type, owner, device and inode before reading. A directory
// renamed or replaced by a symlink after it was opened does not matter:
// the file descriptor still refers to the same inode, and openat never
// walks "..".
//
// Not covered: the client can change the tree between two probes, so a
// result may mix states of the tree (for example report WordPress while
// the client is replacing it); the result is only a suggestion, so this
// is accepted. A directory moved out of the document root while
// detection holds its descriptor is still read, but it must still be
// owned by the client. The client can notice that a scan runs (inotify,
// file leases); it learns nothing else. A system call on a hung network
// or FUSE file system can block and cannot be cancelled: a goroutine
// given up on after a deadline keeps its descriptors until the call
// returns. Batch callers should bound the number of outstanding scans,
// or better run detection in a child process they can kill.
//
// Follow-up, not implemented: run detection in a helper process with the
// site owner's identity (and a hard timeout) as a second barrier.
package cms
