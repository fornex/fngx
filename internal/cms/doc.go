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
//   - never follows symbolic links: the document root itself is opened
//     with O_NOFOLLOW, every directory below it is opened with openat and
//     O_NOFOLLOW relative to its parent's file descriptor, and every
//     marker is checked with fstatat and AT_SYMLINK_NOFOLLOW. A symlink in
//     place of a marker counts as absent and is reported in
//     Result.Ignored. The path is never resolved by name again after the
//     document root is opened, so ".." or a symlink cannot lead outside;
//   - never lists a directory and never recurses: it probes a fixed list
//     of relative paths, so the number of system calls per site has a
//     fixed upper bound (maxOps) whatever the tree looks like;
//   - reads file contents only where a layout check is not enough (two
//     files: index.php and index.html), only the first few KiB, only
//     regular files, only files owned by the owner of the document root
//     (so a hard link to a root-owned or another user's file is not
//     read), and never configuration files with secrets (wp-config.php,
//     configuration.php, config.php, .env are only checked for presence);
//   - opens files with O_NONBLOCK and O_NOCTTY and checks the type with
//     fstatat before the open and fstat after it, so a FIFO or a device
//     node is never read and an open never waits for a FIFO writer;
//   - treats file contents as untrusted bytes: it only searches the
//     prefix for fixed substrings, it does not parse PHP, HTML or JSON;
//   - never puts file contents into its result: only relative marker
//     paths that the rules themselves define.
//
// # Races (TOCTOU)
//
// Covered: a marker swapped for a symlink, a FIFO or another file between
// the fstatat and the open is caught by O_NOFOLLOW and by comparing the
// device and inode of fstatat and fstat. A directory renamed or replaced
// by a symlink after it was opened does not matter: the file descriptor
// still refers to the same inode, and openat never walks "..".
//
// Not covered: the client can change the tree between two probes, so a
// result may mix states of the tree (for example report WordPress while
// the client is replacing it); the result is only a suggestion, so this
// is accepted. A directory moved out of the document root while
// detection holds its descriptor is still read, but the client can only
// move it within its own files. A read from a regular file on a hung
// network or FUSE file system can block; system calls cannot be
// cancelled, so callers that scan many sites should run detection in
// worker goroutines with a per-site deadline and give up on the result,
// not on the goroutine.
//
// Follow-up, not implemented: switching to the site owner's identity
// (setfsuid or a helper process) before probing would add a second
// barrier on top of the checks above.
package cms
