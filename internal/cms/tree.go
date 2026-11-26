// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// maxOps bounds the file system operations (openat, fstatat) one
// detection may perform. The rules need far fewer (see
// TestOpsBudget_N1); the limit is a backstop, not a tuning knob.
const maxOps = 96

// maxIgnored bounds Result.Ignored.
const maxIgnored = 32

// errBudget is returned when maxOps is exhausted.
var errBudget = errors.New("operation budget exhausted")

// kind is the type of a directory entry as seen without following links.
type kind uint8

const (
	kindMissing kind = iota
	kindFile         // regular file
	kindDir
	kindSymlink
	kindOther // FIFO, socket, device
	kindError // the probe failed for another reason, see Result.Ignored
)

func (k kind) String() string {
	switch k {
	case kindMissing:
		return "missing"
	case kindFile:
		return "regular file"
	case kindDir:
		return "directory"
	case kindSymlink:
		return "symbolic link"
	case kindOther:
		return "special file"
	default:
		return "error"
	}
}

// Ignored is a marker path that exists but was not used, with the reason.
type Ignored struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type dirEntry struct {
	fd  int // -1 if the open failed
	err error
}

type statEntry struct {
	k  kind
	st unix.Stat_t
}

// tree is a read-only view of one document root through file
// descriptors. It is not safe for concurrent use.
type tree struct {
	rootFD  int
	rootUID uint32
	dirs    map[string]dirEntry // relative directory path -> descriptor
	stats   map[string]statEntry
	reads   map[string][]byte // nil value: the read was refused
	ops     int
	ignored []Ignored
	seen    map[string]bool // paths already in ignored
}

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
)

// openTree opens the document root. The final path component must be a
// real directory, not a symlink; the components above it are resolved
// normally and must be trusted by the caller (see Detect and DetectUnder).
func openTree(docroot string) (*tree, error) {
	if docroot == "" || docroot[0] != '/' {
		return nil, fmt.Errorf("document root %q: must be an absolute path", docroot)
	}
	fd, err := openRetry(unix.AT_FDCWD, docroot, dirFlags)
	if err != nil {
		return nil, fmt.Errorf("document root %q: %w", docroot, describe(err))
	}
	return newTree(fd)
}

// openTreeUnder opens base, which the caller trusts, and then walks rel
// one component at a time without following symlinks.
func openTreeUnder(base, rel string) (*tree, error) {
	if base == "" || base[0] != '/' {
		return nil, fmt.Errorf("base %q: must be an absolute path", base)
	}
	parts, err := splitRel(rel)
	if err != nil {
		return nil, err
	}
	fd, err := openRetry(unix.AT_FDCWD, base, dirFlags&^unix.O_NOFOLLOW)
	if err != nil {
		return nil, fmt.Errorf("base %q: %w", base, describe(err))
	}
	for i, p := range parts {
		next, err := openRetry(fd, p, dirFlags)
		_ = unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("document root %q: component %q: %w", rel, strings.Join(parts[:i+1], "/"), describe(err))
		}
		fd = next
	}
	return newTree(fd)
}

func newTree(fd int) (*tree, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("document root: %w", err)
	}
	return &tree{
		rootFD:  fd,
		rootUID: st.Uid,
		dirs:    map[string]dirEntry{"": {fd: fd}},
		stats:   map[string]statEntry{},
		reads:   map[string][]byte{},
		seen:    map[string]bool{},
	}, nil
}

func (t *tree) close() {
	for _, d := range t.dirs {
		if d.fd >= 0 {
			_ = unix.Close(d.fd)
		}
	}
	t.dirs = nil
}

// splitRel validates a relative path made of plain names.
func splitRel(rel string) ([]string, error) {
	if rel == "" {
		return nil, nil
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.IndexByte(p, 0) >= 0 {
			return nil, fmt.Errorf("relative path %q: empty, \".\" or \"..\" component", rel)
		}
	}
	return parts, nil
}

func (t *tree) spend() error {
	if t.ops >= maxOps {
		return errBudget
	}
	t.ops++
	return nil
}

func (t *tree) ignore(path, reason string) {
	if t.seen[path] || len(t.ignored) >= maxIgnored {
		return
	}
	t.seen[path] = true
	t.ignored = append(t.ignored, Ignored{Path: path, Reason: reason})
}

// dir returns a descriptor for the relative directory path, opening each
// component with O_NOFOLLOW relative to its parent.
func (t *tree) dir(rel string) (int, error) {
	if d, ok := t.dirs[rel]; ok {
		return d.fd, d.err
	}
	parent, name := "", rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		parent, name = rel[:i], rel[i+1:]
	}
	pfd, err := t.dir(parent)
	if err != nil {
		t.dirs[rel] = dirEntry{fd: -1, err: err}
		return -1, err
	}
	if err := t.spend(); err != nil {
		return -1, err
	}
	fd, err := openRetry(pfd, name, dirFlags)
	if err != nil {
		t.dirs[rel] = dirEntry{fd: -1, err: err}
		if !isAbsent(err) {
			t.ignore(rel, describe(err).Error())
		}
		return -1, err
	}
	t.dirs[rel] = dirEntry{fd: fd}
	return fd, nil
}

// stat returns the kind of the entry at rel without following symlinks.
func (t *tree) stat(rel string) statEntry {
	if e, ok := t.stats[rel]; ok {
		return e
	}
	e := t.statUncached(rel)
	t.stats[rel] = e
	switch e.k {
	case kindSymlink:
		t.ignore(rel, "symbolic link, not followed")
	case kindOther:
		t.ignore(rel, "special file (FIFO, socket or device)")
	}
	return e
}

func (t *tree) statUncached(rel string) statEntry {
	parent, name := "", rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		parent, name = rel[:i], rel[i+1:]
	}
	pfd, err := t.dir(parent)
	if err != nil {
		if errors.Is(err, errBudget) {
			t.ignore(rel, errBudget.Error())
		}
		return statEntry{k: kindMissing}
	}
	if err := t.spend(); err != nil {
		t.ignore(rel, err.Error())
		return statEntry{k: kindMissing}
	}
	var st unix.Stat_t
	if err := fstatatRetry(pfd, name, &st); err != nil {
		if isAbsent(err) {
			return statEntry{k: kindMissing}
		}
		t.ignore(rel, describe(err).Error())
		return statEntry{k: kindError}
	}
	return statEntry{k: kindOf(st.Mode), st: st}
}

func kindOf[M uint16 | uint32](mode M) kind {
	switch uint32(mode) & unix.S_IFMT {
	case unix.S_IFREG:
		return kindFile
	case unix.S_IFDIR:
		return kindDir
	case unix.S_IFLNK:
		return kindSymlink
	default:
		return kindOther
	}
}

// readPrefix returns at most limit bytes from the start of the regular
// file at rel, or nil if the file is missing or must not be read.
func (t *tree) readPrefix(rel string, limit int) []byte {
	if b, ok := t.reads[rel]; ok {
		return b
	}
	b := t.readUncached(rel, limit)
	t.reads[rel] = b
	return b
}

func (t *tree) readUncached(rel string, limit int) []byte {
	pre := t.stat(rel)
	if pre.k != kindFile {
		return nil
	}
	if pre.st.Uid != t.rootUID {
		t.ignore(rel, "owner differs from the document root owner, not read")
		return nil
	}
	parent, name := "", rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		parent, name = rel[:i], rel[i+1:]
	}
	pfd, err := t.dir(parent)
	if err != nil {
		return nil
	}
	if err := t.spend(); err != nil {
		t.ignore(rel, err.Error())
		return nil
	}
	fd, err := openRetry(pfd, name, fileFlags)
	if err != nil {
		t.ignore(rel, "open: "+describe(err).Error())
		return nil
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.ignore(rel, "fstat: "+err.Error())
		return nil
	}
	if kindOf(st.Mode) != kindFile || st.Dev != pre.st.Dev || st.Ino != pre.st.Ino || st.Uid != t.rootUID {
		t.ignore(rel, "changed while being checked, not read")
		return nil
	}
	buf := make([]byte, limit)
	n := 0
	for n < limit {
		m, err := unix.Read(fd, buf[n:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.ignore(rel, "read: "+err.Error())
			return nil
		}
		if m <= 0 {
			break
		}
		n += m
	}
	return buf[:n]
}

// isAbsent reports errors that mean "this path does not lead to an
// entry": missing, a non-directory in the middle of the path, or a
// symlink where a directory was expected (ELOOP from O_NOFOLLOW; on
// some systems O_DIRECTORY|O_NOFOLLOW on a symlink gives ENOTDIR).
func isAbsent(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP)
}

// describe turns well-known errors into short reasons.
func describe(err error) error {
	switch {
	case errors.Is(err, unix.ELOOP):
		return errors.New("symbolic link, not followed")
	case errors.Is(err, unix.ENOTDIR):
		return errors.New("not a directory")
	case errors.Is(err, unix.ENOENT):
		return errors.New("does not exist")
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return errors.New("permission denied")
	}
	return err
}

func openRetry(dirfd int, name string, flags int) (int, error) {
	for {
		fd, err := unix.Openat(dirfd, name, flags, 0)
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

func fstatatRetry(dirfd int, name string, st *unix.Stat_t) error {
	for {
		err := unix.Fstatat(dirfd, name, st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
