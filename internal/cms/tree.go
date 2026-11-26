// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// maxOps bounds the file system operations (openat, fstatat) one
// detection may perform. The rules need far fewer (see
// TestOpsBudget_N1); the limit is a backstop, not a tuning knob.
const maxOps = 128

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
	owner   uint32              // uid of the site owner; every directory and read file must have it
	dirs    map[string]dirEntry // relative directory path -> descriptor
	stats   map[string]statEntry
	reads   map[string][]byte // nil value: the read was refused
	ops     int
	ignored []Ignored
	seen    map[string]bool // paths already in ignored
}

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY | noatime
)

// openTree opens the document root. The final path component must be a
// real directory owned by owner, not a symlink; the components above it
// are resolved normally and must be trusted by the caller (see Detect
// and DetectUnder).
func openTree(docroot string, owner uint32) (*tree, error) {
	if docroot == "" || docroot[0] != '/' {
		return nil, fmt.Errorf("%w: document root %q: must be an absolute path", ErrUnavailable, docroot)
	}
	// A trailing "/" or "/." makes the kernel resolve the last name as
	// a directory and follow a symlink there despite O_NOFOLLOW, so
	// only clean paths are accepted.
	if path.Clean(docroot) != docroot || docroot == "/" {
		return nil, fmt.Errorf("%w: document root %q: must be a clean path (no trailing slash, \".\" or \"..\")", ErrUnavailable, docroot)
	}
	fd, err := openRetry(unix.AT_FDCWD, docroot, dirFlags)
	if err != nil {
		return nil, fmt.Errorf("%w: document root %q: %w", ErrUnavailable, docroot, describe(err))
	}
	if err := checkDir(fd, owner); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: document root %q: %w", ErrUnavailable, docroot, err)
	}
	return newTree(fd, owner), nil
}

// openTreeUnder opens base, which the caller trusts, and then walks rel
// one component at a time without following symlinks. base and every
// component of rel must be directories owned by owner.
func openTreeUnder(base, rel string, owner uint32) (*tree, error) {
	if base == "" || base[0] != '/' {
		return nil, fmt.Errorf("%w: base %q: must be an absolute path", ErrUnavailable, base)
	}
	parts, err := splitRel(rel)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	fd, err := openRetry(unix.AT_FDCWD, base, dirFlags&^unix.O_NOFOLLOW)
	if err != nil {
		return nil, fmt.Errorf("%w: base %q: %w", ErrUnavailable, base, describe(err))
	}
	if err := checkDir(fd, owner); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: base %q: %w", ErrUnavailable, base, err)
	}
	for i, p := range parts {
		next, err := openRetry(fd, p, dirFlags)
		_ = unix.Close(fd)
		if err == nil {
			if err = checkDir(next, owner); err != nil {
				_ = unix.Close(next)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%w: document root %q: component %q: %w", ErrUnavailable, rel, strings.Join(parts[:i+1], "/"), describe(err))
		}
		fd = next
	}
	return newTree(fd, owner), nil
}

// ErrUnavailable is wrapped by every error from Detect and DetectUnder.
// The rest of the message names what failed and how ("does not exist",
// "owner differs", "symbolic link"), which is for the server log only:
// shown to a client it would tell whether paths the client cannot see
// exist. Show clients ErrUnavailable's text instead.
var ErrUnavailable = errors.New("document root unavailable")

var (
	errOwner   = errors.New("owner differs from the site owner")
	errChanged = errors.New("changed while being checked, not read")
)

// checkDir verifies that fd is a directory owned by owner. It is used
// for the document root and the components leading to it.
func checkDir(fd int, owner uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if kindOf(st.Mode) != kindDir {
		return errors.New("not a directory")
	}
	if st.Uid != owner {
		return errOwner
	}
	return nil
}

func newTree(fd int, owner uint32) *tree {
	return &tree{
		rootFD: fd,
		owner:  owner,
		dirs:   map[string]dirEntry{"": {fd: fd}},
		stats:  map[string]statEntry{},
		reads:  map[string][]byte{},
		seen:   map[string]bool{},
	}
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
			return nil, fmt.Errorf("%w: relative path %q: empty, \".\" or \"..\" component", ErrUnavailable, rel)
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
// component with O_NOFOLLOW relative to its parent. A directory not
// owned by the site owner is not entered: a client could otherwise move
// another user's directory (one it may write to but not read) into its
// tree and use detection as an oracle on that user's files.
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
	if err == nil {
		if err = t.spend(); err == nil {
			err = checkSubdir(fd, t.owner)
		}
		if err != nil {
			_ = unix.Close(fd)
		}
	}
	if err != nil {
		t.dirs[rel] = dirEntry{fd: -1, err: err}
		switch {
		case errors.Is(err, unix.ELOOP):
			t.ignore(rel, describe(err).Error())
		case errors.Is(err, unix.ENOTDIR):
			// Linux reports a symlink as ELOOP, other systems may
			// say ENOTDIR; tell a symlink from a plain file.
			var st unix.Stat_t
			if t.spend() == nil && fstatatRetry(pfd, name, &st) == nil && kindOf(st.Mode) == kindSymlink {
				t.ignore(rel, describe(unix.ELOOP).Error())
			}
		case !isAbsent(err):
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
	if !mayRead(&pre.st, t.owner) {
		t.ignore(rel, errOwner.Error()+" and the file is not world-readable, not read")
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
	// Two operations: on Linux an O_PATH open and the reopen.
	if t.ops+2 > maxOps {
		t.ignore(rel, errBudget.Error())
		return nil
	}
	t.ops += 2
	fd, err := openRegular(pfd, name, func(st *unix.Stat_t) error {
		if kindOf(st.Mode) != kindFile || st.Dev != pre.st.Dev || st.Ino != pre.st.Ino || !mayRead(st, t.owner) {
			return errChanged
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errChanged) {
			t.ignore(rel, err.Error())
		} else {
			t.ignore(rel, "open: "+describe(err).Error())
		}
		return nil
	}
	defer func() { _ = unix.Close(fd) }()
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

// fstatCheck runs check on the metadata of an open descriptor.
func fstatCheck(fd int, check func(*unix.Stat_t) error) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	return check(&st)
}

// Below the document root, an entry may be used if the site owner owns
// it or if the "other" permission bits grant the access to everyone:
// then the client could look at it anyway, so detection reveals nothing
// new. This keeps sites detectable whose directories or files belong to
// the web server user (mod_php installers, restores), while a foreign
// directory the client cannot search or a foreign file it cannot read
// (a hard link to root's or another user's private file, or another
// user's directory moved into the client's tree) is skipped.
// ASSUMPTION: no ACL or LSM rule denies the client what the "other" bits
// grant; such a rule could only make detection see more than the client.

// checkSubdir verifies that fd is a directory the site owner may search.
func checkSubdir(fd int, owner uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if kindOf(st.Mode) != kindDir {
		return errors.New("not a directory")
	}
	if st.Uid != owner && st.Mode&0o001 == 0 {
		return errOwner
	}
	return nil
}

// mayRead reports whether the site owner may read the file st describes.
func mayRead(st *unix.Stat_t, owner uint32) bool {
	return st.Uid == owner || st.Mode&0o004 != 0
}
