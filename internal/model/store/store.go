// Package store keeps the settings layers of package model in plain text
// files, without a database (A-3).
//
// Layout under the root directory:
//
//	server.json         server layer
//	users/<user>        user layer, one file per account
//	domains/<domain>    domain layer, one file per domain or subdomain
//
// One file per domain keeps a change to one domain a single small write
// and scales to 10,000 domains (N-1); a directory of that size is cheap on
// ext4 and XFS. User and domain files have no extension because a domain
// name may be 253 bytes long and the file name limit is 255.
//
// Writes are atomic: a temporary file in the same directory is written,
// synced and renamed over the target, then the directory is synced.
// Files are created with mode 0600 and directories with 0700. Temporary
// files start with '.', which no valid name does, so listings skip them.
//
// A Store does no locking: operations are serialized by the caller (A-6).
package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/fornex/fngx/internal/model"
)

const (
	serverFileName = "server.json"
	usersDirName   = "users"
	domainsDirName = "domains"
	dirPerm        = 0o700
	filePerm       = 0o600
	tempPattern    = ".tmp-*"
)

// Store is a settings directory.
type Store struct {
	root    string
	users   string
	domains string
}

// Open opens the settings directory at root, which must be an absolute
// path, creating it and its subdirectories if needed. The subdirectories
// must be real directories (not symlinks), and no directory may be
// writable by group or others.
func Open(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("settings root %q is not an absolute path", root)
	}
	root = filepath.Clean(root)
	s := &Store{
		root:    root,
		users:   filepath.Join(root, usersDirName),
		domains: filepath.Join(root, domainsDirName),
	}
	if err := os.MkdirAll(root, dirPerm); err != nil {
		return nil, err
	}
	// The root itself may be a symlink chosen by the admin.
	if err := checkDir(root, os.Stat); err != nil {
		return nil, err
	}
	for _, d := range []string{s.users, s.domains} {
		if err := os.Mkdir(d, dirPerm); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if err := checkDir(d, os.Lstat); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func checkDir(path string, stat func(string) (fs.FileInfo, error)) error {
	fi, err := stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others (mode %v)", path, fi.Mode().Perm())
	}
	return nil
}

// Root returns the settings directory.
func (s *Store) Root() string { return s.root }

func (s *Store) serverPath() string { return filepath.Join(s.root, serverFileName) }

func (s *Store) userPath(u model.User) (string, error) {
	if err := u.Validate(); err != nil {
		return "", err
	}
	return filepath.Join(s.users, string(u)), nil
}

func (s *Store) domainPath(d model.Domain) (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	return filepath.Join(s.domains, string(d)), nil
}

// LoadServer reads the server layer. If the file does not exist the error
// wraps fs.ErrNotExist; the caller then decides whether built-in defaults
// (model.Server{}) are acceptable.
func (s *Store) LoadServer() (model.Server, error) {
	p := s.serverPath()
	data, err := readFile(p)
	if err != nil {
		return model.Server{}, err
	}
	srv, err := model.ParseServer(data)
	if err != nil {
		return model.Server{}, fmt.Errorf("%s: %w", p, err)
	}
	return srv, nil
}

// SaveServer validates and writes the server layer.
func (s *Store) SaveServer(srv model.Server) error {
	data, err := model.MarshalServer(srv)
	if err != nil {
		return err
	}
	return writeAtomic(s.root, serverFileName, data, true)
}

func loadSettings(p string) (model.Settings, error) {
	data, err := readFile(p)
	if err != nil {
		return model.Settings{}, err
	}
	st, err := model.ParseSettings(data)
	if err != nil {
		return model.Settings{}, fmt.Errorf("%s: %w", p, err)
	}
	return st, nil
}

func saveSettings(p string, st model.Settings, syncParent bool) error {
	data, err := model.MarshalSettings(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Dir(p), filepath.Base(p), data, syncParent)
}

// LoadUser reads a user layer. A missing file wraps fs.ErrNotExist.
func (s *Store) LoadUser(u model.User) (model.Settings, error) {
	p, err := s.userPath(u)
	if err != nil {
		return model.Settings{}, err
	}
	return loadSettings(p)
}

// SaveUser validates and writes a user layer.
func (s *Store) SaveUser(u model.User, st model.Settings) error {
	p, err := s.userPath(u)
	if err != nil {
		return err
	}
	return saveSettings(p, st, true)
}

// DeleteUser removes a user layer. A missing file is not an error.
func (s *Store) DeleteUser(u model.User) error {
	p, err := s.userPath(u)
	if err != nil {
		return err
	}
	return remove(p)
}

// LoadDomain reads a domain layer. A missing file wraps fs.ErrNotExist:
// a domain without a file has not been registered (see CreateDomain and
// InitExistingSites) and must not silently inherit the default mode.
func (s *Store) LoadDomain(d model.Domain) (model.Settings, error) {
	p, err := s.domainPath(d)
	if err != nil {
		return model.Settings{}, err
	}
	return loadSettings(p)
}

// SaveDomain validates and writes a domain layer.
func (s *Store) SaveDomain(d model.Domain, st model.Settings) error {
	p, err := s.domainPath(d)
	if err != nil {
		return err
	}
	return saveSettings(p, st, true)
}

// DeleteDomain removes a domain layer. A missing file is not an error.
func (s *Store) DeleteDomain(d model.Domain) error {
	p, err := s.domainPath(d)
	if err != nil {
		return err
	}
	return remove(p)
}

// CreateDomain registers a domain created after installation with the
// default mode for new domains (M-4). If the domain already has a file it
// is left unchanged and created is false, so a repeated hook is harmless.
func (s *Store) CreateDomain(d model.Domain, srv model.Server, owner model.Settings) (created bool, err error) {
	if _, err := s.LoadDomain(d); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if err := s.SaveDomain(d, model.NewDomainSettings(srv, owner)); err != nil {
		return false, err
	}
	return true, nil
}

// InitExistingSites is for the first installation on a server without
// Cpnginx: every listed site that already works gets proxy mode (M-5,
// I-5). A domain that already has a mode keeps it, so running it twice is
// harmless. It continues after an error with one domain (N-4) and returns
// the number of files written and all errors joined.
func (s *Store) InitExistingSites(domains []model.Domain) (written int, err error) {
	var errs []error
	for _, d := range domains {
		cur, err := s.LoadDomain(d)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		next := model.ExistingSiteSettings(cur)
		if err == nil && len(cur.Diff(next)) == 0 {
			continue
		}
		// The directory is synced once at the end instead of per file:
		// on 10,000 domains this halves the number of fsync calls.
		p, _ := s.domainPath(d) // d was validated by LoadDomain
		if err := saveSettings(p, next, false); err != nil {
			errs = append(errs, err)
			continue
		}
		written++
	}
	if written > 0 {
		errs = append(errs, syncDir(s.domains))
	}
	return written, errors.Join(errs...)
}

// ListUsers returns the users that have a layer file, sorted. Entries
// with invalid names are reported in the error and skipped.
func (s *Store) ListUsers() ([]model.User, error) {
	names, err := listDir(s.users)
	var out []model.User
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, n := range names {
		u := model.User(n)
		if err := u.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Join(s.users, n), err))
			continue
		}
		out = append(out, u)
	}
	return out, errors.Join(errs...)
}

// ListDomains returns the domains that have a layer file, sorted. Entries
// with invalid names are reported in the error and skipped.
func (s *Store) ListDomains() ([]model.Domain, error) {
	names, err := listDir(s.domains)
	var out []model.Domain
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, n := range names {
		d := model.Domain(n)
		if err := d.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Join(s.domains, n), err))
			continue
		}
		out = append(out, d)
	}
	return out, errors.Join(errs...)
}

// LoadAllUsers reads every user layer. A broken file does not stop the
// others (N-4): the result holds every file that loaded, and the error
// joins one error per broken file.
func (s *Store) LoadAllUsers() (map[model.User]model.Settings, error) {
	users, err := s.ListUsers()
	errs := []error{err}
	out := make(map[model.User]model.Settings, len(users))
	for _, u := range users {
		st, err := s.LoadUser(u)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[u] = st
	}
	return out, errors.Join(errs...)
}

// LoadAllDomains reads every domain layer, with the same error handling
// as LoadAllUsers.
func (s *Store) LoadAllDomains() (map[model.Domain]model.Settings, error) {
	domains, err := s.ListDomains()
	errs := []error{err}
	out := make(map[model.Domain]model.Settings, len(domains))
	for _, d := range domains {
		st, err := s.LoadDomain(d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[d] = st
	}
	return out, errors.Join(errs...)
}

// listDir returns the names in dir that do not start with '.'.
func listDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if n := e.Name(); n != "" && n[0] != '.' {
			names = append(names, n)
		}
	}
	return names, nil
}

// readFile reads a settings file that must be a regular file no larger
// than model.MaxFileSize. Symlinks are refused (O_NOFOLLOW) and the type
// is checked before opening, so a FIFO or device cannot block or feed
// the reader.
func readFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w: not a regular file", path, model.ErrInvalid)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- path is built from a validated name
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, model.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > model.MaxFileSize {
		return nil, fmt.Errorf("%s: %w: larger than %d bytes", path, model.ErrInvalid, model.MaxFileSize)
	}
	return data, nil
}

// writeAtomic replaces dir/name with data so that a reader sees either
// the old or the new content, also after a crash. With syncParent false
// the caller must sync dir itself before relying on the new name.
func writeAtomic(dir, name string, data []byte, syncParent bool) (err error) {
	f, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(filePerm); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	if !syncParent {
		return nil
	}
	return syncDir(dir)
}

func remove(p string) error {
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- dir is inside the settings root
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
