package apply

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const (
	fileMode = 0o640
	dirMode  = 0o750
)

// writeNewFile creates path, failing if it already exists, so a file is
// never written through a symlink or over another file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, fileMode) //nolint:gosec // path is inside an engine-owned directory
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// linkOrCopy makes dst share src's content. Generations are immutable once
// tested, so a hard link is safe; copying is the fallback for file systems
// without hard links.
func linkOrCopy(src, dst string) (copied bool, err error) {
	if err := os.Link(src, dst); err == nil {
		return false, nil
	}
	in, err := os.Open(src) //nolint:gosec // src is inside an engine-owned generation
	if err != nil {
		return false, err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, fileMode) //nolint:gosec // dst is inside the candidate
	if err != nil {
		return false, err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return true, err
}

func syncPath(path string) error {
	f, err := os.Open(path) //nolint:gosec // engine-owned path
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncAll fsyncs paths with a few workers: one fsync per file is the price
// of a crash-safe swap, and parallel calls let the file system batch them.
func syncAll(paths []string) error {
	const workers = 8
	ch := make(chan string)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ch {
				if err := syncPath(p); err != nil && errs[i] == nil {
					errs[i] = err
				}
			}
		}()
	}
	for _, p := range paths {
		ch <- p
	}
	close(ch)
	wg.Wait()
	return errors.Join(errs...)
}

// mkdirParents creates the directories between root and the file at rel and
// records the new ones so they can be synced.
func mkdirParents(root, rel string, created map[string]bool) error {
	dir := filepath.Dir(rel)
	if dir == "." {
		return nil
	}
	var missing []string
	for d := dir; d != "."; d = filepath.Dir(d) {
		if created[d] {
			break
		}
		missing = append(missing, d)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		d := missing[i]
		if err := os.Mkdir(filepath.Join(root, d), dirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		created[d] = true
	}
	return nil
}

// checkPrivate fails if dir is not a directory owned by the current user
// and closed to writes by group and others.
func checkPrivate(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("apply: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("apply: %s is writable by group or others (%v)", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("apply: %s is owned by uid %d, not by the current user", dir, st.Uid)
	}
	return nil
}
