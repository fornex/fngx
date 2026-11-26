// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNginx imitates "nginx -t" by scanning the configuration directory:
//
//   - a line "BROKEN" is an error reported with the file and line, the way
//     nginx reports most errors;
//   - a line "HIDDEN" is an error reported without a file name;
//   - two files with the same "DUP <name>" line conflict, reported without a
//     file name (like a duplicate definition that is detected late).
//
// Reload records which generation the live link resolves to.
type fakeNginx struct {
	mu        sync.Mutex
	reloads   []string // generation names, in order
	reloadErr func(n int, gen string) error
	testErr   error // infrastructure error for every test

	active    int
	overlaps  int
	testDelay time.Duration
}

var dupRe = regexp.MustCompile(`(?m)^DUP (\S+)$`)

func (f *fakeNginx) enter() {
	f.mu.Lock()
	f.active++
	if f.active > 1 {
		f.overlaps++
	}
	f.mu.Unlock()
}

func (f *fakeNginx) leave() {
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
}

func (f *fakeNginx) Test(_ context.Context, conf string) (string, error) {
	f.enter()
	defer f.leave()
	f.mu.Lock()
	delay, testErr := f.testDelay, f.testErr
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if testErr != nil {
		return "nginx: cannot run\n", testErr
	}
	if _, err := os.Stat(conf); err != nil {
		return fmt.Sprintf("nginx: [emerg] open() %q failed\n", conf), fmt.Errorf("%w: exit status 1", ErrConfigInvalid)
	}
	dir := filepath.Dir(conf)
	var out strings.Builder
	dups := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // test file
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			switch line {
			case "BROKEN":
				fmt.Fprintf(&out, "nginx: [emerg] unknown directive \"BROKEN\" in %s:%d\n", p, i+1)
			case "HIDDEN":
				out.WriteString("nginx: [emerg] could not build something\n")
			}
		}
		for _, m := range dupRe.FindAllStringSubmatch(string(data), -1) {
			if _, ok := dups[m[1]]; ok {
				fmt.Fprintf(&out, "nginx: [emerg] duplicate %q\n", m[1])
			}
			dups[m[1]] = p
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if out.Len() > 0 {
		fmt.Fprintf(&out, "nginx: configuration file %s test failed\n", conf)
		return out.String(), fmt.Errorf("%w: exit status 1", ErrConfigInvalid)
	}
	return fmt.Sprintf("nginx: configuration file %s test is successful\n", conf), nil
}

func (f *fakeNginx) Reload(_ context.Context, conf string) (string, error) {
	f.enter()
	defer f.leave()
	dir, err := filepath.EvalSymlinks(filepath.Dir(conf))
	if err != nil {
		return "nginx: [error] open() failed\n", fmt.Errorf("exit status 1: %w", err)
	}
	gen := filepath.Base(dir)
	f.mu.Lock()
	f.reloads = append(f.reloads, gen)
	n := len(f.reloads)
	hook := f.reloadErr
	f.mu.Unlock()
	if hook != nil {
		if err := hook(n, gen); err != nil {
			return "nginx: [error] kill failed\n", err
		}
	}
	return "", nil
}

func (f *fakeNginx) snapshot() (reloads []string, overlaps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reloads...), f.overlaps
}

// syncBuffer is a log sink shared by several engines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type testEnv struct {
	root  string
	nginx *fakeNginx
	logs  *syncBuffer
	cfg   Config
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	env := &testEnv{root: t.TempDir(), nginx: &fakeNginx{}, logs: &syncBuffer{}}
	// New refuses a root others can write; do not depend on the umask.
	if err := os.Chmod(env.root, 0o700); err != nil { //nolint:gosec // a directory needs the execute bit
		t.Fatal(err)
	}
	env.cfg = Config{
		Root:     env.root,
		MainFile: "nginx.conf",
		Keep:     3,
		MaxTests: 64,
		Nginx:    env.nginx,
		Logger:   NewLogger(env.logs),
	}
	return env
}

func (env *testEnv) engine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (env *testEnv) live(t *testing.T) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(env.root, "live"))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Base(target)
}

func (env *testEnv) liveFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(env.root, "live", rel)) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (env *testEnv) gens(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(env.root, "generations"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func mainFile() File {
	return File{Path: "nginx.conf", Data: []byte("events {}\nhttp { include vhosts/*.conf; }\n")}
}

func unit(id, body string) Unit {
	return Unit{ID: id, Files: []File{{Path: "vhosts/" + id + ".conf", Data: []byte(body)}}}
}

func full(units ...Unit) Change {
	return Change{Full: true, Common: []File{mainFile()}, Units: units}
}
