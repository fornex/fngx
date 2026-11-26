// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/fornex/fngx/internal/model"
)

func ptr[T any](v T) *T { return &v }

func newStore(t testing.TB) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "settings"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpen(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		if _, err := Open("settings"); err == nil {
			t.Fatal("relative root accepted")
		}
	})
	t.Run("creates layout with 0700", func(t *testing.T) {
		s := newStore(t)
		for _, d := range []string{s.Root(), s.users, s.domains} {
			fi, err := os.Stat(d)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != dirPerm {
				t.Errorf("%s: mode %v", d, fi.Mode().Perm())
			}
		}
		if _, err := Open(s.Root()); err != nil {
			t.Fatalf("reopen: %v", err)
		}
	})
	t.Run("world-writable root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o777); err != nil { // #nosec G302 -- the test needs a world-writable directory
			t.Fatal(err)
		}
		if _, err := Open(root); err == nil {
			t.Fatal("world-writable root accepted")
		}
	})
	t.Run("symlinked subdirectory", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		other := filepath.Join(t.TempDir(), "elsewhere")
		for _, d := range []string{root, other} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(other, filepath.Join(root, domainsDirName)); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(root); err == nil {
			t.Fatal("symlinked domains directory accepted")
		}
	})
	t.Run("subdirectory is a file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		writeRaw(t, filepath.Join(root, usersDirName), "x")
		if _, err := Open(root); err == nil {
			t.Fatal("file in place of users directory accepted")
		}
	})
	t.Run("root is a file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "r")
		writeRaw(t, root, "x")
		if _, err := Open(root); err == nil {
			t.Fatal("file as root accepted")
		}
	})
}

func TestServerRoundTrip(t *testing.T) {
	s := newStore(t)
	if _, err := s.LoadServer(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing server file: %v", err)
	}
	srv := model.Server{Defaults: model.Settings{Mode: ptr(model.ModeHybrid)}, Access: map[model.Field]model.Access{model.FieldCache: model.AccessClient}}
	if err := s.SaveServer(srv); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadServer()
	if err != nil {
		t.Fatal(err)
	}
	if *got.Defaults.Mode != model.ModeHybrid || got.AccessFor(model.FieldCache) != model.AccessClient {
		t.Fatalf("got %+v", got)
	}
	if err := s.SaveServer(model.Server{Access: map[model.Field]model.Access{"x": "y"}}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("invalid server saved: %v", err)
	}
}

func TestDomainAndUserRoundTrip_A3(t *testing.T) {
	s := newStore(t)
	d := model.Domain("example.com")
	u := model.User("bob")
	ds := model.Settings{Mode: ptr(model.ModeProxy), Cache: ptr(true)}
	us := model.Settings{PHPVersion: ptr(model.PHPVersion("ea-php83"))}
	if err := s.SaveDomain(d, ds); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUser(u, us); err != nil {
		t.Fatal(err)
	}
	gotD, err := s.LoadDomain(d)
	if err != nil || len(gotD.Diff(ds)) != 0 {
		t.Fatalf("domain: %+v %v", gotD, err)
	}
	gotU, err := s.LoadUser(u)
	if err != nil || len(gotU.Diff(us)) != 0 {
		t.Fatalf("user: %+v %v", gotU, err)
	}
	for _, p := range []string{filepath.Join(s.domains, string(d)), filepath.Join(s.users, string(u))} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != filePerm {
			t.Errorf("%s: mode %v, want %v", p, fi.Mode().Perm(), os.FileMode(filePerm))
		}
	}
	// Overwrite replaces the file and leaves no temporary files.
	if err := s.SaveDomain(d, model.Settings{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadDomain(d); !got.IsEmpty() {
		t.Fatalf("overwrite: %+v", got)
	}
	assertNoTemp(t, s.domains)

	if err := s.DeleteDomain(d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadDomain(d); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("after delete: %v", err)
	}
	if err := s.DeleteDomain(d); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if err := s.DeleteUser(u); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadUser(u); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("user after delete: %v", err)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover temporary file %s", e.Name())
		}
	}
}

func TestInvalidNamesNeverTouchDisk_N6(t *testing.T) {
	s := newStore(t)
	badDomains := []model.Domain{"", "../server.json", "a/b.com", ".hidden.com", "EXAMPLE.com", "..", "x"}
	for _, d := range badDomains {
		if err := s.SaveDomain(d, model.Settings{}); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("SaveDomain(%q) = %v", d, err)
		}
		if _, err := s.LoadDomain(d); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("LoadDomain(%q) = %v", d, err)
		}
		if err := s.DeleteDomain(d); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("DeleteDomain(%q) = %v", d, err)
		}
	}
	for _, u := range []model.User{"", "../domains", "Bob", "a.b"} {
		if err := s.SaveUser(u, model.Settings{}); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("SaveUser(%q) = %v", u, err)
		}
		if _, err := s.LoadUser(u); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("LoadUser(%q) = %v", u, err)
		}
		if err := s.DeleteUser(u); !errors.Is(err, model.ErrInvalid) {
			t.Errorf("DeleteUser(%q) = %v", u, err)
		}
	}
	if err := s.SaveDomain("example.com", model.Settings{Mode: ptr(model.Mode("apache"))}); !errors.Is(err, model.ErrInvalid) {
		t.Errorf("invalid settings saved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.domains, "example.com")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file written for invalid settings: %v", err)
	}
	assertNoTemp(t, s.domains)
}

func TestCorruptFiles(t *testing.T) {
	big := `{"version":1,"x":"` + strings.Repeat("a", model.MaxFileSize) + `"}`
	tests := []struct {
		name    string
		setup   func(t *testing.T, path string)
		wantErr error
	}{
		{"empty", func(t *testing.T, p string) { writeRaw(t, p, "") }, model.ErrInvalid},
		{"truncated", func(t *testing.T, p string) { writeRaw(t, p, `{"version":1,"mo`) }, model.ErrInvalid},
		{"garbage", func(t *testing.T, p string) { writeRaw(t, p, "\x00\xff\xfe") }, model.ErrInvalid},
		{"unknown field", func(t *testing.T, p string) { writeRaw(t, p, `{"version":1,"x":1}`) }, model.ErrInvalid},
		{"invalid value", func(t *testing.T, p string) { writeRaw(t, p, `{"version":1,"mode":"apache"}`) }, model.ErrInvalid},
		{"too large", func(t *testing.T, p string) { writeRaw(t, p, big) }, model.ErrInvalid},
		{"directory", func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}, model.ErrInvalid},
		{"fifo", func(t *testing.T, p string) {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Skip("mkfifo:", err)
			}
		}, model.ErrInvalid},
		{"symlink", func(t *testing.T, p string) {
			target := filepath.Join(t.TempDir(), "target")
			writeRaw(t, target, `{"version":1}`)
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}, model.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			tt.setup(t, filepath.Join(s.domains, "example.com"))
			_, err := s.LoadDomain("example.com")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "example.com") {
				t.Errorf("error does not name the file: %v", err)
			}
		})
	}
	t.Run("server file corrupt", func(t *testing.T) {
		s := newStore(t)
		writeRaw(t, s.serverPath(), `{"version":1,"defaults":{"mode":"x"}}`)
		if _, err := s.LoadServer(); !errors.Is(err, model.ErrInvalid) {
			t.Fatalf("got %v", err)
		}
	})
}

// TestLoadAllPartialFailure_N4: one broken file does not prevent loading
// the others, and every problem is reported.
func TestLoadAllPartialFailure_N4(t *testing.T) {
	s := newStore(t)
	for _, d := range []model.Domain{"a.com", "b.com", "c.com"} {
		if err := s.SaveDomain(d, model.Settings{Mode: ptr(model.ModeProxy)}); err != nil {
			t.Fatal(err)
		}
	}
	writeRaw(t, filepath.Join(s.domains, "b.com"), `{"version":1,"mode":"bad"}`)
	writeRaw(t, filepath.Join(s.domains, "README"), "x")
	writeRaw(t, filepath.Join(s.domains, "Upper.com"), `{"version":1}`)
	writeRaw(t, filepath.Join(s.domains, ".tmp-123"), "partial") // crash leftover: ignored

	got, err := s.LoadAllDomains()
	if len(got) != 2 || got["a.com"].Mode == nil || got["c.com"].Mode == nil {
		t.Fatalf("loaded %v", got)
	}
	if err == nil {
		t.Fatal("no error reported")
	}
	for _, want := range []string{"b.com", "README", "Upper.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), ".tmp-") {
		t.Errorf("temporary file reported: %v", err)
	}

	if err := s.SaveUser("bob", model.Settings{}); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, filepath.Join(s.users, "alice"), "{")
	users, err := s.LoadAllUsers()
	if len(users) != 1 || err == nil || !strings.Contains(err.Error(), "alice") {
		t.Fatalf("users %v, err %v", users, err)
	}
}

func TestListSorted(t *testing.T) {
	s := newStore(t)
	for _, d := range []model.Domain{"c.com", "a.com", "b.a.com"} {
		if err := s.SaveDomain(d, model.Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListDomains()
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[a.com b.a.com c.com]" {
		t.Fatalf("got %v", got)
	}
	users, err := s.ListUsers()
	if err != nil || len(users) != 0 {
		t.Fatalf("users %v %v", users, err)
	}
}

func TestCreateDomain_M4(t *testing.T) {
	s := newStore(t)
	srv := model.Server{}
	created, err := s.CreateDomain("new.com", srv, model.Settings{})
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	got, _ := s.LoadDomain("new.com")
	if got.Mode == nil || *got.Mode != model.ModeNginx {
		t.Fatalf("new domain mode %+v", got)
	}
	// A repeated hook does not reset a mode changed in the meantime.
	if err := s.SaveDomain("new.com", model.Settings{Mode: ptr(model.ModeProxy)}); err != nil {
		t.Fatal(err)
	}
	created, err = s.CreateDomain("new.com", model.Server{Defaults: model.Settings{Mode: ptr(model.ModeHybrid)}}, model.Settings{})
	if err != nil || created {
		t.Fatalf("second create: created=%v err=%v", created, err)
	}
	if got, _ := s.LoadDomain("new.com"); *got.Mode != model.ModeProxy {
		t.Fatalf("existing domain changed: %v", *got.Mode)
	}
	// Admin-changed default (M-4).
	srv.Defaults.Mode = ptr(model.ModeHybrid)
	if _, err := s.CreateDomain("other.com", srv, model.Settings{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadDomain("other.com"); *got.Mode != model.ModeHybrid {
		t.Fatalf("admin default ignored: %v", *got.Mode)
	}
	// Corrupt file: report, do not overwrite.
	writeRaw(t, filepath.Join(s.domains, "bad.com"), "{")
	if _, err := s.CreateDomain("bad.com", srv, model.Settings{}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("corrupt file: %v", err)
	}
	if _, err := s.CreateDomain("x", srv, model.Settings{}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("invalid name: %v", err)
	}
}

func TestInitExistingSites_M5(t *testing.T) {
	s := newStore(t)
	if err := s.SaveDomain("hybrid.com", model.Settings{Mode: ptr(model.ModeHybrid)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDomain("cached.com", model.Settings{Cache: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, filepath.Join(s.domains, "broken.com"), "{")
	domains := []model.Domain{"a.com", "sub.a.com", "hybrid.com", "cached.com", "broken.com", "bad_name.com"}

	n, err := s.InitExistingSites(model.Server{}, domains)
	if n != 3 {
		t.Errorf("written %d, want 3", n)
	}
	if err == nil || !strings.Contains(err.Error(), "broken.com") || !strings.Contains(err.Error(), "bad_name.com") {
		t.Errorf("errors not reported: %v", err)
	}
	want := map[model.Domain]model.Mode{"a.com": model.ModeProxy, "sub.a.com": model.ModeProxy, "hybrid.com": model.ModeHybrid, "cached.com": model.ModeProxy}
	for d, m := range want {
		got, err := s.LoadDomain(d)
		if err != nil || got.Mode == nil || *got.Mode != m {
			t.Errorf("%s: %+v %v", d, got, err)
		}
	}
	if got, _ := s.LoadDomain("cached.com"); got.Cache == nil || !*got.Cache {
		t.Error("other fields lost")
	}
	// Idempotent.
	if n, _ := s.InitExistingSites(model.Server{}, domains[:4]); n != 0 {
		t.Errorf("second run wrote %d files", n)
	}
}

func TestWriteAtomicFailureCleansUp(t *testing.T) {
	s := newStore(t)
	// Make the target a non-empty directory so rename fails.
	target := filepath.Join(s.domains, "example.com")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDomain("example.com", model.Settings{}); err == nil {
		t.Fatal("rename over directory succeeded")
	}
	assertNoTemp(t, s.domains)
}

func TestWriteIntoMissingDirectory(t *testing.T) {
	s := newStore(t)
	if err := os.RemoveAll(s.users); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUser("bob", model.Settings{}); err == nil {
		t.Fatal("write into removed directory succeeded")
	}
	if _, err := s.ListUsers(); err == nil {
		t.Fatal("listing a removed directory succeeded")
	}
}

func TestInitExistingSitesRefusesLockedMode_M5(t *testing.T) {
	s := newStore(t)
	for _, a := range []model.Access{model.AccessLocked, "bogus"} {
		srv := model.Server{Access: map[model.Field]model.Access{model.FieldMode: a}}
		n, err := s.InitExistingSites(srv, []model.Domain{"old.com"})
		if n != 0 || !errors.Is(err, model.ErrNotPermitted) {
			t.Fatalf("access %q: written %d, err %v", a, n, err)
		}
	}
	if _, err := s.LoadDomain("old.com"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("file written: %v", err)
	}
}

func TestInitExistingSitesDuplicates_M5(t *testing.T) {
	s := newStore(t)
	n, err := s.InitExistingSites(model.Server{}, []model.Domain{"a.com", "a.com"})
	if err != nil || n != 1 {
		t.Fatalf("written %d, err %v", n, err)
	}
}

// TestUpdateDomainAsClient_U8 checks the client path end to end: the
// stored layer, not a client-supplied one, is the base of the check.
func TestUpdateDomainAsClient_U8(t *testing.T) {
	s := newStore(t)
	srv := model.Server{}
	if err := s.UpdateDomainAsClient("new.com", srv, model.Settings{Mode: ptr(model.ModeProxy)}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unregistered domain: %v", err)
	}
	if err := s.SaveDomain("a.com", model.Settings{Mode: ptr(model.ModeNginx), Cache: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	// Cache is locked by default, so dropping it is a forbidden change.
	if err := s.UpdateDomainAsClient("a.com", srv, model.Settings{Mode: ptr(model.ModeProxy)}); !errors.Is(err, model.ErrNotPermitted) {
		t.Fatalf("forbidden change accepted: %v", err)
	}
	if err := s.UpdateDomainAsClient("a.com", srv, model.Settings{Mode: ptr(model.ModeProxy), Cache: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadDomain("a.com"); *got.Mode != model.ModeProxy {
		t.Fatalf("mode not saved: %v", *got.Mode)
	}
	if err := s.UpdateDomainAsClient("a.com", srv, model.Settings{Cache: ptr(true)}); !errors.Is(err, model.ErrNotPermitted) {
		t.Fatalf("mode removal accepted: %v", err)
	}
}

func TestListErrorsEscapeNames(t *testing.T) {
	s := newStore(t)
	writeRaw(t, filepath.Join(s.domains, "x\nFAKE LOG LINE"), "{}")
	_, err := s.ListDomains()
	if err == nil || strings.Contains(err.Error(), "\n") {
		t.Fatalf("name not escaped: %q", err)
	}
}
