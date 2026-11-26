// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/fornex/fngx/internal/model"
)

func detect(t *testing.T, root string) Result {
	t.Helper()
	r, err := Detect(root, me)
	if err != nil {
		t.Fatalf("Detect(%q): %v", root, err)
	}
	return r
}

func hasIgnored(r Result, path string) bool {
	return slices.ContainsFunc(r.Ignored, func(i Ignored) bool { return i.Path == path })
}

func TestTemplateNamesValid_T2(t *testing.T) {
	for _, s := range signatures {
		if _, err := model.ParseTemplateName(string(s.template)); err != nil {
			t.Errorf("%s: %v", s.app, err)
		}
	}
}

func TestDetect_T10_Fixtures(t *testing.T) {
	tests := []struct {
		fixture  string
		app      App
		variant  string
		template model.TemplateName
		conf     Confidence
		hint     string
	}{
		{"wordpress", WordPress, "", TemplateWordPress, High, ""},
		{"wordpress-minimal", WordPress, "", TemplateWordPress, Medium, ""},
		{"joomla4", Joomla, "", TemplateJoomla, High, ""},
		{"joomla3", Joomla, "", TemplateJoomla, High, ""},
		{"drupal8", Drupal, "8+", TemplateDrupal, High, ""},
		{"drupal-project-root", Drupal, "8+", TemplateDrupal, High, "web"},
		{"drupal7", Drupal, "7", TemplateDrupal7, High, ""},
		{"laravel-project-root", Laravel, "project-root", TemplateLaravel, High, "public"},
		{"laravel-public", Laravel, "public", TemplateLaravel, Medium, ""},
		{"opencart", OpenCart, "", TemplateOpenCart, High, ""},
		{"react-cra", React, "create-react-app", TemplateReact, High, ""},
		{"react-vite", React, "vite", TemplateReact, Medium, ""},
		{"react-spa", React, "spa", TemplateReact, Low, ""},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			r := detect(t, fixtureDir(t, tt.fixture))
			if len(r.Candidates) != 1 {
				t.Fatalf("candidates = %+v, want exactly one", r.Candidates)
			}
			c, ok := r.Suggestion()
			if !ok {
				t.Fatalf("no suggestion for %+v", r.Candidates)
			}
			if c.App != tt.app || c.Variant != tt.variant || c.Template != tt.template || c.Confidence != tt.conf || c.DocrootHint != tt.hint {
				t.Errorf("got %s/%s template %s %s hint %q, want %s/%s template %s %s hint %q",
					c.App, c.Variant, c.Template, c.Confidence, c.DocrootHint,
					tt.app, tt.variant, tt.template, tt.conf, tt.hint)
			}
			if len(c.Evidence) == 0 {
				t.Error("no evidence")
			}
			if len(r.Ignored) != 0 {
				t.Errorf("ignored = %+v, want none", r.Ignored)
			}
		})
	}
}

func TestDetect_T10_NothingFound(t *testing.T) {
	for _, name := range []string{"empty", "static", "plain-php"} {
		t.Run(name, func(t *testing.T) {
			r := detect(t, fixtureDir(t, name))
			if len(r.Candidates) != 0 {
				t.Errorf("candidates = %+v, want none", r.Candidates)
			}
			if _, ok := r.Suggestion(); ok {
				t.Error("Suggestion ok on an empty result")
			}
		})
	}
}

func TestDetect_T10_Ambiguous(t *testing.T) {
	root := fixtureDir(t, "wordpress")
	build(t, root, fixtures["joomla4"])
	r := detect(t, root)
	if len(r.Candidates) != 2 {
		t.Fatalf("candidates = %+v, want WordPress and Joomla", r.Candidates)
	}
	if c, ok := r.Suggestion(); ok {
		t.Errorf("Suggestion = %+v, want none for an ambiguous tree", c)
	}
}

func TestDetect_T10_StrongerWins(t *testing.T) {
	// A WordPress site with a leftover SPA index.html: WordPress is High,
	// so the content checks do not run and index.html is not read.
	root := fixtureDir(t, "wordpress")
	build(t, root, fx{"index.html": spaIndex})
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	r := tr.detect()
	c, ok := r.Suggestion()
	if !ok || c.App != WordPress {
		t.Fatalf("Suggestion = %+v, %v; want WordPress", c, ok)
	}
	if len(tr.reads) != 0 {
		t.Errorf("files read: %v, want none", tr.reads)
	}
}

func TestDetect_T10_WeakerKeptButNotAmbiguous(t *testing.T) {
	// Minimal WordPress (Medium) plus an SPA index.html (Low): both are
	// reported, WordPress is suggested.
	root := fixtureDir(t, "wordpress-minimal")
	build(t, root, fx{"index.html": spaIndex})
	r := detect(t, root)
	if len(r.Candidates) != 2 {
		t.Fatalf("candidates = %+v", r.Candidates)
	}
	if c, ok := r.Suggestion(); !ok || c.App != WordPress {
		t.Errorf("Suggestion = %+v, %v; want WordPress", c, ok)
	}
}

func TestDetect_T10_DoesNotModify(t *testing.T) {
	root := t.TempDir()
	for name, f := range fixtures {
		if err := os.Mkdir(filepath.Join(root, name), 0o750); err != nil {
			t.Fatal(err)
		}
		build(t, filepath.Join(root, name), f)
	}
	before := snapshot(t, root)
	for name := range fixtures {
		detect(t, filepath.Join(root, name))
	}
	if after := snapshot(t, root); after != before {
		t.Errorf("tree changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func snapshot(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %v %d %d\n", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Symlink attacks (N-6): a client points markers or directories at files
// outside the document root.

func TestDetect_N6_SymlinkedMarkerFile(t *testing.T) {
	outside := t.TempDir()
	build(t, outside, fx{"wp-settings.php": "", "secret": "x"})
	root := fixtureDir(t, "wordpress")
	for _, name := range []string{"wp-settings.php", "wp-config.php"} {
		p := filepath.Join(root, name)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, name), p); err != nil {
			t.Fatal(err)
		}
	}
	r := detect(t, root)
	if len(r.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none: required marker is a symlink", r.Candidates)
	}
	if !hasIgnored(r, "wp-settings.php") {
		t.Errorf("ignored = %+v, want wp-settings.php", r.Ignored)
	}
}

func TestDetect_N6_SymlinkedConfigIsOnlySupporting(t *testing.T) {
	// wp-config.php as a symlink to /etc/passwd: WordPress is still
	// detected from the other markers, wp-config.php is not evidence and
	// is never read.
	root := fixtureDir(t, "wordpress")
	p := filepath.Join(root, "wp-config.php")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", p); err != nil {
		t.Fatal(err)
	}
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	r := tr.detect()
	if len(tr.reads) != 0 {
		t.Errorf("files read: %v, want none", tr.reads)
	}
	c, ok := r.Suggestion()
	if !ok || c.App != WordPress {
		t.Fatalf("Suggestion = %+v, %v", c, ok)
	}
	if slices.Contains(c.Evidence, "wp-config.php") {
		t.Error("symlinked wp-config.php counted as evidence")
	}
	if !hasIgnored(r, "wp-config.php") {
		t.Errorf("ignored = %+v, want wp-config.php", r.Ignored)
	}
}

func TestDetect_N6_SymlinkedDirectory(t *testing.T) {
	outside := t.TempDir()
	build(t, outside, fx{"lib/Drupal.php": "", "version.php": ""})
	root := t.TempDir()
	build(t, root, fx{"index.php": "", "core/": "", "wp-settings.php": ""})
	// core/lib -> outside/lib would make core/lib/Drupal.php visible;
	// wp-includes -> outside makes the WordPress directory marker a link.
	if err := os.Symlink(filepath.Join(outside, "lib"), filepath.Join(root, "core", "lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "wp-includes")); err != nil {
		t.Fatal(err)
	}
	r := detect(t, root)
	if len(r.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", r.Candidates)
	}
	for _, p := range []string{"wp-includes", "core/lib"} {
		if !hasIgnored(r, p) {
			t.Errorf("ignored = %+v, want %s", r.Ignored, p)
		}
	}
}

func TestDetect_N6_SymlinkedContentFile(t *testing.T) {
	// index.html and index.php point at files outside the document root
	// whose contents would match; they must not be read.
	outside := t.TempDir()
	build(t, outside, fx{"spa.html": spaIndex, "laravel.php": laravelIndex})
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "spa.html"), filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "laravel.php"), filepath.Join(root, "index.php")); err != nil {
		t.Fatal(err)
	}
	r := detect(t, root)
	if len(r.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", r.Candidates)
	}
	for _, p := range []string{"index.html", "index.php"} {
		if !hasIgnored(r, p) {
			t.Errorf("ignored = %+v, want %s", r.Ignored, p)
		}
	}
}

func TestDetect_N6_SymlinkLoops(t *testing.T) {
	root := t.TempDir()
	for _, l := range [][2]string{
		{"wp-includes", "wp-includes"},
		{"core", "sites"}, {"sites", "core"},
		{"index.html", "index.html"},
		{"administrator", "."}, {"system", ".."},
	} {
		if err := os.Symlink(l[1], filepath.Join(root, l[0])); err != nil {
			t.Fatal(err)
		}
	}
	build(t, root, fx{"wp-settings.php": "", "includes/defines.php": ""})
	r := detect(t, root)
	if len(r.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", r.Candidates)
	}
}

func TestDetect_N6_DocrootIsSymlink(t *testing.T) {
	target := fixtureDir(t, "wordpress")
	link := filepath.Join(t.TempDir(), "public_html")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// A trailing "/" or "/." makes the kernel follow the final symlink
	// despite O_NOFOLLOW; such paths are refused outright.
	for _, p := range []string{link, link + "/", link + "/.", link + "//", link + "/../public_html", target + "/"} {
		if _, err := Detect(p, me); err == nil {
			t.Errorf("Detect(%q) succeeded: followed a symlink or accepted an unclean path", p)
		}
	}
	if _, err := Detect(target, me); err != nil {
		t.Errorf("Detect(target): %v", err)
	}
}

func TestDetect_BadDocroot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", "relative/dir", file, filepath.Join(file, "x"), "/nonexistent-" + t.Name()} {
		if _, err := Detect(p, me); err == nil {
			t.Errorf("Detect(%q) succeeded", p)
		}
	}
}

func TestDetectUnder_N6(t *testing.T) {
	home := t.TempDir()
	build(t, home, fx{"public_html/blog/": ""})
	build(t, filepath.Join(home, "public_html", "blog"), fixtures["wordpress"])
	other := t.TempDir() // another user's site
	build(t, other, fixtures["joomla4"])
	if err := os.Symlink(other, filepath.Join(home, "public_html", "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "public_html"), filepath.Join(home, "www")); err != nil {
		t.Fatal(err)
	}

	r, err := DetectUnder(home, "public_html/blog", me)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := r.Suggestion(); !ok || c.App != WordPress {
		t.Errorf("Suggestion = %+v, %v; want WordPress", c, ok)
	}
	for _, rel := range []string{"public_html/evil", "www/blog", "public_html/../public_html/blog", "/public_html", "public_html//blog", "./public_html"} {
		if _, err := DetectUnder(home, rel, me); err == nil {
			t.Errorf("DetectUnder(%q) succeeded", rel)
		}
	}
	if _, err := DetectUnder("relative", "x", me); err == nil {
		t.Error("DetectUnder accepted a relative base")
	}
	if r, err := DetectUnder(filepath.Join(home, "public_html", "blog"), "", me); err != nil || len(r.Candidates) == 0 {
		t.Errorf("DetectUnder with empty rel: %+v, %v", r, err)
	}
}

func TestDetect_N6_FIFO(t *testing.T) {
	// Opening a FIFO for reading blocks until a writer appears unless
	// O_NONBLOCK is set; detection must neither block nor read it.
	root := t.TempDir()
	build(t, root, fx{"assets/": "", "wp-includes/": ""})
	for _, name := range []string{"index.html", "index.php", "wp-settings.php"} {
		if err := unix.Mkfifo(filepath.Join(root, name), 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
	}
	done := make(chan Result, 1)
	go func() {
		r, err := Detect(root, me)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	select {
	case r := <-done:
		if len(r.Candidates) != 0 {
			t.Errorf("candidates = %+v, want none", r.Candidates)
		}
		for _, p := range []string{"index.html", "index.php", "wp-settings.php"} {
			if !hasIgnored(r, p) {
				t.Errorf("ignored = %+v, want %s", r.Ignored, p)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Detect blocked on a FIFO")
	}
}

func TestDetect_N6_FIFOSwappedAfterStat(t *testing.T) {
	// TOCTOU: the entry was a regular file at fstatat time and is a FIFO
	// at open time. The open must not block and the read must be refused.
	root := t.TempDir()
	build(t, root, fx{"index.html": spaIndex})
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	if tr.stat("index.html").k != kindFile {
		t.Fatal("setup: not a file")
	}
	p := filepath.Join(root, "index.html")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan []byte, 1)
	go func() { done <- tr.readPrefix("index.html", indexHTMLLimit) }()
	select {
	case b := <-done:
		if b != nil {
			t.Errorf("read %q from a swapped FIFO", b)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readPrefix blocked on a FIFO")
	}
}

func TestDetect_N6_FileSwappedAfterStat(t *testing.T) {
	// TOCTOU: a different regular file (for example a hard link to
	// another file) replaces the marker between fstatat and open.
	root := t.TempDir()
	build(t, root, fx{"index.html": "<html></html>", "other.html": spaIndex})
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	tr.stat("index.html")
	if err := os.Rename(filepath.Join(root, "other.html"), filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if b := tr.readPrefix("index.html", indexHTMLLimit); b != nil {
		t.Errorf("read %q from a swapped file", b)
	}
	if !slices.ContainsFunc(tr.ignored, func(i Ignored) bool { return strings.Contains(i.Reason, "changed") }) {
		t.Errorf("ignored = %+v, want a 'changed' entry", tr.ignored)
	}
}

func TestDetect_N6_SymlinkSwappedAfterStat(t *testing.T) {
	outside := t.TempDir()
	build(t, outside, fx{"spa.html": spaIndex})
	root := t.TempDir()
	build(t, root, fx{"index.html": "<html></html>"})
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	tr.stat("index.html")
	p := filepath.Join(root, "index.html")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "spa.html"), p); err != nil {
		t.Fatal(err)
	}
	if b := tr.readPrefix("index.html", indexHTMLLimit); b != nil {
		t.Errorf("followed a symlink swapped in after stat: %q", b)
	}
}

func TestDetect_N6_OwnerMismatchNotRead(t *testing.T) {
	// A hard link to a root-owned or another user's file has that file's
	// owner. Simulated by pretending the document root has another owner.
	root := fixtureDir(t, "laravel-public")
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	tr.owner++
	r := tr.detect()
	if len(r.Candidates) != 0 {
		t.Errorf("candidates = %+v, want none", r.Candidates)
	}
	if !hasIgnored(r, "index.php") {
		t.Errorf("ignored = %+v, want index.php", r.Ignored)
	}
}

func TestDetect_N6_HugeFile(t *testing.T) {
	// A sparse 1 GiB index.html: only the prefix is read.
	big := func(t *testing.T, marker string, at int64) string {
		root := t.TempDir()
		p := filepath.Join(root, "index.html")
		f, err := os.Create(p) //nolint:gosec // path inside t.TempDir
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt([]byte(marker), at); err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(1 << 30); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return root
	}
	start := time.Now()
	r := detect(t, big(t, spaIndex, 0))
	if c, ok := r.Suggestion(); !ok || c.App != React {
		t.Errorf("marker at the start: Suggestion = %+v, %v; want React", c, ok)
	}
	r = detect(t, big(t, spaIndex, 1<<29))
	if len(r.Candidates) != 0 {
		t.Errorf("marker past the read limit found: %+v", r.Candidates)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("huge files took %v", d)
	}
}

func TestDetect_PermissionErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not restrict root")
	}
	root := fixtureDir(t, "react-vite")
	build(t, root, fx{"wp-settings.php": "", "wp-includes/version.php": ""})
	chmod := func(p string, m os.FileMode) {
		t.Helper()
		if err := os.Chmod(filepath.Join(root, p), m); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, p), 0o700) }) //nolint:gosec // restores a test directory
	}
	chmod("index.html", 0)
	chmod("wp-includes", 0)
	r := detect(t, root)
	for _, c := range r.Candidates {
		if c.App == React {
			t.Errorf("React detected from an unreadable index.html: %+v", c)
		}
		if c.App == WordPress && slices.Contains(c.Evidence, "wp-includes/version.php") {
			t.Errorf("evidence from an unreadable directory: %+v", c)
		}
	}
	if !hasIgnored(r, "index.html") {
		t.Errorf("ignored = %+v, want index.html", r.Ignored)
	}

	chmod(".", 0)
	if _, err := Detect(root, me); err == nil {
		t.Error("Detect opened an unreadable document root")
	}
}

func TestOpsBudget_N1(t *testing.T) {
	// Static bound: every distinct marker path is stat'ed at most once,
	// every distinct parent directory opened and fstat'ed at most once
	// (plus one fstatat when the open fails with ENOTDIR), and two opens
	// per content check.
	paths, dirs, reads := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range signatures {
		for _, m := range append(append([]marker{}, s.required...), s.supporting...) {
			paths[m.path] = true
			for d := filepath.Dir(m.path); d != "."; d = filepath.Dir(d) {
				dirs[d] = true
			}
		}
		if s.content != nil {
			reads[s.content.path] = true
		}
	}
	bound := len(paths) + 3*len(dirs) + 2*len(reads)
	t.Logf("static bound: %d stats + 3 x %d directories + 2 x %d reads = %d (maxOps %d)",
		len(paths), len(dirs), len(reads), bound, maxOps)
	if bound > maxOps {
		t.Fatalf("rules need up to %d operations, maxOps is %d", bound, maxOps)
	}

	u := union()
	u["index.php"] = laravelIndex
	u["index.html"] = spaIndex
	for name, f := range map[string]fx{"empty": {}, "union": u, "wordpress": fixtures["wordpress"], "react-spa": fixtures["react-spa"]} {
		root := t.TempDir()
		build(t, root, f)
		tr, err := openTree(root, me)
		if err != nil {
			t.Fatal(err)
		}
		r := tr.detect()
		t.Logf("%s: %d operations, %d candidates", name, tr.ops, len(r.Candidates))
		if tr.ops > bound {
			t.Errorf("%s: %d operations, above the static bound %d", name, tr.ops, bound)
		}
		tr.close()
	}
}

func TestBudgetExhausted(t *testing.T) {
	root := fixtureDir(t, "wordpress")
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	tr.ops = maxOps
	r := tr.detect()
	if len(r.Candidates) != 0 {
		t.Errorf("candidates = %+v with no budget", r.Candidates)
	}
	if !slices.ContainsFunc(r.Ignored, func(i Ignored) bool { return strings.Contains(i.Reason, errBudget.Error()) }) {
		t.Errorf("ignored = %+v, want a budget entry", r.Ignored)
	}
	if len(r.Ignored) > maxIgnored {
		t.Errorf("%d ignored entries, limit %d", len(r.Ignored), maxIgnored)
	}
}

func TestSplitRel(t *testing.T) {
	for _, bad := range []string{"/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", "a\x00b"} {
		if _, err := splitRel(bad); err == nil {
			t.Errorf("splitRel(%q) accepted", bad)
		}
	}
	if p, err := splitRel("public_html/blog"); err != nil || len(p) != 2 {
		t.Errorf("splitRel: %v, %v", p, err)
	}
}

func TestContentCheck_UntrustedBytes(t *testing.T) {
	c := rootDiv
	for in, want := range map[string]bool{
		"":                          false,
		"\x00\xff\xfe<div id=root>": true,
		`<div id="root"`:            true,
		`<div id="rootx"`:           false,
		strings.Repeat("<", 1<<14):  false,
	} {
		if got := c.match([]byte(in)); got != want {
			t.Errorf("match(%.20q) = %v, want %v", in, got, want)
		}
	}
	if c.match(nil) {
		t.Error("match(nil) = true")
	}
}

func TestConfidenceText(t *testing.T) {
	for c, want := range map[Confidence]string{Low: "low", Medium: "medium", High: "high", 0: "confidence(0)"} {
		b, err := c.MarshalText()
		if err != nil || string(b) != want {
			t.Errorf("%d: %q, %v", c, b, err)
		}
	}
}

func TestDetect_N6_WrongOwner(t *testing.T) {
	root := fixtureDir(t, "wordpress")
	if _, err := Detect(root, me+1); err == nil {
		t.Error("Detect accepted a document root owned by someone else")
	}
	if _, err := DetectUnder(filepath.Dir(root), filepath.Base(root), me+1); err == nil {
		t.Error("DetectUnder accepted a base owned by someone else")
	}
}

// TestDetect_N6_ForeignOwnedEntries uses real foreign-owned files and
// directories, which needs root (the production identity).
func TestDetect_N6_ForeignOwnedEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	const other = 4242
	chown := func(p string) {
		t.Helper()
		if err := os.Lchown(p, other, other); err != nil {
			t.Fatal(err)
		}
	}

	// A foreign-owned file (what a hard link to another user's or
	// root's file looks like) is not read.
	root := fixtureDir(t, "laravel-public")
	chown(filepath.Join(root, "index.php"))
	r := detect(t, root)
	if len(r.Candidates) != 0 || !hasIgnored(r, "index.php") {
		t.Errorf("foreign index.php: %+v", r)
	}

	// A foreign-owned directory (another user's directory moved into
	// the client's tree) is not entered.
	root = fixtureDir(t, "wordpress")
	chown(filepath.Join(root, "wp-includes"))
	r = detect(t, root)
	for _, c := range r.Candidates {
		if slices.Contains(c.Evidence, "wp-includes/version.php") {
			t.Errorf("evidence from a foreign directory: %+v", c)
		}
	}
	if !hasIgnored(r, "wp-includes") {
		t.Errorf("ignored = %+v, want wp-includes", r.Ignored)
	}

	// The same through DetectUnder: a foreign component is refused.
	home := t.TempDir()
	build(t, home, fx{"public_html/stolen/index.php": laravelIndex})
	chown(filepath.Join(home, "public_html", "stolen"))
	if _, err := DetectUnder(home, "public_html/stolen", me); err == nil {
		t.Error("DetectUnder entered a foreign-owned directory")
	}
}

func TestDetect_N6_DeviceSwappedAfterStat(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mknod")
	}
	root := t.TempDir()
	build(t, root, fx{"index.html": spaIndex})
	tr, err := openTree(root, me)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	tr.stat("index.html")
	p := filepath.Join(root, "index.html")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(p, unix.S_IFCHR|0o600, int(unix.Mkdev(1, 5))); err != nil { //nolint:gosec // 1:5 is /dev/zero, fits in int
		t.Skipf("mknod: %v", err)
	}
	if b := tr.readPrefix("index.html", indexHTMLLimit); b != nil {
		t.Errorf("read %d bytes from a device", len(b))
	}
}

func TestDetect_T10_LaravelVariants(t *testing.T) {
	for name, index := range map[string]string{
		// Laravel 5.0 to 5.4: no LARAVEL_START.
		"5.0": "<?php\nrequire __DIR__.'/../bootstrap/autoload.php';\n$app = require_once __DIR__.'/../bootstrap/app.php';\n" +
			"$request = Illuminate\\Http\\Request::capture();\n",
		// Shared-hosting install with an edited path.
		"edited": strings.ReplaceAll(laravelIndex, "/../bootstrap/", "/../laravel/bootstrap/"),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			build(t, root, fx{"index.php": index})
			c, ok := detect(t, root).Suggestion()
			if !ok || c.App != Laravel || c.Variant != "public" {
				t.Errorf("Suggestion = %+v, %v; want Laravel public", c, ok)
			}
		})
	}
}
