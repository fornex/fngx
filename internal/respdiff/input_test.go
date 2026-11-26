// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTargets_N6(t *testing.T) {
	in := `# migration list
example.com
  Example.COM
www.example.com/shop?id=1

xn--80ak6aa92e.com/
example.com/
`
	got, err := ParseTargets(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, tg := range got {
		s = append(s, tg.String())
	}
	want := "example.com www.example.com/shop?id=1 xn--80ak6aa92e.com"
	if strings.Join(s, " ") != want {
		t.Errorf("got %q, want %q", s, want)
	}

	for _, bad := range []string{
		"", "# only comments\n",
		"http://example.com\n",
		"example.com/a b\n",
		"example.com/a#frag\n",
		"example.com//evil.org\n",
		"exa mple.com\n",
		"пример.рф\n",
		"127.0.0.1\n",
		"example.com/\x00\n",
		"example.com:8080\n",
		"example.com/" + strings.Repeat("a", 3000) + "\n",
	} {
		if _, err := ParseTargets(strings.NewReader(bad)); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseTargets(%q) error = %v, want ErrInvalid", bad, err)
		}
	}
	_, err = ParseTargets(strings.NewReader("example.com\nbad_domain.com\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error lacks line number: %v", err)
	}
}

func TestTargetURL(t *testing.T) {
	tg, _ := ParseTarget("example.com/a?b")
	for _, c := range []struct {
		scheme string
		port   int
		want   string
	}{
		{"http", 80, "http://example.com/a?b"},
		{"https", 443, "https://example.com/a?b"},
		{"https", 8443, "https://example.com:8443/a?b"},
	} {
		if got := tg.URL(c.scheme, c.port); got != c.want {
			t.Errorf("URL(%s, %d) = %q, want %q", c.scheme, c.port, got, c.want)
		}
	}
}

func TestRules(t *testing.T) {
	c, err := compileRules(nil)
	if err != nil {
		t.Fatalf("default rules: %v", err)
	}
	in := []byte(`<meta name="csrf-token" content="abc"><input type="hidden" value="v1" name="_token">` +
		`<input type="hidden" name="0123456789abcdef0123456789abcdef" value="1"><p>keep</p>`)
	got := string(c.normalizeBody(in))
	want := `<meta name="csrf-token" content="-"><input type="hidden" value="-" name="_token">` +
		`<input type="hidden" name="-" value="1"><p>keep</p>`
	if got != want {
		t.Errorf("normalizeBody:\n got %s\nwant %s", got, want)
	}

	for _, bad := range []string{
		`{"body_patterns":[{"name":"x","regexp":"("}]}`,
		`{"body_patterns":[{"name":"x","regexp":"abc"}]}`,
		`{"body_patterns":[{"name":"x","regexp":"(a)(b)"}]}`,
		`{"body_patterns":[{"regexp":"(a)"}]}`,
		`{"header_patterns":[{"name":"x","regexp":"(a)"}]}`,
		`{"headers":[{"names":[],"severity":"info"}]}`,
		`{"headers":[{"names":["a b"],"severity":"info"}]}`,
		`{"headers":[{"names":["X"],"severity":"info"},{"names":["x"],"severity":"warning"}]}`,
	} {
		r, err := ParseRules([]byte(bad))
		if err == nil {
			_, err = compileRules(&r)
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("rules %s: error %v, want ErrInvalid", bad, err)
		}
	}
	for _, bad := range []string{`{"unknown":1}`, `{"headers":[{"names":["x"],"severity":"loud"}]}`, `{} {}`} {
		if _, err := ParseRules([]byte(bad)); err == nil {
			t.Errorf("ParseRules(%s) accepted", bad)
		}
	}

	// The fingerprint depends on the body patterns only.
	r, _ := ParseRules([]byte(`{"other_headers":"ignore"}`))
	c2, _ := compileRules(&r)
	if c2.bodyFP != c.bodyFP {
		t.Error("header-only rules changed the body fingerprint")
	}
	r, _ = ParseRules([]byte(`{"body_patterns":[{"name":"ts","regexp":"generated at (\\d+)"}]}`))
	c3, err := compileRules(&r)
	if err != nil || c3.bodyFP == c.bodyFP || len(c3.body) != len(c.body)+1 {
		t.Errorf("extra body pattern: err %v", err)
	}
	r, _ = ParseRules([]byte(`{"no_defaults":true}`))
	c4, _ := compileRules(&r)
	if len(c4.body) != 0 || len(c4.header) != 0 || c4.other != SevInfo {
		t.Errorf("no_defaults: %+v", c4)
	}
}

func TestSnapshotFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	s := snapOf(ok("http"), ok("https"))
	if err := s.WriteFile(path, false); err != nil {
		t.Fatal(err)
	}
	// A failed final step keeps the complete snapshot and names it.
	err := s.WriteFile(path, false)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") || !strings.Contains(err.Error(), "kept in") {
		t.Errorf("second write: %v", err)
	}
	kept, _ := filepath.Glob(filepath.Join(dir, ".respdiff-*"))
	if len(kept) != 1 {
		t.Fatalf("kept files: %v", kept)
	}
	if _, err := LoadSnapshotFile(kept[0]); err != nil {
		t.Errorf("kept snapshot: %v", err)
	}
	_ = os.Remove(kept[0])
	if err := s.WriteFile(path, true); err != nil {
		t.Errorf("overwrite: %v", err)
	}
	var fi os.FileInfo
	fi, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	back, err := LoadSnapshotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != 2 || back.Results[1].TLS.CertSHA256 != "c1" {
		t.Errorf("round trip: %+v", back)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".respdiff-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestLoadSnapshotRejects(t *testing.T) {
	good := string(mustJSON(t, snapOf(ok("http"))))
	for name, data := range map[string]string{
		"trailing":     good + "{}",
		"unknown":      strings.Replace(good, `"version"`, `"extra":1,"version"`, 1),
		"version":      strings.Replace(good, `"version":1`, `"version":2`, 1),
		"server":       strings.Replace(good, `192.0.2.1`, `example.com`, 1),
		"method":       strings.Replace(good, `"GET"`, `"POST"`, 1),
		"tls mode":     strings.Replace(good, `"strict"`, `"off"`, 1),
		"scheme":       strings.Replace(good, `"http"`, `"ftp"`, 1),
		"target":       strings.Replace(good, `"example.com"`, `"bad domain"`, 1),
		"noncanonical": strings.Replace(good, `"example.com"`, `"Example.com"`, 1),
		"status":       strings.Replace(good, `"status":200`, `"status":7`, 1),
		"duplicate":    strings.Replace(good, `"results":[`, `"results":[`+string(mustJSON(t, ok("http")))+",", 1),
	} {
		if _, err := LoadSnapshot([]byte(data)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error %v, want ErrInvalid", name, err)
		}
	}
}

func FuzzLoadSnapshot(f *testing.F) {
	f.Add(mustJSON(f, snapOf(ok("http"), ok("https"))))
	f.Add(mustJSON(f, snapOf()))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"server":"::1","options":{"method":"HEAD","tls_mode":"record"},"results":[{"target":"a.example","scheme":"https","error":{"kind":"timeout"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := LoadSnapshot(data)
		if err != nil {
			return
		}
		// A loaded snapshot can be saved, reloaded and compared.
		s2, err := LoadSnapshot(mustJSON(t, s))
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		rep, err := Compare(s, s2, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Diffs) != 0 {
			t.Fatalf("snapshot differs from its own copy: %+v", rep.Diffs)
		}
	})
}

func FuzzParseTarget(f *testing.F) {
	for _, s := range []string{"example.com", "example.com/a?b=c", "a.b/%zz", "x.y?"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tg, err := ParseTarget(s)
		if err != nil {
			return
		}
		back, err := ParseTarget(tg.String())
		if err != nil || back != tg {
			t.Fatalf("round trip %q -> %q -> %+v, %v", s, tg.String(), back, err)
		}
	})
}
