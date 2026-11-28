// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fornex/fngx/internal/apply"
	"github.com/fornex/fngx/internal/model"
	"github.com/fornex/fngx/internal/userrules"
)

func TestArg(t *testing.T) { // N-6
	ok := map[string]string{
		"example.com":       "example.com",
		"/home/a/public":    "/home/a/public",
		"[2001:db8::1]:443": "[2001:db8::1]:443",
		"a b":               `"a b"`,
		`a"b`:               `"a\"b"`,
		`a\b`:               `"a\\b"`,
		"a;b{c}#d'e":        `"a;b{c}#d'e"`,
	}
	for in, want := range ok {
		a, err := newArg("test", in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if a.String() != want {
			t.Errorf("%q printed as %s, want %s", in, a, want)
		}
	}
	for _, in := range []string{"", "a$b", "${x}", "a\nb", "a\rb", "a\tb", "a\x00b", "a\x7fb", "caf\xc3\xa9"} {
		if _, err := newArg("test", in); !errors.Is(err, errUnsafe) {
			t.Errorf("%q accepted", in)
		}
	}
	if s := (Arg{}).String(); s != `"<unset>"` {
		t.Errorf("zero Arg printed as %s", s)
	}
}

// TestInjection feeds hostile values into every input field that reaches the
// configuration and expects validation to refuse them (N-6). Values of the
// model types are built by conversion to bypass their parsers.
func TestInjection(t *testing.T) {
	r := newRenderer(t)
	e := goldenEnv()
	hostile := []string{
		"/home/a;\n}\nserver {", "/home/a b", "/home/a$document_root", "/home/a\"", "/home/a'",
		"/home/a{", "/home/a}", "/home/a#", "/home/a\\b", "relative/path", "/home/../etc",
		"/home/a/", "/home/a\x00", "/home/caf\xc3\xa9", "/home/a*", "/home/a?",
	}
	type mutate func(s *Server, d *Domain, v string)
	fields := map[string]mutate{
		"docroot": func(_ *Server, d *Domain, v string) { d.DocRoot = v },
		"cert":    func(_ *Server, d *Domain, v string) { d.TLS = &TLS{Cert: v, Key: "/k"} },
		"key":     func(_ *Server, d *Domain, v string) { d.TLS = &TLS{Cert: "/c", Key: v} },
		"socket": func(_ *Server, d *Domain, v string) {
			d.Settings.Mode.Value = model.ModeNginx
			d.PHPSocket = v
		},
		"pid":     func(s *Server, _ *Domain, v string) { s.PIDFile = v },
		"errlog":  func(s *Server, _ *Domain, v string) { s.ErrorLog = v },
		"acclog":  func(s *Server, _ *Domain, v string) { s.AccessLog = v },
		"mime":    func(s *Server, _ *Domain, v string) { s.MimeTypes = v },
		"tempdir": func(s *Server, _ *Domain, v string) { s.TempDir = v },
		"name":    func(_ *Server, d *Domain, v string) { d.Name = model.Domain("a" + v + ".com") },
		"alias":   func(_ *Server, d *Domain, v string) { d.Aliases = []model.Domain{model.Domain(v)} },
		"user":    func(_ *Server, d *Domain, v string) { d.User = model.User("a" + v) },
		"srvuser": func(s *Server, _ *Domain, v string) { s.User = "a" + v },
		"ext":     func(s *Server, _ *Domain, v string) { s.StaticExtensions = []string{"png" + v} },
		"app": func(s *Server, d *Domain, v string) {
			d.Settings.Mode.Value = model.ModeNginx
			d.Settings.AppTemplate.Value = model.TemplateName(v)
			s.AppTemplates = map[model.TemplateName]string{model.TemplateName(v): ""}
		},
		"kind": func(_ *Server, d *Domain, v string) { d.Kind = Kind(v) },
		"mode": func(_ *Server, d *Domain, v string) { d.Settings.Mode.Value = model.Mode("proxy" + v) },
	}
	for name, f := range fields {
		for _, v := range hostile {
			s, d := e.baseServer(), e.domain("example.com", model.ModeProxy)
			f(&s, &d, v)
			if u, err := r.Domain(&s, &d); err == nil {
				t.Errorf("%s=%q accepted:\n%s", name, v, goldenText(u.Files))
			}
		}
	}
	// Admin text is trusted but must be text.
	s, d := e.baseServer(), e.domain("example.com", model.ModeProxy)
	d.Admin.HTTPInclude = "deny all;\x00"
	if _, err := r.Domain(&s, &d); err == nil {
		t.Error("admin text with NUL accepted")
	}
}

// TestHostileAdminTextStaysInItsFile shows why admin texts go into files of
// their own: whatever they contain, the vhost file only has an include line.
func TestHostileAdminTextStaysInItsFile(t *testing.T) { // T-6, N-6
	r := newRenderer(t)
	e := goldenEnv()
	s, d := e.baseServer(), e.domain("example.com", model.ModeProxy)
	d.Admin.HTTPInclude = "}\nserver { listen 81; }\n"
	u, err := r.Domain(&s, &d)
	if err != nil {
		t.Fatal(err)
	}
	vhost := string(u.Files[len(u.Files)-1].Data)
	if strings.Contains(vhost, "listen 81") || !strings.Contains(vhost, "include domains/example.com/http-include.conf;") {
		t.Errorf("admin text leaked into the vhost file:\n%s", vhost)
	}
}

func FuzzDocRoot(f *testing.F) { // N-6
	for _, s := range []string{"/home/a/public_html", "/home/a b", "/x;y", "/x\n}", "/a$b", "/a/./b"} {
		f.Add(s)
	}
	r := newRenderer(f)
	e := goldenEnv()
	f.Fuzz(func(t *testing.T, root string) {
		s, d := e.baseServer(), e.domain("example.com", model.ModeNginx)
		d.DocRoot = root
		u, err := r.Domain(&s, &d)
		if err != nil {
			return
		}
		want := "    root " + root + ";\n"
		vhost := string(fileData(t, u, vhostPath(d.Name)))
		if strings.Count(vhost, want) != 1 {
			t.Fatalf("root %q not printed as one token:\n%s", root, vhost)
		}
		// Nothing else changed: the output equals the output for a plain
		// root with the root replaced.
		d.DocRoot = "/plain"
		u2, err := r.Domain(&s, &d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ReplaceAll(vhost, want, "    root /plain;\n") != string(fileData(t, u2, vhostPath(d.Name))) {
			t.Fatalf("root %q changed more than the root line", root)
		}
	})
}

func fileData(t testing.TB, u apply.Unit, path string) []byte {
	t.Helper()
	for _, f := range u.Files {
		if f.Path == path {
			return f.Data
		}
	}
	t.Fatalf("unit %s has no %s", u.ID, path)
	return nil
}

func TestClientReservedLocation(t *testing.T) { // T-7, T-9
	r := newRenderer(t)
	e := goldenEnv()
	v, err := userrules.New(userrules.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"location / { expires 1h; }", "location ^~ / { expires 1h; }"} {
		rules, err := v.Validate([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		s, d := e.baseServer(), e.domain("example.com", model.ModeNginx)
		d.Client = rules
		if _, err := r.Domain(&s, &d); err == nil || !strings.Contains(err.Error(), "defined by the template") {
			t.Errorf("%q: got %v", text, err)
		}
	}
	rules, err := v.Validate([]byte("location = / { expires 1h; }\nlocation /x/ { expires 1h; }"))
	if err != nil {
		t.Fatal(err)
	}
	s, d := e.baseServer(), e.domain("example.com", model.ModeNginx)
	d.Client = rules
	if _, err := r.Domain(&s, &d); err != nil {
		t.Errorf("specific locations refused: %v", err)
	}
}

// TestClientLocationMode checks that client location blocks render only in
// nginx mode (T-7, T-8, customer decision 26): a domain whose rules were
// accepted in nginx mode and later switched to proxy or hybrid must fail
// instead of serving files from disk past Apache.
func TestClientLocationMode(t *testing.T) {
	r := newRenderer(t)
	e := goldenEnv()
	v, err := userrules.New(userrules.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		text        string
		hasLocation bool
	}{
		{"", false},
		{"expires 1h;\nadd_header X-A b;\n", false},
		{"rewrite ^/a$ /b permanent;\n", false},
		{"location = /x { return 404; }\n", true},
		{"deny all;\nlocation ~ \\.png$ {}\n", true},
		{"location /a/ {\n    location /a/b/ { expires 1h; }\n}\n", true},
	}
	for _, mode := range []model.Mode{model.ModeProxy, model.ModeHybrid, model.ModeNginx} {
		for _, tt := range tests {
			text, hasLocation := tt.text, tt.hasLocation
			rules, err := v.Validate([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			s, d := e.baseServer(), e.domain("example.com", mode)
			d.Client = rules
			_, err = r.Domain(&s, &d)
			if !hasLocation || mode == model.ModeNginx {
				if err != nil {
					t.Errorf("%s, %q: %v", mode, text, err)
				}
				continue
			}
			want := fmt.Sprintf("render: domain %q: client rules in %s mode: line ", d.Name, mode)
			var ue *userrules.Error
			if err == nil || !strings.HasPrefix(err.Error(), want) || !errors.As(err, &ue) ||
				!strings.Contains(ue.Reason, "only in nginx mode") {
				t.Errorf("%s, %q: got %v, want prefix %q and a userrules.Error", mode, text, err, want)
			}
		}
	}

	// A reserved location outside nginx mode gets only the mode error, not
	// the advice to use a more specific location.
	reserved, err := v.Validate([]byte("location / { expires 1h; }"))
	if err != nil {
		t.Fatal(err)
	}
	s, d := e.baseServer(), e.domain("example.com", model.ModeProxy)
	d.Client = reserved
	if _, err := r.Domain(&s, &d); err == nil || !strings.Contains(err.Error(), "only in nginx mode") ||
		strings.Contains(err.Error(), "defined by the template") {
		t.Errorf("reserved location in proxy mode: got %v", err)
	}

	// All fails only the affected domain.
	s = e.baseServer()
	bad := e.domain("bad.example", model.ModeHybrid)
	bad.Client = clientRules(t)
	good := e.domain("good.example", model.ModeProxy)
	good.Client = clientSimpleRules(t)
	res, err := r.All(&s, []Domain{bad, good})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 || res.Failed[0].Domain != "bad.example" || len(res.Change.Units) != 1 || res.Change.Full {
		t.Errorf("All: failed %v, units %d, full %v", res.Failed, len(res.Change.Units), res.Change.Full)
	}
}

func TestCustomTemplates(t *testing.T) { // T-3
	custom := fstest.MapFS{
		"proxy.conf.tmpl": {Data: []byte(`# custom {{.Domain}}
{{- range .Servers}}
server {
{{- template "listen" .}}
    server_name {{join $.Names " "}};
    root {{$.Root}};
    location / {
{{- template "proxy" .}}
    }
    add_header X-Custom {{q "custom value"}};
}
{{- end}}
`)},
		"README.txt": {Data: []byte("ignored")},
	}
	r, err := New(Config{Custom: custom})
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsCustom(model.ModeProxy) || r.IsCustom(model.ModeNginx) {
		t.Error("IsCustom is wrong")
	}
	e := goldenEnv()
	s, d := e.baseServer(), e.domain("example.com", model.ModeProxy)
	d.Aliases = []model.Domain{"www.example.com"}
	u, err := r.Domain(&s, &d)
	if err != nil {
		t.Fatal(err)
	}
	got := string(u.Files[0].Data)
	for _, want := range []string{"# custom example.com", "server_name example.com www.example.com;", `add_header X-Custom "custom value";`, "proxy_pass http://127.0.0.1:8080;"} {
		if !strings.Contains(got, want) {
			t.Errorf("custom output lacks %q:\n%s", want, got)
		}
	}
	// Other modes keep the built-in template.
	d.Settings.Mode.Value = model.ModeNginx
	u, err = r.Domain(&s, &d)
	if err != nil {
		t.Fatal(err)
	}
	builtin, _ := newRenderer(t).Domain(&s, &d)
	if !bytes.Equal(u.Files[0].Data, builtin.Files[0].Data) {
		t.Error("nginx mode does not use the built-in template")
	}

	for name, fsys := range map[string]fstest.MapFS{
		"unknown mode":  {"apache.conf.tmpl": {Data: []byte("x")}},
		"parse error":   {"nginx.conf.tmpl": {Data: []byte("{{if}}")}},
		"unknown field": {"nginx.conf.tmpl": {Data: []byte("{{.Nope}}")}},
	} {
		r, err := New(Config{Custom: fsys})
		if name == "unknown field" {
			// text/template reports unknown fields at execution.
			if err != nil {
				t.Fatal(err)
			}
			d := e.domain("example.com", model.ModeNginx)
			if _, err := r.Domain(&s, &d); err == nil {
				t.Errorf("%s: no error", name)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	// q refuses what it cannot make safe.
	r, err = New(Config{Custom: fstest.MapFS{"nginx.conf.tmpl": {Data: []byte(`{{q "a$b"}}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	d = e.domain("example.com", model.ModeNginx)
	if _, err := r.Domain(&s, &d); err == nil {
		t.Error(`q "a$b" did not fail`)
	}
}

func TestBuiltin(t *testing.T) { // T-3
	for _, n := range []string{"proxy.conf.tmpl", "hybrid.conf.tmpl", "nginx.conf.tmpl", "common.tmpl", "main.conf.tmpl"} {
		if b, err := Builtin(n); err != nil || len(b) == 0 {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"../render.go", "snippets/proxy.conf", "nope.tmpl"} {
		if _, err := Builtin(n); err == nil {
			t.Errorf("%s: no error", n)
		}
	}
}

func TestAll(t *testing.T) { // N-4
	r := newRenderer(t)
	e := goldenEnv()
	s := e.baseServer()
	a := e.domain("a.example", model.ModeProxy)
	b := e.domain("b.example", model.ModeHybrid)
	b.Aliases = []model.Domain{"a.example", "shared.example"}
	c := e.domain("c.example", model.ModeNginx)
	c.Aliases = []model.Domain{"shared.example"}
	res, err := r.All(&s, []Domain{c, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Change.Full || len(res.Failed) != 0 || len(res.Change.Units) != 3 {
		t.Fatalf("unexpected result: full=%v failed=%v units=%d", res.Change.Full, res.Failed, len(res.Change.Units))
	}
	for i, id := range []string{"a.example", "b.example", "c.example"} {
		if res.Change.Units[i].ID != id {
			t.Errorf("unit %d is %q, want %q", i, res.Change.Units[i].ID, id)
		}
	}
	if len(res.Warnings) != 2 {
		t.Errorf("want 2 warnings about shared names, got %q", res.Warnings)
	}
	if err := checkApplyPaths(res.Change); err != nil {
		t.Error(err)
	}

	bad := e.domain("bad.example", model.ModeProxy)
	bad.DocRoot = "/home/x;y"
	res, err = r.All(&s, []Domain{a, bad, a})
	if err != nil {
		t.Fatal(err)
	}
	if res.Change.Full || len(res.Change.Units) != 1 || len(res.Failed) != 2 {
		t.Errorf("a failed domain must make the change incremental: full=%v units=%d failed=%v", res.Change.Full, len(res.Change.Units), res.Failed)
	}

	s.PIDFile = "relative"
	if _, err := r.All(&s, []Domain{a}); err == nil {
		t.Error("invalid server accepted")
	}
}

type noopNginx struct{}

func (noopNginx) Test(context.Context, string) (string, error)   { return "", nil }
func (noopNginx) Reload(context.Context, string) (string, error) { return "", nil }

// checkApplyPaths runs a change through internal/apply with a fake nginx,
// which checks unit IDs and paths against the engine's rules.
func checkApplyPaths(ch apply.Change) error {
	dir, err := os.MkdirTemp("", "render-paths")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	e, err := apply.New(apply.Config{Root: dir, Keep: 1, MaxTests: 1, Nginx: noopNginx{}, Logger: apply.NewLogger(io.Discard)})
	if err != nil {
		return err
	}
	_, err = e.Check(context.Background(), ch)
	return err
}

func TestDeterministic(t *testing.T) { // N-1
	r := newRenderer(t)
	e := goldenEnv()
	s := e.baseServer()
	domains := manyDomains(e, 500)
	first, err := r.All(&s, domains)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // shuffling test input
	rng.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })
	second, err := r.All(&s, domains)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Change, second.Change) {
		t.Error("output depends on input order")
	}
}

func TestServerValidate(t *testing.T) {
	e := goldenEnv()
	bad := map[string]func(s *Server){
		"same ports":     func(s *Server) { s.HTTPSPort = s.HTTPPort },
		"port 0":         func(s *Server) { s.HTTPPort = 0 },
		"no protocols":   func(s *Server) { s.SSLProtocols = nil },
		"bad protocol":   func(s *Server) { s.SSLProtocols = []string{"SSLv3"} },
		"h3 without 1.3": func(s *Server) { s.SSLProtocols = []string{"TLSv1.2"} },
		"dup address":    func(s *Server) { s.Addresses = []netip.Addr{e.dedicated4} },
		"wildcard addr":  func(s *Server) { s.Addresses = []netip.Addr{netip.MustParseAddr("0.0.0.0")} },
		"apache port 0":  func(s *Server) { s.Apache.HTTP = netip.MustParseAddrPort("127.0.0.1:0") },
		"apache zero":    func(s *Server) { s.Apache.HTTP = netip.AddrPort{} },
		"connections":    func(s *Server) { s.WorkerConnections = 0 },
		"app none":       func(s *Server) { s.AppTemplates = map[model.TemplateName]string{"none": ""} },
		"apache on 80":   func(s *Server) { s.Apache.HTTP = netip.MustParseAddrPort("127.0.0.1:80") },
		"apache on ded.": func(s *Server) { s.Apache.HTTPS = netip.AddrPortFrom(e.dedicated4, 443) },
		"body size":      func(s *Server) { s.ClientMaxBodySize = "1gb" },
		"body size 2":    func(s *Server) { s.ClientMaxBodySize = "" },
		"body size 3":    func(s *Server) { s.ClientMaxBodySize = "m" },
	}
	for name, f := range bad {
		s := e.baseServer()
		f(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := e.baseServer()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	// Apache on port 80 of an address nginx does not listen on is fine.
	s.Addresses = []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	s.Apache.HTTP = netip.MustParseAddrPort("127.0.0.1:80")
	for _, v := range []string{"0", "512", "10k", "1M", "2g"} {
		s.ClientMaxBodySize = v
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	s = e.baseServer()
	d := e.domain("example.com", model.ModeProxy)
	d.IPs = []netip.Addr{netip.MustParseAddr("192.0.2.99")}
	if err := d.Validate(&s); err == nil {
		t.Error("unknown dedicated address accepted")
	}
	s.Apache = nil
	d = e.domain("example.com", model.ModeHybrid)
	if err := d.Validate(&s); err == nil {
		t.Error("hybrid without Apache accepted")
	}
	d = e.domain("example.com", model.ModeNginx)
	d.Settings.AppTemplate.Value = "wordpress"
	if err := d.Validate(&s); err == nil {
		t.Error("missing app template accepted")
	}
}

// TestPIDMatchesApply guards the contract with internal/apply: the engine
// signals the master through this PID file.
func TestPIDMatchesApply(t *testing.T) {
	r := newRenderer(t)
	s := DefaultServer()
	files, err := r.Common(&s)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == apply.DefaultMainFile {
			if !bytes.Contains(f.Data, []byte("\npid "+apply.DefaultPIDFile+";\n")) {
				t.Errorf("main file does not set pid %s", apply.DefaultPIDFile)
			}
			return
		}
	}
	t.Fatalf("no %s in common files", apply.DefaultMainFile)
}

// TestTemplateDocs checks that docs/templates.md names every template
// variable (T-5).
func TestTemplateDocs(t *testing.T) {
	doc, err := os.ReadFile("../../docs/templates.md")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	var walk func(prefix string, typ reflect.Type)
	walk = func(prefix string, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			if typ.Kind() == reflect.Slice {
				prefix += "[]"
			}
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ == reflect.TypeFor[Arg]() {
			want = append(want, prefix)
			return
		}
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.IsExported() {
				walk(prefix+"."+f.Name, f.Type)
			}
		}
	}
	walk("", reflect.TypeFor[VhostData]())
	walk("", reflect.TypeFor[MainData]())
	for _, w := range want {
		if !bytes.Contains(doc, []byte("`"+w+"`")) {
			t.Errorf("docs/templates.md does not document `%s`", w)
		}
	}
}

func BenchmarkAll10000(b *testing.B) { // N-1, N-2
	r := newRenderer(b)
	e := goldenEnv()
	s := e.baseServer()
	domains := manyDomains(e, 10000)
	b.ReportAllocs()
	for b.Loop() {
		res, err := r.All(&s, domains)
		if err != nil || len(res.Failed) > 0 {
			b.Fatal(err, res.Failed)
		}
	}
}
