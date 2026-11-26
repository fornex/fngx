// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"text/template"

	"github.com/fornex/fngx/internal/apply"
	"github.com/fornex/fngx/internal/model"
)

//go:embed templates/builtin
var builtinFS embed.FS

const builtinDir = "templates/builtin"

// TemplateExt is the file extension of vhost templates.
const TemplateExt = ".conf.tmpl"

// commonTemplate holds the helper templates every vhost template can call.
const commonTemplate = "common.tmpl"

// Config configures a Renderer.
type Config struct {
	// Custom holds the admin's own vhost templates (T-3), stored apart from
	// the built-in ones, for example os.DirFS("/etc/<product>/templates").
	// A file named <mode>.conf.tmpl replaces the built-in template of that
	// mode. nil means built-in templates only.
	Custom fs.FS
}

// Renderer turns server and domain input into nginx configuration files
// for internal/apply (A-4). It is safe for concurrent use.
type Renderer struct {
	main   *template.Template
	vhost  map[model.Mode]*template.Template
	custom map[model.Mode]bool
}

func funcs() template.FuncMap {
	return template.FuncMap{"q": quoteFunc, "join": joinFunc}
}

func modes() []model.Mode { return []model.Mode{model.ModeProxy, model.ModeHybrid, model.ModeNginx} }

// New parses the built-in templates and the custom ones in cfg.Custom.
func New(cfg Config) (*Renderer, error) {
	common, err := builtinFS.ReadFile(builtinDir + "/" + commonTemplate)
	if err != nil {
		return nil, err
	}
	base, err := template.New(commonTemplate).Funcs(funcs()).Option("missingkey=error").Parse(string(common))
	if err != nil {
		return nil, fmt.Errorf("render: built-in %s: %w", commonTemplate, err)
	}
	mainText, err := builtinFS.ReadFile(builtinDir + "/main.conf.tmpl")
	if err != nil {
		return nil, err
	}
	mainTpl, err := template.Must(base.Clone()).New("main.conf.tmpl").Parse(string(mainText))
	if err != nil {
		return nil, fmt.Errorf("render: built-in main.conf.tmpl: %w", err)
	}
	r := &Renderer{main: mainTpl, vhost: map[model.Mode]*template.Template{}, custom: map[model.Mode]bool{}}

	customText := map[model.Mode]string{}
	if cfg.Custom != nil {
		entries, err := fs.ReadDir(cfg.Custom, ".")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("render: custom templates: %w", err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, TemplateExt) {
				continue
			}
			m, err := model.ParseMode(strings.TrimSuffix(name, TemplateExt))
			if err != nil {
				return nil, fmt.Errorf("render: custom template %q: name must be <mode>%s: %w", name, TemplateExt, err)
			}
			data, err := fs.ReadFile(cfg.Custom, name)
			if err != nil {
				return nil, fmt.Errorf("render: custom template %q: %w", name, err)
			}
			customText[m] = string(data)
		}
	}
	for _, m := range modes() {
		name := string(m) + TemplateExt
		text, ok := customText[m]
		if !ok {
			b, err := builtinFS.ReadFile(builtinDir + "/" + name)
			if err != nil {
				return nil, err
			}
			text = string(b)
		}
		t, err := template.Must(base.Clone()).New(name).Parse(text)
		if err != nil {
			src := "built-in"
			if ok {
				src = "custom"
			}
			return nil, fmt.Errorf("render: %s template %s: %w", src, name, err)
		}
		r.vhost[m] = t
		r.custom[m] = ok
	}
	return r, nil
}

// IsCustom reports whether mode m uses the admin's own template (T-3).
func (r *Renderer) IsCustom(m model.Mode) bool { return r.custom[m] }

// Builtin returns the text of a built-in template, so that the admin can
// copy it as a starting point (T-3). name is "<mode>.conf.tmpl",
// "common.tmpl" or "main.conf.tmpl".
func Builtin(name string) ([]byte, error) {
	if path.Base(name) != name || !strings.HasSuffix(name, ".tmpl") {
		return nil, fmt.Errorf("render: no built-in template %q", name)
	}
	return builtinFS.ReadFile(builtinDir + "/" + name)
}

// Common returns the files shared by all domains: the main file, the
// snippets and the application templates. They depend only on s, so a
// change of one domain never needs them regenerated.
func (r *Renderer) Common(s *Server) ([]apply.File, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("render: server: %w", err)
	}
	return r.common(s)
}

func (r *Renderer) common(s *Server) ([]apply.File, error) {
	var buf bytes.Buffer
	if err := r.main.Execute(&buf, buildMain(s)); err != nil {
		return nil, fmt.Errorf("render: main file: %w", err)
	}
	files := []apply.File{{Path: mainFile, Data: bytes.Clone(buf.Bytes())}}
	for _, p := range []string{proxySnippet, fcgiSnippet} {
		data, err := builtinFS.ReadFile(builtinDir + "/" + p)
		if err != nil {
			return nil, err
		}
		files = append(files, apply.File{Path: p, Data: data})
	}
	names := make([]model.TemplateName, 0, len(s.AppTemplates))
	for n := range s.AppTemplates {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		text := s.AppTemplates[n]
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		files = append(files, apply.File{Path: appPath(n), Data: []byte(text)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// Domain renders one domain into an apply unit whose ID is the domain name
// (N-4). The server input is validated as well; to render many domains use
// All, which validates it once.
func (r *Renderer) Domain(s *Server, d *Domain) (apply.Unit, error) {
	if err := s.Validate(); err != nil {
		return apply.Unit{}, fmt.Errorf("render: server: %w", err)
	}
	return r.domain(s, d, nil)
}

func (r *Renderer) domain(s *Server, d *Domain, buf *bytes.Buffer) (apply.Unit, error) {
	if err := d.Validate(s); err != nil {
		return apply.Unit{}, fmt.Errorf("render: domain %q: %w", d.Name, err)
	}
	v, extra := buildVhost(s, d)
	if buf == nil {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	if err := r.vhost[d.Settings.Mode.Value].Execute(buf, v); err != nil {
		return apply.Unit{}, fmt.Errorf("render: domain %q: %w", d.Name, err)
	}
	u := apply.Unit{ID: string(d.Name), Files: make([]apply.File, 0, 1+len(extra))}
	u.Files = append(u.Files, apply.File{Path: vhostPath(d.Name), Data: bytes.Clone(buf.Bytes())})
	for _, f := range extra {
		u.Files = append(u.Files, apply.File{Path: f.path, Data: []byte(f.data)})
	}
	sort.Slice(u.Files, func(i, j int) bool { return u.Files[i].Path < u.Files[j].Path })
	return u, nil
}

// DomainError is a domain that could not be rendered.
type DomainError struct {
	Domain model.Domain
	Err    error
}

func (e DomainError) Error() string { return e.Err.Error() }

// Result is the output of All.
type Result struct {
	// Change holds the common files and one unit per rendered domain, in
	// a deterministic order (units sorted by vhost file name). It is a full change (apply.Change.Full) only
	// if every domain rendered; otherwise it is incremental, so that the
	// live configuration of a failed domain is kept instead of removed
	// (N-4), and the caller must remove deleted domains itself.
	Change apply.Change
	// Failed lists the domains that were not rendered, sorted by name.
	Failed []DomainError
	// Warnings lists server names used by more than one domain. For
	// domains on the same address nginx accepts that with a "conflicting
	// server name" warning and only one of the server blocks gets the name
	// (assumption: the first in file order; the warning names that domain
	// first).
	Warnings []string
}

// All renders the complete configuration: common files and every domain.
// An invalid server input fails the whole call; an invalid domain only
// fails that domain.
func (r *Renderer) All(s *Server, domains []Domain) (*Result, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("render: server: %w", err)
	}
	common, err := r.common(s)
	if err != nil {
		return nil, err
	}
	order := make([]int, len(domains))
	for i := range order {
		order[i] = i
	}
	// Sort by vhost file name: nginx reads "vhosts/*.conf" in that order
	// (glob(3) sorts), which decides which block keeps a duplicate name.
	// It differs from sorting by name: "a.com-x.net.conf" < "a.com.conf".
	sort.SliceStable(order, func(a, b int) bool {
		return vhostPath(domains[order[a]].Name) < vhostPath(domains[order[b]].Name)
	})

	res := &Result{Change: apply.Change{Common: common, Units: make([]apply.Unit, 0, len(domains))}}
	owner := make(map[model.Domain]model.Domain, len(domains)*2)
	var buf bytes.Buffer
	for i, idx := range order {
		d := &domains[idx]
		if i > 0 && d.Name == domains[order[i-1]].Name {
			res.Failed = append(res.Failed, DomainError{d.Name, fmt.Errorf("render: domain %q listed more than once", d.Name)})
			continue
		}
		u, err := r.domain(s, d, &buf)
		if err != nil {
			res.Failed = append(res.Failed, DomainError{d.Name, err})
			continue
		}
		res.Change.Units = append(res.Change.Units, u)
		for _, n := range append([]model.Domain{d.Name}, d.Aliases...) {
			if prev, ok := owner[n]; ok && prev != d.Name {
				res.Warnings = append(res.Warnings, fmt.Sprintf("server name %q is used by both %q and %q", n, prev, d.Name))
				continue
			}
			owner[n] = d.Name
		}
	}
	res.Change.Full = len(res.Failed) == 0
	return res, nil
}
