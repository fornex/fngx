// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/fornex/fngx/internal/apply"
	"github.com/fornex/fngx/internal/model"
	"github.com/fornex/fngx/internal/product"
	"github.com/fornex/fngx/internal/userrules"
)

// Server holds the server-wide input of the generator. The cPanel adapter
// fills it from cPanel data and the server settings; nothing here is read
// from cPanel files by this package.
type Server struct {
	// User is the account nginx worker processes run as ("user"
	// directive, https://nginx.org/en/docs/ngx_core_module.html#user).
	// Empty omits the directive. Default: "nobody" (assumption: the
	// account that has read access to cPanel document roots).
	User string

	// PIDFile must equal apply.ExecNginx.PIDFile, which is how the apply
	// engine finds the master process to reload it.
	PIDFile string
	// ErrorLog is the main error log file.
	ErrorLog string
	// AccessLog is the http-level access log; empty turns it off.
	AccessLog string
	// MimeTypes is the absolute path of the MIME types map installed with
	// nginx. It lives outside the generated set.
	MimeTypes string
	// TempDir, when set, holds the client body and proxy/FastCGI temp
	// directories instead of the paths compiled into nginx.
	TempDir string
	// WorkerConnections is the "worker_connections" value.
	WorkerConnections int
	// ClientMaxBodySize is the largest request body nginx accepts
	// ("client_max_body_size", for example "1g"; "0" means no limit). The
	// nginx default of 1m would break uploads that Apache accepts.
	ClientMaxBodySize string

	// Addresses are the shared addresses nginx listens on. Empty means
	// all IPv4 addresses (and IPv6 with IPv6 set).
	Addresses []netip.Addr
	// IPv6 adds "[::]" when Addresses is empty.
	IPv6 bool
	// Dedicated lists every dedicated IP of the server (A-1). A domain may
	// only use addresses from this list. Each gets its own default server.
	Dedicated []netip.Addr

	// HTTPPort and HTTPSPort are 80 and 443 in production (M-1); tests use
	// unprivileged ports.
	HTTPPort  int
	HTTPSPort int
	// HTTP2 enables HTTP/2 on HTTPS servers, HTTP3 adds QUIC listeners and
	// the Alt-Svc header (M-1). HTTP/3 needs nginx built with
	// --with-http_v3_module.
	HTTP2 bool
	HTTP3 bool
	// SSLProtocols is the "ssl_protocols" list (M-1), from TLSv1, TLSv1.1,
	// TLSv1.2, TLSv1.3. HTTP/3 needs TLSv1.3.
	SSLProtocols []string

	// Apache is the backend of proxy and hybrid domains (M-6). nil means
	// there is no Apache, and such domains are rejected.
	Apache *Apache

	// StaticExtensions are the file extensions nginx serves itself in
	// hybrid mode (M-7): lower-case letters and digits.
	StaticExtensions []string

	// AppTemplates maps an application template name (T-2) to its text.
	// Each becomes the common file apps/<name>.conf, included by
	// nginx-mode domains that select it. The text is trusted admin input.
	AppTemplates map[model.TemplateName]string
}

// Apache describes where Apache listens after it is moved to local ports
// (M-6). Moving it is not part of this package.
type Apache struct {
	// HTTP receives plain HTTP requests.
	HTTP netip.AddrPort
	// HTTPS, when valid, receives requests that came to nginx over HTTPS;
	// nginx connects to it over TLS and passes the host name with SNI.
	// When it is the zero value, HTTPS requests go to HTTP as well and the
	// backend learns the original scheme only from X-Forwarded-Proto.
	HTTPS netip.AddrPort
}

// DefaultServer returns a Server with production defaults. Paths follow
// the installed layout of build/nginx (docs/build.md) and the PID file of
// internal/apply; all of them are assumptions until the installer exists.
func DefaultServer() Server {
	return Server{
		User:              "nobody",
		PIDFile:           apply.DefaultPIDFile,
		ErrorLog:          "/var/log/" + product.Name + "/nginx/error.log",
		AccessLog:         "/var/log/" + product.Name + "/nginx/access.log",
		MimeTypes:         "/etc/" + product.Name + "/nginx/mime.types",
		WorkerConnections: 4096,
		// Assumption: Apache 2.4.54 and later default LimitRequestBody to
		// 1 GiB; to compare with cPanel's Apache on the test server.
		ClientMaxBodySize: "1g",
		HTTPPort:          80,
		HTTPSPort:         443,
		HTTP2:             true,
		HTTP3:             true,
		SSLProtocols:      []string{"TLSv1.2", "TLSv1.3"},
		StaticExtensions:  DefaultStaticExtensions(),
	}
}

// DefaultStaticExtensions returns the built-in hybrid list (M-7). It is a
// proposal of the developer: common images, fonts, styles, scripts,
// documents, archives and media.
func DefaultStaticExtensions() []string {
	return []string{
		"7z", "avif", "bmp", "css", "csv", "doc", "docx", "eot", "flv", "gif",
		"gz", "ico", "jpeg", "jpg", "js", "json", "map", "mp3", "mp4", "ogg",
		"otf", "pdf", "png", "ppt", "pptx", "rar", "svg", "svgz", "tar", "tgz",
		"tif", "tiff", "ttf", "txt", "wav", "webm", "webp", "woff", "woff2",
		"xls", "xlsx", "xml", "zip",
	}
}

// Kind is how a domain is configured in cPanel. It is informational: the
// built-in templates treat all kinds alike. Parked domains are not a kind:
// they are aliases of the domain they are parked on.
type Kind string

// Kinds.
const (
	KindMain  Kind = "main"
	KindSub   Kind = "sub"
	KindAddon Kind = "addon"
)

// Domain is the per-domain input of the generator.
type Domain struct {
	// Name is the primary server name; it is also the unit ID.
	Name model.Domain
	// Aliases are additional server names: www., parked domains and
	// cPanel aliases as reported by cPanel.
	Aliases []model.Domain
	Kind    Kind
	// User owns the domain.
	User model.User
	// DocRoot is the absolute document root.
	DocRoot string
	// IPs, when set, are the domain's dedicated addresses (A-1); the
	// domain then listens only on them. Each must be in Server.Dedicated
	// or Server.Addresses.
	IPs []netip.Addr
	// TLS enables the HTTPS server; nil means HTTP only (M-2).
	TLS *TLS
	// Settings are the effective settings from model.Resolve.
	Settings model.Effective
	// PHPSocket is the PHP-FPM socket of the domain's pool; required in
	// nginx mode (M-9). Pools are created elsewhere (PHP-4).
	PHPSocket string
	// Admin holds the admin's own rewrite rules and includes (T-6).
	Admin AdminRules
	// Client holds the client's rules (T-7). Only text produced by
	// userrules.Rules.Format reaches the configuration.
	Client *userrules.Rules
}

// TLS holds the certificate files installed by cPanel (M-2).
type TLS struct {
	Cert string // certificate chain, PEM
	Key  string // private key, PEM
}

// AdminRules are trusted texts written by the server admin (T-6), separate
// for the HTTP and HTTPS server. Each non-empty text becomes its own file
// that the server block includes, so an unbalanced brace in it cannot
// close the server block: nginx parses an included file on its own.
type AdminRules struct {
	HTTPRewrite  string
	HTTPInclude  string
	HTTPSRewrite string
	HTTPSInclude string
}

// Limits.
const (
	maxPathLen     = 4096
	maxAliases     = 1000
	maxAdminText   = 1 << 20
	maxExtLen      = 16
	maxExtensions  = 200
	maxIPsPerVhost = 16
)

var validProtocols = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// checkPath accepts a clean absolute path made of characters that have no
// meaning in nginx configuration and in file name globbing (N-6). It is
// stricter than newArg, which would quote the rest, so that a path is always
// printed bare and reads the same to a human as to nginx.
func checkPath(what, p string) error {
	if p == "" {
		return fmt.Errorf("%s: empty: %w", what, errUnsafe)
	}
	if len(p) > maxPathLen {
		return fmt.Errorf("%s: longer than %d bytes: %w", what, maxPathLen, errUnsafe)
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%s %q: must be a clean absolute path: %w", what, p, errUnsafe)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("/._-+@,=~", c) >= 0
		if !ok {
			return fmt.Errorf("%s %q: character %q not allowed: %w", what, p, c, errUnsafe)
		}
	}
	return nil
}

func checkPort(what string, p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("%s %d: out of range", what, p)
	}
	return nil
}

func checkAddr(what string, a netip.Addr) error {
	if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.Is4In6() {
		return fmt.Errorf("%s %q: must be a specific IPv4 or IPv6 address without zone", what, a)
	}
	return nil
}

// checkExtension accepts 1 to 16 lower-case ASCII letters and digits, which
// are literal inside a regular expression.
func checkExtension(e string) error {
	if e == "" || len(e) > maxExtLen {
		return fmt.Errorf("static extension %q: 1 to %d characters", e, maxExtLen)
	}
	for i := 0; i < len(e); i++ {
		if c := e[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return fmt.Errorf("static extension %q: only a-z and 0-9", e)
		}
	}
	return nil
}

// checkAdminText accepts any valid UTF-8 text without NUL. Admin text is
// trusted (T-6); this only keeps binary garbage out of the files, and
// nginx -t (T-9) checks the rest.
func checkAdminText(what, s string) error {
	if len(s) > maxAdminText {
		return fmt.Errorf("%s: larger than %d bytes", what, maxAdminText)
	}
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return fmt.Errorf("%s: must be UTF-8 text without NUL bytes", what)
	}
	return nil
}

// Validate checks the server input.
func (s *Server) Validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if s.User != "" {
		add(model.User(s.User).Validate())
	}
	add(checkPath("pid file", s.PIDFile))
	add(checkPath("error log", s.ErrorLog))
	if s.AccessLog != "" {
		add(checkPath("access log", s.AccessLog))
	}
	add(checkPath("mime types", s.MimeTypes))
	if s.TempDir != "" {
		add(checkPath("temp dir", s.TempDir))
	}
	if s.WorkerConnections < 1 || s.WorkerConnections > 1<<20 {
		add(fmt.Errorf("worker connections %d: out of range", s.WorkerConnections))
	}
	add(checkSize("client max body size", s.ClientMaxBodySize))
	add(checkPort("http port", s.HTTPPort))
	add(checkPort("https port", s.HTTPSPort))
	if s.HTTPPort == s.HTTPSPort {
		add(errors.New("http and https ports must differ"))
	}
	seen := map[netip.Addr]string{}
	for _, list := range []struct {
		name  string
		addrs []netip.Addr
	}{{"address", s.Addresses}, {"dedicated address", s.Dedicated}} {
		for _, a := range list.addrs {
			add(checkAddr(list.name, a))
			if prev, ok := seen[a]; ok {
				add(fmt.Errorf("%s %s: already listed as %s", list.name, a, prev))
			}
			seen[a] = list.name
		}
	}
	if len(s.SSLProtocols) == 0 {
		add(errors.New("ssl protocols: empty"))
	}
	for _, p := range s.SSLProtocols {
		if !slices.Contains(validProtocols, p) {
			add(fmt.Errorf("ssl protocol %q: must be one of %s", p, strings.Join(validProtocols, ", ")))
		}
	}
	if s.HTTP3 && !slices.Contains(s.SSLProtocols, "TLSv1.3") {
		add(errors.New("HTTP/3 needs TLSv1.3 in ssl protocols"))
	}
	if a := s.Apache; a != nil {
		if !a.HTTP.IsValid() || checkAddr("apache http", a.HTTP.Addr()) != nil || a.HTTP.Port() == 0 {
			add(fmt.Errorf("apache http address %q: must be a specific address and port", a.HTTP))
		} else {
			add(s.checkNotListened("apache http", a.HTTP))
		}
		if a.HTTPS != (netip.AddrPort{}) {
			if !a.HTTPS.IsValid() || checkAddr("apache https", a.HTTPS.Addr()) != nil || a.HTTPS.Port() == 0 {
				add(fmt.Errorf("apache https address %q: must be a specific address and port", a.HTTPS))
			} else {
				add(s.checkNotListened("apache https", a.HTTPS))
			}
		}
	}
	if len(s.StaticExtensions) > maxExtensions {
		add(fmt.Errorf("static extensions: more than %d", maxExtensions))
	}
	for _, e := range s.StaticExtensions {
		add(checkExtension(e))
	}
	names := make([]model.TemplateName, 0, len(s.AppTemplates))
	for name := range s.AppTemplates {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		text := s.AppTemplates[name]
		if err := name.Validate(); err != nil || name == model.TemplateNone {
			add(fmt.Errorf("app template name %q: invalid", name))
		}
		add(checkAdminText("app template "+string(name), text))
	}
	return errors.Join(errs...)
}

// checkSize accepts an nginx size: digits with an optional k, m or g
// suffix (https://nginx.org/en/docs/syntax.html).
func checkSize(what, v string) error {
	n := strings.TrimRight(v, "kKmMgG")
	if len(v)-len(n) > 1 || n == "" || len(n) > 12 || strings.Trim(n, "0123456789") != "" {
		return fmt.Errorf("%s %q: must be digits with an optional k, m or g suffix", what, v)
	}
	return nil
}

// checkNotListened refuses a backend address that nginx itself listens on:
// nginx would fail to bind at start (which nginx -t does not catch) or pass
// requests to itself.
func (s *Server) checkNotListened(what string, ap netip.AddrPort) error {
	p := int(ap.Port())
	if p != s.HTTPPort && p != s.HTTPSPort {
		return nil
	}
	if len(s.Addresses) == 0 || slices.Contains(s.Addresses, ap.Addr()) || slices.Contains(s.Dedicated, ap.Addr()) {
		return fmt.Errorf("%s address %s: nginx listens there itself", what, ap)
	}
	return nil
}

// reservedLocations are locations every built-in template defines. A client
// rule with the same location would make nginx -t fail with a duplicate
// location, so it is refused here with a clear message (T-9 would refuse it
// too, but only when the set is tested).
var reservedLocations = [][]string{{"/"}, {"^~", "/"}}

func checkClientRules(r *userrules.Rules) error {
	if r == nil {
		return nil
	}
	for _, d := range r.Directives {
		if d.Name != "location" {
			continue
		}
		for _, res := range reservedLocations {
			if slices.Equal(d.Args, res) {
				return fmt.Errorf("client rules: \"location %s\" is defined by the template; use a more specific location", strings.Join(d.Args, " "))
			}
		}
	}
	return nil
}

// Validate checks the domain input against the server input.
func (d *Domain) Validate(s *Server) error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(d.Name.Validate())
	if len(d.Aliases) > maxAliases {
		add(fmt.Errorf("more than %d aliases", maxAliases))
	}
	for _, a := range d.Aliases {
		add(a.Validate())
	}
	switch d.Kind {
	case KindMain, KindSub, KindAddon:
	default:
		add(fmt.Errorf("kind %q: must be main, sub or addon", d.Kind))
	}
	add(d.User.Validate())
	add(checkPath("document root", d.DocRoot))
	if len(d.IPs) > maxIPsPerVhost {
		add(fmt.Errorf("more than %d addresses", maxIPsPerVhost))
	}
	for _, ip := range d.IPs {
		if !slices.Contains(s.Dedicated, ip) && !slices.Contains(s.Addresses, ip) {
			add(fmt.Errorf("address %s is not a server address", ip))
		}
	}
	if d.TLS != nil {
		add(checkPath("certificate", d.TLS.Cert))
		add(checkPath("certificate key", d.TLS.Key))
	}
	mode := d.Settings.Mode.Value
	add(mode.Validate())
	switch mode {
	case model.ModeProxy, model.ModeHybrid:
		if s.Apache == nil {
			add(fmt.Errorf("mode %s needs Apache, and the server has none", mode))
		}
	case model.ModeNginx:
		add(checkPath("PHP-FPM socket", d.PHPSocket))
		if app := d.Settings.AppTemplate.Value; app != model.TemplateNone {
			add(app.Validate())
			if _, ok := s.AppTemplates[app]; !ok {
				add(fmt.Errorf("app template %q does not exist", app))
			}
		}
	}
	add(checkClientRules(d.Client))
	if mode != model.ModeNginx {
		// Last line of defense: rules accepted while the domain was in
		// nginx mode must not render once it is switched to proxy or
		// hybrid (T-8, customer decision 26).
		if err := d.Client.CheckNoLocation(); err != nil {
			add(fmt.Errorf("client rules in %s mode: %w", mode, err))
		}
	}
	add(checkAdminText("admin HTTP rewrite", d.Admin.HTTPRewrite))
	add(checkAdminText("admin HTTP include", d.Admin.HTTPInclude))
	add(checkAdminText("admin HTTPS rewrite", d.Admin.HTTPSRewrite))
	add(checkAdminText("admin HTTPS include", d.Admin.HTTPSInclude))
	return errors.Join(errs...)
}
