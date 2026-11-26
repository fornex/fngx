// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/fornex/fngx/internal/model"
	"github.com/fornex/fngx/internal/product"
)

// The types in this file are the data that templates see. Every field that
// templates can print is an Arg, an int or a list of them, so no input
// string can reach the output unchecked (N-6). docs/templates.md documents
// every field (T-5); TestTemplateDocs keeps the two in sync.

// VhostData is the root of a vhost template.
type VhostData struct {
	Product Arg   // product name
	Domain  Arg   // primary server name
	Names   []Arg // all server names: primary first, then aliases sorted
	User    Arg   // owner account
	Kind    Arg   // main, sub or addon
	Mode    Arg   // proxy, hybrid or nginx
	Root    Arg   // document root

	// Servers has the HTTP server and, with a certificate, the HTTPS
	// server, in this order.
	Servers []ServerData

	// Apache is set in proxy and hybrid mode.
	Apache *ApacheData
	// Static is set in hybrid mode.
	Static *StaticData
	// PHP is set in nginx mode.
	PHP *PHPData
	// App is the include path of the application template (T-2); set in
	// nginx mode when the domain selects one.
	App *Arg
}

// ServerData is one server block: HTTP or HTTPS.
type ServerData struct {
	Scheme Arg   // http or https
	TLS    bool  // HTTPS server
	Listen []Arg // address:port pairs for "listen"
	// QUIC lists address:port pairs for "listen ... quic"; empty unless
	// HTTP/3 is on and this is the HTTPS server.
	QUIC []Arg
	// AltSvc is the value of the Alt-Svc header advertising HTTP/3, or nil.
	AltSvc *Arg
	HTTP2  bool
	Cert   *Arg // certificate file (HTTPS only)
	Key    *Arg // key file (HTTPS only)

	// Backend is the proxy_pass URL of Apache for this scheme (proxy and
	// hybrid mode), BackendTLS whether it is an https:// URL.
	Backend    *Arg
	BackendTLS bool

	// Include files, relative to the main file, or nil when empty (T-6,
	// T-7). See docs/templates.md for the positions the built-in templates
	// use and why.
	AdminRewrite *Arg
	AdminInclude *Arg
	ClientRules  *Arg
}

// ApacheData describes the backend (M-6).
type ApacheData struct {
	HTTP  Arg  // http://address:port
	HTTPS *Arg // https://address:port, or nil when HTTPS goes to HTTP
}

// StaticData lists the extensions nginx serves itself in hybrid mode (M-7).
type StaticData struct {
	Extensions []Arg
	// Regex is a case-insensitive location regex matching them, for
	// "location ~* {{.Static.Regex}}".
	Regex Arg
}

// PHPData describes the PHP-FPM pool (M-9).
type PHPData struct {
	Pass Arg // fastcgi_pass target: unix:/path/to/socket
}

// MainData is the root of the main file template.
type MainData struct {
	Product           Arg
	User              *Arg
	PIDFile           Arg
	ErrorLog          Arg
	AccessLog         *Arg
	MimeTypes         Arg
	Temp              *TempData
	WorkerConnections int
	SSLProtocols      []Arg
	// Defaults lists one default server per listening address: HTTP and
	// HTTPS.
	Defaults []DefaultData
	// Apache is the HTTP backend URL for the HTTP default server, or nil
	// when there is no Apache.
	Apache *Arg
}

// TempData holds the temporary directories, set when Server.TempDir is.
type TempData struct {
	ClientBody, Proxy, FastCGI, UWSGI, SCGI Arg
}

// DefaultData is a default server for one address.
type DefaultData struct {
	TLS    bool
	Listen Arg
	QUIC   *Arg
}

func listenAddr(a netip.Addr, port int) string {
	return netip.AddrPortFrom(a, uint16(port)).String() //nolint:gosec // port range checked in Validate
}

// listenSet returns the listen arguments for a port. Empty addrs means all
// addresses: "port" for IPv4 and "[::]:port" for IPv6.
func listenSet(addrs []netip.Addr, ipv6 bool, port int) []Arg {
	if len(addrs) == 0 {
		out := []Arg{mustArg("listen", strconv.Itoa(port))}
		if ipv6 {
			out = append(out, mustArg("listen", "[::]:"+strconv.Itoa(port)))
		}
		return out
	}
	sorted := slices.Clone(addrs)
	slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
	sorted = slices.Compact(sorted)
	out := make([]Arg, len(sorted))
	for i, a := range sorted {
		out[i] = mustArg("listen", listenAddr(a, port))
	}
	return out
}

func altSvc(port int) *Arg {
	// Value format from the example in
	// https://nginx.org/en/docs/http/ngx_http_v3_module.html#example
	return argPtr(rawArg(fmt.Sprintf(`'h3=":%d"; ma=86400'`, port)))
}

// staticRegex builds "\.(?:ext1|ext2)$" from validated extensions.
func staticRegex(exts []string) Arg {
	return rawArg(`"\.(?:` + strings.Join(exts, "|") + `)$"`)
}

func normExtensions(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// Paths in the generated set, relative to the main file.
const (
	mainFile     = "nginx.conf"
	proxySnippet = "snippets/proxy.conf"
	fcgiSnippet  = "snippets/fastcgi.conf"
)

func vhostPath(d model.Domain) string { return "vhosts/" + string(d) + ".conf" }

// domainDir holds a domain's include files. It is outside vhosts/ so that
// the "vhosts/*.conf" glob never matches a directory, even for a domain
// whose name ends in ".conf".
func domainDir(d model.Domain) string { return "domains/" + string(d) }

func appPath(t model.TemplateName) string { return "apps/" + string(t) + ".conf" }

// includeFile is one per-domain include file.
type includeFile struct {
	path string
	data string
}

// vhostInput is a validated domain turned into template data plus the
// extra files of its unit.
func buildVhost(s *Server, d *Domain) (*VhostData, []includeFile) {
	mode := d.Settings.Mode.Value
	names := []Arg{mustArg("server name", string(d.Name))}
	aliases := slices.Clone(d.Aliases)
	slices.Sort(aliases)
	aliases = slices.Compact(aliases)
	for _, a := range aliases {
		if a != d.Name {
			names = append(names, mustArg("server name", string(a)))
		}
	}
	v := &VhostData{
		Product: mustArg("product", product.Name),
		Domain:  names[0],
		Names:   names,
		User:    mustArg("user", string(d.User)),
		Kind:    mustArg("kind", string(d.Kind)),
		Mode:    mustArg("mode", string(mode)),
		Root:    mustArg("document root", d.DocRoot),
	}
	if mode == model.ModeProxy || mode == model.ModeHybrid {
		v.Apache = &ApacheData{HTTP: mustArg("apache", "http://"+s.Apache.HTTP.String())}
		if s.Apache.HTTPS.IsValid() {
			v.Apache.HTTPS = argPtr(mustArg("apache", "https://"+s.Apache.HTTPS.String()))
		}
	}
	if mode == model.ModeHybrid && len(s.StaticExtensions) > 0 {
		exts := normExtensions(s.StaticExtensions)
		st := &StaticData{Regex: staticRegex(exts)}
		for _, e := range exts {
			st.Extensions = append(st.Extensions, mustArg("extension", e))
		}
		v.Static = st
	}
	if mode == model.ModeNginx {
		v.PHP = &PHPData{Pass: mustArg("php socket", "unix:"+d.PHPSocket)}
		if app := d.Settings.AppTemplate.Value; app != model.TemplateNone {
			v.App = argPtr(mustArg("app template", appPath(app)))
		}
	}

	addrs, ipv6 := s.Addresses, s.IPv6
	if len(d.IPs) > 0 {
		addrs, ipv6 = d.IPs, false
	}
	dir := domainDir(d.Name)
	var files []includeFile
	file := func(name, text string) *Arg {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		p := dir + "/" + name
		files = append(files, includeFile{p, text})
		return argPtr(mustArg("include", p))
	}
	var client *Arg
	if d.Client != nil {
		client = file("client.conf", d.Client.Format())
	}

	httpSrv := ServerData{
		Scheme:       mustArg("scheme", "http"),
		Listen:       listenSet(addrs, ipv6, s.HTTPPort),
		AdminRewrite: file("http-rewrite.conf", d.Admin.HTTPRewrite),
		AdminInclude: file("http-include.conf", d.Admin.HTTPInclude),
		ClientRules:  client,
	}
	if v.Apache != nil {
		httpSrv.Backend = &v.Apache.HTTP
	}
	v.Servers = append(v.Servers, httpSrv)

	if d.TLS != nil {
		tlsSrv := ServerData{
			Scheme:       mustArg("scheme", "https"),
			TLS:          true,
			Listen:       listenSet(addrs, ipv6, s.HTTPSPort),
			HTTP2:        s.HTTP2,
			Cert:         argPtr(mustArg("certificate", d.TLS.Cert)),
			Key:          argPtr(mustArg("certificate key", d.TLS.Key)),
			AdminRewrite: file("https-rewrite.conf", d.Admin.HTTPSRewrite),
			AdminInclude: file("https-include.conf", d.Admin.HTTPSInclude),
			ClientRules:  client,
		}
		if s.HTTP3 {
			tlsSrv.QUIC = tlsSrv.Listen
			tlsSrv.AltSvc = altSvc(s.HTTPSPort)
		}
		if v.Apache != nil {
			tlsSrv.Backend = &v.Apache.HTTP
			if v.Apache.HTTPS != nil {
				tlsSrv.Backend, tlsSrv.BackendTLS = v.Apache.HTTPS, true
			}
		}
		v.Servers = append(v.Servers, tlsSrv)
	}
	return v, files
}

func buildMain(s *Server) *MainData {
	m := &MainData{
		Product:           mustArg("product", product.Name),
		PIDFile:           mustArg("pid file", s.PIDFile),
		ErrorLog:          mustArg("error log", s.ErrorLog),
		MimeTypes:         mustArg("mime types", s.MimeTypes),
		WorkerConnections: s.WorkerConnections,
	}
	if s.User != "" {
		m.User = argPtr(mustArg("user", s.User))
	}
	if s.AccessLog != "" {
		m.AccessLog = argPtr(mustArg("access log", s.AccessLog))
	}
	if s.TempDir != "" {
		t := func(name string) Arg { return mustArg("temp dir", s.TempDir+"/"+name) }
		m.Temp = &TempData{
			ClientBody: t("client_body"), Proxy: t("proxy"), FastCGI: t("fastcgi"),
			UWSGI: t("uwsgi"), SCGI: t("scgi"),
		}
	}
	for _, p := range s.SSLProtocols {
		m.SSLProtocols = append(m.SSLProtocols, mustArg("ssl protocol", p))
	}
	if s.Apache != nil {
		m.Apache = argPtr(mustArg("apache", "http://"+s.Apache.HTTP.String()))
	}
	// One default server per address nginx listens on: the shared set and
	// every dedicated address.
	sets := [][]Arg{listenSet(s.Addresses, s.IPv6, s.HTTPPort), listenSet(s.Dedicated, false, s.HTTPPort)}
	tlsSets := [][]Arg{listenSet(s.Addresses, s.IPv6, s.HTTPSPort), listenSet(s.Dedicated, false, s.HTTPSPort)}
	if len(s.Dedicated) == 0 {
		sets, tlsSets = sets[:1], tlsSets[:1]
	}
	for _, set := range sets {
		for _, a := range set {
			m.Defaults = append(m.Defaults, DefaultData{Listen: a})
		}
	}
	for _, set := range tlsSets {
		for _, a := range set {
			dd := DefaultData{TLS: true, Listen: a}
			if s.HTTP3 {
				dd.QUIC = argPtr(a)
			}
			m.Defaults = append(m.Defaults, dd)
		}
	}
	return m
}
