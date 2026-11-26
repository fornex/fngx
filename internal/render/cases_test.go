// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"net/netip"
	"testing"

	"github.com/fornex/fngx/internal/model"
	"github.com/fornex/fngx/internal/userrules"
)

// env holds everything that differs between the golden files (fixed fake
// paths) and the integration tests (temporary directories, free ports).
type env struct {
	home       string // parent of document roots
	certDir    string // <domain>.crt and <domain>.key
	phpDir     string // <domain>.sock
	httpPort   int
	httpsPort  int
	apache     netip.AddrPort
	apacheTLS  netip.AddrPort
	dedicated4 netip.Addr
	dedicated6 netip.Addr
	server     func() Server // server input before per-case changes
}

func goldenEnv() *env {
	return &env{
		home:       "/home",
		certDir:    "/etc/ssl/test",
		phpDir:     "/run/php-fpm",
		httpPort:   80,
		httpsPort:  443,
		apache:     netip.MustParseAddrPort("127.0.0.1:8080"),
		apacheTLS:  netip.MustParseAddrPort("127.0.0.1:8443"),
		dedicated4: netip.MustParseAddr("192.0.2.10"),
		dedicated6: netip.MustParseAddr("2001:db8::10"),
		server:     DefaultServer,
	}
}

func (e *env) baseServer() Server {
	s := e.server()
	s.HTTPPort, s.HTTPSPort = e.httpPort, e.httpsPort
	s.Apache = &Apache{HTTP: e.apache}
	s.Dedicated = []netip.Addr{e.dedicated4, e.dedicated6}
	s.AppTemplates = map[model.TemplateName]string{
		"generic-php": "location / {\n    try_files $uri $uri/ /index.php?$args;\n}\n",
	}
	return s
}

func (e *env) domain(name string, mode model.Mode) Domain {
	return Domain{
		Name:      model.Domain(name),
		Kind:      KindMain,
		User:      "alice",
		DocRoot:   e.home + "/alice/" + name,
		Settings:  model.Effective{Mode: model.Resolved[model.Mode]{Value: mode}, AppTemplate: model.Resolved[model.TemplateName]{Value: model.TemplateNone}},
		PHPSocket: e.phpDir + "/" + name + ".sock",
	}
}

func (e *env) tls(name string) *TLS {
	return &TLS{Cert: e.certDir + "/" + name + ".crt", Key: e.certDir + "/" + name + ".key"}
}

const clientRulesText = `location = /teapot { return 418; }
add_header X-Client "yes it is";
rewrite ^/old/(.*)$ /new/$1 permanent;
location ~* \.png$ { expires 30d; }
deny 203.0.113.0/24;
location ^~ /app/ { expires 1h; }
`

func clientRules(t testing.TB) *userrules.Rules {
	t.Helper()
	v, err := userrules.New(userrules.Config{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.Validate([]byte(clientRulesText))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var adminRules = AdminRules{
	HTTPRewrite:  "rewrite ^/admin-old$ /admin-new permanent;",
	HTTPInclude:  "location = /admin-http { return 200 \"admin http\\n\"; }\ndeny 198.51.100.7;\n",
	HTTPSRewrite: "rewrite ^/admin-old$ /admin-new-tls permanent;\n",
	HTTPSInclude: "location = /admin-https { return 200 \"admin https\\n\"; }\n",
}

// renderCase is one golden case: a server and one domain.
type renderCase struct {
	name string
	// build returns the inputs for env e.
	build func(t testing.TB, e *env) (Server, Domain)
}

// cases cover each mode (T-1, Q-1) with and without TLS, aliases, a
// dedicated IP, client rules and admin includes.
var cases = []renderCase{
	{"proxy-plain", func(_ testing.TB, e *env) (Server, Domain) {
		return e.baseServer(), e.domain("example.com", model.ModeProxy)
	}},
	{"proxy-tls-aliases", func(_ testing.TB, e *env) (Server, Domain) {
		s := e.baseServer()
		s.Apache.HTTPS = e.apacheTLS
		d := e.domain("example.net", model.ModeProxy)
		d.Aliases = []model.Domain{"www.example.net", "parked.example", "www.example.net"}
		d.TLS = e.tls("example.net")
		return s, d
	}},
	{"proxy-dedicated-rules", func(t testing.TB, e *env) (Server, Domain) {
		d := e.domain("shop.example.org", model.ModeProxy)
		d.Kind = KindSub
		d.IPs = []netip.Addr{e.dedicated6, e.dedicated4}
		d.TLS = e.tls("shop.example.org")
		d.Admin = adminRules
		d.Client = clientRules(t)
		return e.baseServer(), d
	}},
	{"hybrid-plain", func(_ testing.TB, e *env) (Server, Domain) {
		return e.baseServer(), e.domain("example.com", model.ModeHybrid)
	}},
	{"hybrid-tls-rules", func(t testing.TB, e *env) (Server, Domain) {
		s := e.baseServer()
		s.StaticExtensions = []string{"png", "css", "js", "png"}
		d := e.domain("example.net", model.ModeHybrid)
		d.Aliases = []model.Domain{"www.example.net"}
		d.TLS = e.tls("example.net")
		d.Client = clientRules(t)
		return s, d
	}},
	{"hybrid-dedicated-admin", func(_ testing.TB, e *env) (Server, Domain) {
		s := e.baseServer()
		s.HTTP3 = false
		d := e.domain("addon.example", model.ModeHybrid)
		d.Kind = KindAddon
		d.IPs = []netip.Addr{e.dedicated4}
		d.TLS = e.tls("addon.example")
		d.Admin = adminRules
		return s, d
	}},
	{"nginx-plain", func(_ testing.TB, e *env) (Server, Domain) {
		return e.baseServer(), e.domain("example.com", model.ModeNginx)
	}},
	{"nginx-tls-app-rules", func(t testing.TB, e *env) (Server, Domain) {
		d := e.domain("example.net", model.ModeNginx)
		d.Aliases = []model.Domain{"www.example.net"}
		d.TLS = e.tls("example.net")
		d.Settings.AppTemplate.Value = "generic-php"
		d.Admin = adminRules
		d.Client = clientRules(t)
		return e.baseServer(), d
	}},
	{"nginx-dedicated-http2only", func(_ testing.TB, e *env) (Server, Domain) {
		s := e.baseServer()
		s.HTTP3 = false
		s.SSLProtocols = []string{"TLSv1.2"}
		d := e.domain("xn--80ak6aa92e.example", model.ModeNginx)
		d.IPs = []netip.Addr{e.dedicated4}
		d.TLS = e.tls("xn--80ak6aa92e.example")
		return s, d
	}},
}

// mainCase is a golden case for the common files.
type mainCase struct {
	name  string
	build func(e *env) Server
}

var mainCases = []mainCase{
	{"main-default", func(e *env) Server { return e.baseServer() }},
	{"main-shared-ipv6-noapache", func(e *env) Server {
		s := e.baseServer()
		s.Apache = nil
		s.Addresses = []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}
		s.Dedicated = nil
		s.User = ""
		s.AccessLog = ""
		s.TempDir = "/var/tmp/nginx"
		s.AppTemplates = nil
		s.HTTP3 = false
		return s
	}},
	{"main-wildcard-ipv6", func(e *env) Server {
		s := e.baseServer()
		s.IPv6 = true
		s.Dedicated = nil
		return s
	}},
}
