// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import (
	"errors"
	"strings"
	"testing"
)

func mustNew(t testing.TB, cfg Config) *Validator {
	t.Helper()
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func sameTree(a, b []*Directive) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Name != y.Name || x.Block != y.Block || len(x.Args) != len(y.Args) {
			return false
		}
		for j := range x.Args {
			if x.Args[j] != y.Args[j] {
				return false
			}
		}
		if !sameTree(x.Children, y.Children) {
			return false
		}
	}
	return true
}

// roundTrip checks that the normalized form parses back to the same tree
// and prints identically.
func roundTrip(t testing.TB, v *Validator, r *Rules) {
	t.Helper()
	out := r.Format()
	r2, err := v.Validate([]byte(out))
	if err != nil {
		t.Fatalf("normalized output rejected: %v\n%s", err, out)
	}
	if !sameTree(r.Directives, r2.Directives) {
		t.Fatalf("normalized output parses to a different tree:\n%s", out)
	}
	if out2 := r2.Format(); out2 != out {
		t.Fatalf("normalization is not stable:\n%s\n---\n%s", out, out2)
	}
}

// TestAccepted covers inputs that must be accepted (T-8) and their
// normalized form.
func TestAccepted(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"only comments and blanks", "# nothing here\n\n   # still nothing\n", ""},
		{"rewrite permanent with capture", `rewrite ^/old/(.*)$ /new/$1 permanent;`, "rewrite ^/old/(.*)$ /new/$1 permanent;\n"},
		{"rewrite to absolute url", `rewrite ^ https://example.com$request_uri? redirect;`, "rewrite ^ https://example.com$request_uri? redirect;\n"},
		{"rewrite scheme url", `rewrite ^/a$ $scheme://$host/b;`, "rewrite ^/a$ $scheme://$host/b;\n"},
		{"internal rewrite with captures in query", `rewrite ^/p/(\d+)$ /index.php?id=$1&$args last;`, "rewrite ^/p/(\\d+)$ /index.php?id=$1&$args last;\n"},
		{"internal rewrite literal", `rewrite ^/feed$ /feed.xml break;`, "rewrite ^/feed$ /feed.xml break;\n"},
		{"return code", `return 403;`, "return 403;\n"},
		{"return redirect", `return 301 https://example.com$request_uri;`, "return 301 https://example.com$request_uri;\n"},
		{"return url only", `return https://example.com/;`, "return https://example.com/;\n"},
		{"return text quoted", `return 200 "say \"hi\" to $remote_addr";`, "return 200 \"say \\\"hi\\\" to $remote_addr\";\n"},
		{"return text single quoted", `return 200 'it is "ok"';`, "return 200 \"it is \\\"ok\\\"\";\n"},
		{"return braces kept inside quotes", `return 200 "}";`, "return 200 \"}\";\n"},
		{"add_header", `add_header X-Frame-Options SAMEORIGIN always;`, "add_header X-Frame-Options SAMEORIGIN always;\n"},
		{"add_header injection text stays quoted", `add_header X-Note "a; include /etc/passwd; }";`, "add_header X-Note \"a; include /etc/passwd; }\";\n"},
		{"add_header http variable", `add_header X-UA $http_user_agent;`, "add_header X-UA $http_user_agent;\n"},
		{"braced variable", `return 301 https://${host}/x;`, "return 301 \"https://${host}/x\";\n"},
		{"expires forms", "expires 30d;\nexpires modified 1h30m;\nexpires @15h30m;\nexpires -1;\nexpires epoch;\nexpires off;",
			"expires 30d;\nexpires modified 1h30m;\nexpires @15h30m;\nexpires -1;\nexpires epoch;\nexpires off;\n"},
		{"allow deny", "allow 192.168.0.0/16;\nallow 2001:db8::/32;\nallow 10.0.0.1;\nallow unix:;\ndeny all;",
			"allow 192.168.0.0/16;\nallow 2001:db8::/32;\nallow 10.0.0.1;\nallow unix:;\ndeny all;\n"},
		{"location regex", `location ~* \.(jpg|png)$ { expires 30d; add_header Cache-Control "public"; }`,
			"location ~* \\.(jpg|png)$ {\n    expires 30d;\n    add_header Cache-Control public;\n}\n"},
		{"location exact and prefix", "location = /exact { return 204; }\nlocation ^~ /img/ { }\nlocation /a { }",
			"location = /exact {\n    return 204;\n}\nlocation ^~ /img/ {\n}\nlocation /a {\n}\n"},
		{"nested locations", "location /a {\n location /a/b {\n  location /a/b/c { deny all; }\n }\n}",
			"location /a {\n    location /a/b {\n        location /a/b/c {\n            deny all;\n        }\n    }\n}\n"},
		{"no spaces around braces", `location /x{return 204;}`, "location /x {\n    return 204;\n}\n"},
		{"CRLF line endings (Q-6)", "return 204;\r\n# c\r\ndeny all;\r\n", "return 204;\ndeny all;\n"},
		{"trailing comment", "return 204; # done", "return 204;\n"},
		{"comment with unicode", "# \u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440\nreturn 204;", "return 204;\n"},
		{"unicode letters in path", "location /\u043f\u0440\u0438\u0432\u0435\u0442 { return 204; }", "location \"/\u043f\u0440\u0438\u0432\u0435\u0442\" {\n    return 204;\n}\n"},
		// "\\" decodes to one backslash; "\c" keeps its backslash, as in nginx.
		{"backslash kept like nginx", `location ~ "^/a\.b\\c$" { }`, "location ~ ^/a\\.b\\c$ {\n}\n"},
		{"backslash before quote needs quoting", `location ~ "^/a\\\"$" { }`, "location ~ \"^/a\\\\\\\"$\" {\n}\n"},
		{"lookbehind is not a named capture", `location ~ "(?<=a)b(?<!c)" { }`, "location ~ (?<=a)b(?<!c) {\n}\n"},
		{"tabs as separators", "return\t204;", "return 204;\n"},
	}
	v := mustNew(t, Config{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := v.Validate([]byte(tt.in))
			if err != nil {
				t.Fatalf("Validate(%q) error: %v", tt.in, err)
			}
			if got := r.Format(); got != tt.want {
				t.Errorf("Format() =\n%s\nwant\n%s", got, tt.want)
			}
			roundTrip(t, v, r)
		})
	}
}

// TestRejected covers inputs that must be rejected: forbidden directives
// (T-8, Q-6), attempts to leave the block or read other users' files,
// comment and quoting tricks, Unicode lookalikes and CRLF injection (Q-6).
func TestRejected(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		line   int
		col    int
		reason string
	}{
		// Forbidden directives (T-8).
		{"alias", "alias /home/other/;", 1, 1, `directive "alias" is not allowed`},
		{"root", "root /;", 1, 1, "not allowed"},
		{"include", "include /etc/passwd;", 1, 1, "not allowed"},
		{"proxy_pass", "proxy_pass http://127.0.0.1:2087;", 1, 1, "not allowed"},
		{"fastcgi_pass", "fastcgi_pass unix:/run/php.sock;", 1, 1, "not allowed"},
		{"fastcgi_param", "fastcgi_param PHP_ADMIN_VALUE open_basedir=/;", 1, 1, "not allowed"},
		{"alias inside location", "location /x {\n  alias /home/other/public_html/;\n}", 2, 3, `"alias" is not allowed`},
		{"set", "set $backend 127.0.0.1;", 1, 1, "not allowed"},
		{"if", "if (-f /home/other/x) { return 403; }", 1, 1, "not allowed"},
		{"try_files", "try_files $uri /../../x;", 1, 1, "not allowed"},
		{"error_page", "error_page 404 /../../x;", 1, 1, "not allowed"},
		{"access_log", "access_log /home/other/.ssh/authorized_keys;", 1, 1, "not allowed"},
		{"disable_symlinks", "disable_symlinks off;", 1, 1, "not allowed"},
		{"server_name takeover", "server_name victim.example;", 1, 1, "not allowed"},
		{"ssi", "ssi on;", 1, 1, "not allowed"},
		{"uppercase name", "Return 204;", 1, 1, "invalid directive name"},
		{"quoted name", `"return" 204;`, 1, 1, "must not be quoted"},
		{"server block", "server { listen 80; }", 1, 1, "not allowed"},

		// Leaving the block.
		{"extra closing brace", "return 204; }\nserver_name x;", 1, 13, "unexpected '}'"},
		{"missing closing brace", "location /x {\nreturn 204;", 2, 12, "missing '}'"},
		{"missing semicolon", "return 204", 1, 11, "missing ';'"},
		{"missing semicolon before brace", "location /x { return 204 }", 1, 26, "missing ';'"},
		{"lone semicolon", ";", 1, 1, "unexpected ';'"},
		{"lone brace", "{ }", 1, 1, "unexpected '{'"},
		{"block on simple directive", "return 204 { }", 1, 12, "does not take a block"},
		{"location without block", "location /x;", 1, 12, "needs a block"},
		{"brace inside bare word", "return 200 a}b;", 1, 13, "unexpected '}'"},
		{"escaped semicolon", `return 200 a\;b;`, 1, 13, "escaped"},
		{"escaped brace", `return 200 a\}b;`, 1, 13, "escaped"},

		// Quoting and comment tricks.
		{"unterminated quote", `return 200 "x\";`, 1, 12, "unterminated"},
		{"quote inside word", `return 200 a"b";`, 1, 13, "quote character"},
		{"text after quote", `return 200 "a"b;`, 1, 15, "after the closing quote"},
		{"hash inside word", "return 200 a#b;", 1, 13, "'#'"},
		{"comment hides semicolon", "return 204 # ;\n", 2, 1, "missing ';'"},
		{"newline in quotes", "return 200 \"a\nb\";", 1, 14, "line break inside a quoted string"},
		{"escape n", `return 200 "a\nb";`, 1, 14, `\n is not allowed`},
		{"escape r in header", `add_header X "a\r\nSet-Cookie: x";`, 1, 16, `\r is not allowed`},
		{"escape t", `return 200 "a\tb";`, 1, 14, `\t is not allowed`},
		{"tab in quotes", "return 200 \"a\tb\";", 1, 14, "tab character"},
		{"backslash at end", `return 200 a\`, 1, 13, "backslash at the end"},

		// Control and Unicode characters (Q-6).
		{"lone CR", "return 204;\rdeny all;", 1, 12, "carriage return"},
		{"CR in comment", "# a\rb\nreturn 204;", 1, 4, "carriage return"},
		{"NUL", "return 204;\x00", 1, 12, "NUL"},
		{"NUL in quotes", "return 200 \"a\x00\";", 1, 14, "NUL"},
		{"escape char", "return 200 a\x1bb;", 1, 13, "control character"},
		{"DEL", "return 200 a\x7f;", 1, 13, "control character"},
		{"C1 control", "return 200 a\u0085;", 1, 13, "control character"},
		{"invalid utf8", "return 200 a\xff;", 1, 13, "invalid UTF-8"},
		{"overlong utf8 slash", "return 200 a\xc0\xaf;", 1, 13, "invalid UTF-8"},
		{"cyrillic a in alias", "\u0430lias /x;", 1, 1, "invalid directive name"},
		{"cyrillic e in return", "r\u0435turn 204;", 1, 1, "invalid directive name"},
		{"fullwidth semicolon", "return 204\uff1b", 1, 11, "non-ASCII character U+FF1B"},
		{"fullwidth brace", "location /x \uff5b", 1, 13, "non-ASCII character U+FF5B"},
		{"no-break space", "return\u00a0204;", 1, 7, "U+00A0"},
		{"zero width space", "return 200 a\u200bb;", 1, 13, "invisible"},
		{"bidi override in comment", "# \u202e;\nreturn 204;", 1, 3, "invisible"},
		{"byte order mark", "\ufeffreturn 204;", 1, 1, "invisible"},
		{"line separator", "return 204;\u2028deny all;", 1, 12, "invisible"},

		// Variables and captures.
		{"uri in redirect (Q-6)", "return 302 https://example.com$uri;", 1, 12, "$uri is not allowed"},
		{"uri upper case", "return 302 https://example.com$URI;", 1, 12, "$URI is not allowed"},
		{"uri braced", "add_header X ${uri};", 1, 14, "$uri is not allowed"},
		{"document_uri", "add_header X $document_uri;", 1, 14, "not allowed"},
		{"document_root", "return 200 $document_root;", 1, 12, "$document_root is not allowed"},
		{"realpath_root", "add_header X $realpath_root;", 1, 14, "not allowed"},
		{"request_filename", "return 200 $request_filename;", 1, 12, "not allowed"},
		{"hostname", "return 200 $hostname;", 1, 12, "not allowed"},
		{"binary_remote_addr", "return 200 $binary_remote_addr;", 1, 12, "not allowed"},
		{"upstream variable", "add_header X $upstream_addr;", 1, 14, "not allowed"},
		{"admin map variable", "return 200 $fngx_backend;", 1, 12, "not allowed"},
		{"bare http_ prefix", "return 200 $http_;", 1, 12, "not allowed"},
		{"dollar at end", `return 200 "price $";`, 1, 12, "'$' must be followed"},
		{"dollar space", `return 200 "a $ b";`, 1, 12, "'$' must be followed"},
		{"unterminated brace var", `return 200 "${host";`, 1, 12, "unterminated ${"},
		{"bad brace var", `return 200 "${ho-st}";`, 1, 12, "invalid variable name"},
		{"capture in return", "location ~ ^/old/(.*) { return 301 /new/$1; }", 1, 36, "captures"},
		{"capture in add_header", "add_header X $1;", 1, 14, "captures"},

		// Rewrite targets that could leave the document root.
		{"capture in internal path", "rewrite ^/(.*)$ /$1 last;", 1, 17, "only after '?'"},
		{"variable in internal path", "rewrite ^ /$arg_f break;", 1, 11, "only after '?'"},
		{"dotdot internal", "rewrite ^ /../../other/public_html/wp-config.php last;", 1, 11, "'..'"},
		{"relative internal", "rewrite ^ $arg_x last;", 1, 11, "must start with '/'"},
		{"upper case scheme is internal", "rewrite ^ HTTP://x/;", 1, 11, "must start with '/'"},
		{"percent internal", "rewrite ^ /%2e%2e/x last;", 1, 11, "'%'"},
		{"uri in rewrite query", "rewrite ^ /x?$uri;", 1, 11, "$uri"},
		{"unknown rewrite flag", "rewrite ^ /x end;", 1, 14, "unknown rewrite flag"},

		// Regular expressions.
		{"named capture location", "location ~ (?<document_root>.*) { }", 1, 12, "named captures"},
		{"named capture P", "rewrite (?P<x>.*) /a;", 1, 9, "named captures"},
		{"named capture quote", "rewrite \"(?'x'.*)\" /a;", 1, 9, "named captures"},
		{"pcre verb", `location ~ "(*LIMIT_MATCH=1)a" { }`, 1, 12, "verbs"},
		{"pcre callout", `location ~ "a(?C1)" { }`, 1, 12, "callouts"},
		{"empty regex", `location ~ "" { }`, 1, 12, "empty"},

		// location syntax.
		{"named location", "location @x { }", 1, 10, "named locations"},
		{"attached modifier", "location =/x { }", 1, 10, "separate the location modifier"},
		{"attached regex modifier", `location ~\.php$ { }`, 1, 10, "separate the location modifier"},
		{"relative location", "location x { }", 1, 10, "must start with '/'"},
		{"bad modifier", "location ! /x { }", 1, 10, "unknown location modifier"},
		{"too many location args", "location = /x /y { }", 1, 1, "wrong number of arguments"},

		// Other argument rules.
		{"content-length header", "add_header Content-Length 0;", 1, 12, "cannot be set"},
		{"transfer-encoding header", "add_header transfer-encoding chunked always;", 1, 12, "cannot be set"},
		{"x-accel header", "add_header X-Accel-Redirect /x;", 1, 12, "cannot be set"},
		{"header name with space", `add_header "X A" v;`, 1, 12, "header name"},
		{"header name with colon", `add_header "X:" v;`, 1, 12, "header name"},
		{"add_header bad flag", "add_header X v never;", 1, 16, "always"},
		{"expires variable", "expires $arg_x;", 1, 9, "invalid time"},
		{"expires garbage", "expires 1 h;", 1, 9, "usage"},
		{"allow hostname", "allow example.com;", 1, 7, "invalid address"},
		{"allow zone", "allow fe80::1%eth0;", 1, 7, "invalid address"},
		{"allow two args", "allow 1.2.3.4 5.6.7.8;", 1, 1, "wrong number"},
		{"return bad code", "return 999;", 1, 8, "between 200 and 599"},
		{"return 1xx", "return 101;", 1, 8, "between 200 and 599"},
		{"return relative url only", "return /x;", 1, 8, "needs a URL"},
		{"return text without code", "return hello world;", 1, 8, "status code"},
		{"return empty redirect", `return 301 "";`, 1, 12, "empty"},
	}
	v := mustNew(t, Config{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := v.Validate([]byte(tt.in))
			if err == nil {
				t.Fatalf("Validate(%q) accepted, normalized:\n%s", tt.in, r.Format())
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("error %v is %T, want *Error", err, err)
			}
			if e.Line != tt.line || e.Column != tt.col {
				t.Errorf("position = %d:%d, want %d:%d (%v)", e.Line, e.Column, tt.line, tt.col, err)
			}
			if !strings.Contains(e.Reason, tt.reason) {
				t.Errorf("reason = %q, want substring %q", e.Reason, tt.reason)
			}
		})
	}
}

// TestLimits covers the defensive limits (N-6).
func TestLimits(t *testing.T) {
	v := mustNew(t, Config{MaxBytes: 100, MaxDirectives: 3, MaxDepth: 2})
	tests := []struct {
		name   string
		in     string
		reason string
	}{
		{"size", strings.Repeat("#", 101), "larger than 100 bytes"},
		{"directives", "deny all; deny all; deny all; deny all;", "too many directives"},
		{"depth", "location /a { location /a/b { location /a/b/c { } } }", "nested too deeply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Validate([]byte(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.reason) {
				t.Fatalf("error = %v, want %q", err, tt.reason)
			}
		})
	}

	d := mustNew(t, Config{})
	long := "return 200 " + strings.Repeat("a", maxTokenBytes+1) + ";"
	if _, err := d.Validate([]byte(long)); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("long argument: error = %v", err)
	}
	many := "add_header" + strings.Repeat(" a", maxArgs+1) + ";"
	if _, err := d.Validate([]byte(many)); err == nil || !strings.Contains(err.Error(), "too many arguments") {
		t.Errorf("many arguments: error = %v", err)
	}
	deep := strings.Repeat("location /a {", 10000)
	if _, err := d.Validate([]byte(deep)); err == nil {
		t.Errorf("deep nesting accepted")
	}
}

// TestConfig covers the administrator's whitelist extension (T-7) and the
// hard-deny list it cannot override (T-8).
func TestConfig(t *testing.T) {
	denied := []string{
		"alias", "root", "include", "proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass",
		"memcached_pass", "proxy_set_header", "fastcgi_param", "set", "if", "try_files", "error_page",
		"index", "auth_request", "auth_basic_user_file", "mirror", "post_action", "add_before_body",
		"ssi", "ssi_types", "perl", "perl_set", "js_content", "content_by_lua_block", "access_by_lua",
		"load_module", "access_log", "error_log", "client_body_temp_path", "disable_symlinks",
		"ssl_certificate_key", "xslt_stylesheet", "server_name", "listen", "set_real_ip_from",
		"modsecurity_rules_file", "modsecurity_rules_remote", "stub_status", "resolver", "some_pass",
	}
	for _, n := range denied {
		if _, err := New(Config{ExtraDirectives: []string{n}}); err == nil {
			t.Errorf("New allowed hard-denied directive %q", n)
		}
		if HardDenyReason(n) == "" {
			t.Errorf("HardDenyReason(%q) is empty", n)
		}
	}
	for _, n := range []string{"", "Limit_rate", "limit-rate", "1x", "a b", "\u0430lias"} {
		if _, err := New(Config{ExtraDirectives: []string{n}}); err == nil {
			t.Errorf("New accepted invalid name %q", n)
		}
	}
	for _, c := range []Config{{MaxBytes: -1}, {MaxDepth: 100}, {MaxDirectives: ceilingMaxDirectives + 1}} {
		if _, err := New(c); err == nil {
			t.Errorf("New accepted limits %+v", c)
		}
	}
	for _, n := range BuiltinDirectives() {
		if r := HardDenyReason(n); r != "" {
			t.Errorf("builtin %q is hard-denied: %s", n, r)
		}
	}

	v := mustNew(t, Config{ExtraDirectives: []string{"limit_rate", "autoindex"}})
	r, err := v.Validate([]byte("location /dl { limit_rate 100k; autoindex on; }"))
	if err != nil {
		t.Fatalf("extended whitelist: %v", err)
	}
	if got, want := r.Format(), "location /dl {\n    limit_rate 100k;\n    autoindex on;\n}\n"; got != want {
		t.Errorf("Format() = %q, want %q", got, want)
	}
	if _, err := v.Validate([]byte("limit_rate $document_root;")); err == nil {
		t.Errorf("extended directive accepted an unsafe variable")
	}
	if _, err := mustNew(t, Config{}).Validate([]byte("limit_rate 1k;")); err == nil {
		t.Errorf("limit_rate accepted without whitelisting")
	}
	got := strings.Join(v.Directives(), ",")
	if want := "add_header,allow,autoindex,deny,expires,limit_rate,location,return,rewrite"; got != want {
		t.Errorf("Directives() = %s, want %s", got, want)
	}
}

func TestErrorMessageIsASCII(t *testing.T) {
	v := mustNew(t, Config{})
	_, err := v.Validate([]byte("location \u202e { }"))
	if err == nil {
		t.Fatal("accepted")
	}
	_, err = v.Validate([]byte("location ! \"" + strings.Repeat("\u0436", 200) + "\" { }"))
	if err == nil {
		t.Fatal("accepted")
	}
	_, err = v.Validate([]byte("location \"\u0436" + strings.Repeat("x", 200) + "\" /x { }"))
	if err == nil {
		t.Fatal("accepted")
	}
	for i := 0; i < len(err.Error()); i++ {
		if c := err.Error()[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("error message has byte %#x: %q", c, err.Error())
		}
	}
	if len(err.Error()) > 300 {
		t.Errorf("error message is not shortened: %d bytes", len(err.Error()))
	}
}

func TestFormatArg(t *testing.T) {
	tests := map[string]string{
		"":       `""`,
		"a":      "a",
		`\.`:     `\.`,
		`\`:      `"\\"`,
		`\\`:     `"\\\\"`,
		`\t`:     `"\\t"`,
		`\"`:     `"\\\""`,
		"a b":    `"a b"`,
		"a;b":    `"a;b"`,
		"${x}":   `"${x}"`,
		"#":      `"#"`,
		"'":      `"'"`,
		"\u0436": "\"\u0436\"",
		`a\{`:    `"a\\{"`,
		`/x?a=1`: `/x?a=1`,
	}
	v := mustNew(t, Config{})
	for in, want := range tests {
		if got := formatArg(in); got != want {
			t.Errorf("formatArg(%q) = %s, want %s", in, got, want)
		}
		// The printed argument must read back as the same value.
		r, err := v.Validate([]byte("add_header X " + formatArg(in) + ";"))
		if strings.Contains(in, "$") || strings.ContainsAny(in, "\\") && strings.Contains(in, "{") {
			continue
		}
		if err != nil {
			t.Errorf("formatArg(%q) does not parse: %v", in, err)
			continue
		}
		if got := r.Directives[0].Args[1]; got != in {
			t.Errorf("formatArg(%q) reads back as %q", in, got)
		}
	}
}
