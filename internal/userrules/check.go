// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// maxRegexBytes limits a regular expression in location or rewrite. Long
// patterns are more likely to backtrack badly on every request.
const maxRegexBytes = 1024

// check validates the arguments of d. Children of a block are checked as
// they are parsed.
func (v *Validator) check(d *Directive) error {
	switch d.Name {
	case "location":
		return checkLocation(d)
	case "rewrite":
		return checkRewrite(d)
	case "return":
		return checkReturn(d)
	case "add_header":
		return checkAddHeader(d)
	case "expires":
		return checkExpires(d)
	case "allow", "deny":
		return checkAccess(d)
	}
	return checkGeneric(d)
}

// at returns the position of argument i, or of the directive itself.
func (d *Directive) at(i int) pos {
	if i >= 0 && i < len(d.argPos) {
		return d.argPos[i]
	}
	return pos{d.Line, d.Column}
}

func argCount(d *Directive, lo, hi int, usage string) error {
	if n := len(d.Args); n < lo || n > hi {
		return errAt(d.at(-1), "wrong number of arguments; usage: %s", usage)
	}
	return nil
}

// location [ = | ~ | ~* | ^~ ] uri { ... }
func checkLocation(d *Directive) error {
	const usage = "location [ = | ~ | ~* | ^~ ] /path { ... }"
	if err := argCount(d, 1, 2, usage); err != nil {
		return err
	}
	if len(d.Args) == 1 {
		uri := d.Args[0]
		switch {
		case strings.HasPrefix(uri, "@"):
			return errAt(d.at(0), "named locations are not allowed")
		case strings.HasPrefix(uri, "=") || strings.HasPrefix(uri, "~") || strings.HasPrefix(uri, "^~"):
			return errAt(d.at(0), "separate the location modifier from the path with a space")
		}
		return checkLocationPath(d, 0)
	}
	switch d.Args[0] {
	case "=", "^~":
		return checkLocationPath(d, 1)
	case "~", "~*":
		return checkRegex(d, 1)
	}
	return errAt(d.at(0), "unknown location modifier %s; usage: %s", quote(d.Args[0]), usage)
}

func checkLocationPath(d *Directive, i int) error {
	if !strings.HasPrefix(d.Args[i], "/") {
		return errAt(d.at(i), "location path must start with '/'")
	}
	return nil
}

// checkRegex rejects PCRE constructs that are not needed for client rules
// and have side effects:
//   - named captures, (?<name>...), (?P<name>...) and (?'name'...), create
//     nginx variables and can overwrite variables of the server
//     configuration;
//   - "(*" verbs change matching options and limits;
//   - "(?C" callouts.
func checkRegex(d *Directive, i int) error {
	re := d.Args[i]
	switch {
	case re == "":
		return errAt(d.at(i), "regular expression is empty")
	case len(re) > maxRegexBytes:
		return errAt(d.at(i), "regular expression is longer than %d bytes", maxRegexBytes)
	}
	for j := 0; j+1 < len(re); j++ {
		if re[j] != '(' {
			continue
		}
		rest := re[j+1:]
		switch {
		case strings.HasPrefix(rest, "?<") && !strings.HasPrefix(rest, "?<=") && !strings.HasPrefix(rest, "?<!"),
			strings.HasPrefix(rest, "?P<"), strings.HasPrefix(rest, "?'"):
			return errAt(d.at(i), "named captures are not allowed; use numbered captures such as $1")
		case strings.HasPrefix(rest, "*"):
			return errAt(d.at(i), "PCRE verbs such as (*...) are not allowed")
		case strings.HasPrefix(rest, "?C"):
			return errAt(d.at(i), "PCRE callouts are not allowed")
		}
	}
	if nestedQuantifier(re) {
		return errAt(d.at(i), "nested repetition such as (a+)+ is not allowed: it can make matching very slow")
	}
	return nil
}

// nestedQuantifier reports a group that contains an unbounded quantifier
// (*, + or {n,}) and is itself repeated by *, + or {. Such patterns can
// backtrack exponentially; a client regex runs in workers shared by every
// site on the server. The scan is conservative: it may reject some safe
// patterns.
func nestedQuantifier(re string) bool {
	var stack []bool // per open group: contains an unbounded quantifier
	inner := false   // the same for the current top level
	for j := 0; j < len(re); j++ {
		switch c := re[j]; c {
		case '\\':
			j++
		case '[':
			// Skip a character class; ']' right after '[' or '[^' is literal.
			k := j + 1
			if k < len(re) && re[k] == '^' {
				k++
			}
			if k < len(re) && re[k] == ']' {
				k++
			}
			for k < len(re) && re[k] != ']' {
				if re[k] == '\\' {
					k++
				}
				k++
			}
			j = k
		case '(':
			stack = append(stack, inner)
			inner = false
		case ')':
			if len(stack) == 0 {
				continue // unbalanced; nginx -t reports it
			}
			group := inner
			inner = stack[len(stack)-1] || group
			stack = stack[:len(stack)-1]
			if group && j+1 < len(re) && strings.IndexByte("*+{", re[j+1]) >= 0 {
				return true
			}
		case '*', '+':
			inner = true
		case '{':
			if k := strings.IndexByte(re[j:], '}'); k > 0 && strings.HasSuffix(re[j:j+k], ",") {
				inner = true
			}
		}
	}
	return false
}

// rewrite regex replacement [flag]
func checkRewrite(d *Directive) error {
	if err := argCount(d, 2, 3, "rewrite regex replacement [last | break | redirect | permanent]"); err != nil {
		return err
	}
	if err := checkRegex(d, 0); err != nil {
		return err
	}
	flag := ""
	if len(d.Args) == 3 {
		flag = d.Args[2]
		switch flag {
		case "last", "break", "redirect", "permanent":
		default:
			return errAt(d.at(2), "unknown rewrite flag %s; use last, break, redirect or permanent", quote(flag))
		}
	}
	repl := d.Args[1]
	// The nginx documentation: a replacement that starts with "http://",
	// "https://" or "$scheme" is returned as a redirect.
	external := flag == "redirect" || flag == "permanent" ||
		strings.HasPrefix(repl, "http://") || strings.HasPrefix(repl, "https://") ||
		strings.HasPrefix(repl, "$scheme")
	if external {
		return checkVars(d, 1, scopeRedirect)
	}
	// An internal rewrite changes the URI that is later mapped to a file
	// under the document root. nginx does not normalize the new URI, so the
	// path part is limited to literal text without "..": a variable or a
	// capture could put "/../" into it and leave the client's directory.
	path, _, hasQuery := strings.Cut(repl, "?")
	switch {
	case !strings.HasPrefix(path, "/"):
		return errAt(d.at(1), "internal rewrite target must start with '/'; use a full URL or the redirect flag for redirects")
	case strings.Contains(path, "$"):
		return errAt(d.at(1), "variables and captures are allowed only after '?' in an internal rewrite target; use the redirect or permanent flag for redirects")
	case strings.Contains(path, ".."):
		return errAt(d.at(1), "'..' is not allowed in a rewrite target")
	case strings.ContainsAny(path, "\\%"):
		return errAt(d.at(1), "'\\' and '%%' are not allowed in the path of an internal rewrite target")
	}
	if hasQuery {
		return checkVars(d, 1, scopeQuery)
	}
	return nil
}

var redirectCodes = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// return code [text] | return code URL | return URL
func checkReturn(d *Directive) error {
	if err := argCount(d, 1, 2, "return code [text]; return code URL; return URL"); err != nil {
		return err
	}
	code, isCode := parseCode(d.Args[0])
	if !isCode {
		if len(d.Args) == 2 {
			return errAt(d.at(0), "first argument of return must be a status code")
		}
		u := d.Args[0]
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "$scheme") {
			return errAt(d.at(0), "return without a code needs a URL starting with http://, https:// or $scheme")
		}
		return checkVars(d, 0, scopeSafe)
	}
	if code < 200 || code > 599 {
		return errAt(d.at(0), "status code must be between 200 and 599")
	}
	if len(d.Args) == 2 {
		if redirectCodes[code] && d.Args[1] == "" {
			return errAt(d.at(1), "redirect URL is empty")
		}
		return checkVars(d, 1, scopeSafe)
	}
	return nil
}

func parseCode(s string) (int, bool) {
	if len(s) != 3 || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// deniedHeaders are response headers a client must not add: they control
// message framing or the connection, and duplicates can desynchronize a
// connection that a CDN or proxy shares between several sites.
var deniedHeaders = map[string]bool{
	"connection":        true,
	"content-length":    true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"te":                true,
	"trailer":           true,
	"transfer-encoding": true,
	"upgrade":           true,
}

// add_header name value [always]
func checkAddHeader(d *Directive) error {
	if err := argCount(d, 2, 3, "add_header name value [always]"); err != nil {
		return err
	}
	name := d.Args[0]
	if !headerName.MatchString(name) {
		return errAt(d.at(0), "header name may contain only letters, digits and '-'")
	}
	lower := strings.ToLower(name)
	if deniedHeaders[lower] || strings.HasPrefix(lower, "x-accel-") {
		return errAt(d.at(0), "header %q cannot be set", name)
	}
	if len(d.Args) == 3 && d.Args[2] != "always" {
		return errAt(d.at(2), "third argument of add_header can only be \"always\"")
	}
	return checkVars(d, 1, scopeSafe)
}

// expiresTime follows https://nginx.org/en/docs/syntax.html: a number with an
// optional unit, several of them combined, optionally negative or, for
// expires, prefixed with '@' for a time of day.
var expiresTime = regexp.MustCompile(`^[-@]?(?:[0-9]{1,9}(?:ms|[smhdwMy])?)+$`)

// expires [modified] time | epoch | max | off
func checkExpires(d *Directive) error {
	const usage = "expires [modified] time; expires epoch | max | off"
	if err := argCount(d, 1, 2, usage); err != nil {
		return err
	}
	if len(d.Args) == 2 {
		if d.Args[0] != "modified" {
			return errAt(d.at(0), "usage: %s", usage)
		}
		if !expiresTime.MatchString(d.Args[1]) {
			return errAt(d.at(1), "invalid time %s", quote(d.Args[1]))
		}
		return nil
	}
	switch a := d.Args[0]; {
	case a == "epoch" || a == "max" || a == "off":
	case expiresTime.MatchString(a):
	default:
		return errAt(d.at(0), "invalid time %s; usage: %s", quote(a), usage)
	}
	return nil
}

// allow | deny  address | CIDR | unix: | all
func checkAccess(d *Directive) error {
	if err := argCount(d, 1, 1, d.Name+" address | CIDR | unix: | all"); err != nil {
		return err
	}
	a := d.Args[0]
	if a == "all" || a == "unix:" {
		return nil
	}
	if ip, err := netip.ParseAddr(a); err == nil && ip.Zone() == "" {
		return nil
	}
	if _, err := netip.ParsePrefix(a); err == nil {
		return nil
	}
	return errAt(d.at(0), "invalid address %s; use an IP address, a CIDR range, unix: or all", quote(a))
}

// checkGeneric checks a directive the administrator added (T-7). Its
// arguments are unknown, so every '$' must be a safe variable reference.
func checkGeneric(d *Directive) error {
	for i := range d.Args {
		if err := checkVars(d, i, scopeSafe); err != nil {
			return err
		}
	}
	return nil
}

// safeVars are the variables a client may use. They describe the request
// and are set by nginx from data the visitor already sent, so they expose
// nothing about the server. Variables such as $document_root,
// $realpath_root, $request_filename, $hostname, $server_addr, $pid and
// $upstream_* expose server internals; $binary_remote_addr holds raw bytes.
// Variables defined by the administrator's templates (map, set) must not be
// readable either. Names are compared in lower case.
var safeVars = map[string]bool{
	"args":            true,
	"content_length":  true,
	"content_type":    true,
	"host":            true,
	"https":           true,
	"is_args":         true,
	"msec":            true,
	"query_string":    true,
	"remote_addr":     true,
	"remote_port":     true,
	"request_id":      true,
	"request_method":  true,
	"request_uri":     true,
	"scheme":          true,
	"server_name":     true,
	"server_port":     true,
	"server_protocol": true,
	"status":          true,
	"time_iso8601":    true,
	"time_local":      true,
}

// varScope selects which references checkVars allows.
type varScope int

const (
	scopeSafe     varScope = iota // safeVars, no captures
	scopeRedirect                 // safeVars and captures
	scopeQuery                    // queryVars and captures
)

// queryVars may appear after '?' in an internal rewrite target.
var queryVars = map[string]bool{
	"args":         true,
	"is_args":      true,
	"query_string": true,
	"request_uri":  true,
}

var safeVarPrefixes = []string{"arg_", "cookie_", "http_"}

func isVarChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// checkVars checks every variable reference in argument i. captures allows
// regex captures $1..$9.
//
// $uri and $document_uri are refused: they hold the decoded URI, which can
// contain CR and LF from %0D%0A and split a response header (Q-6). Captures
// are refused outside rewrite for the same reason, since location regexes
// match the decoded URI.
//
// Captures stay allowed in rewrite, in a redirect target and after '?' in an
// internal target. This relies on nginx escaping a capture copied into a
// redirect or into the query string when the request URI was
// percent-encoded (ngx_http_script_copy_capture_code in
// src/http/ngx_http_script.c), which is the only way to get CR or LF into
// the decoded URI. This is an assumption to confirm on the test server
// (Q-6): without it a capture could split the Location header or, after a
// proxied internal rewrite, the request line sent to the backend.
func checkVars(d *Directive, i int, scope varScope) error {
	captures := scope != scopeSafe
	s := d.Args[i]
	for j := 0; j < len(s); j++ {
		if s[j] != '$' {
			continue
		}
		j++
		if j >= len(s) {
			return errAt(d.at(i), "'$' must be followed by a variable name; nginx has no escape for '$'")
		}
		var name string
		switch c := s[j]; {
		case c >= '1' && c <= '9':
			if !captures {
				return errAt(d.at(i), "regex captures such as $%c are not allowed in %s; use rewrite", c, d.Name)
			}
			continue
		case c == '{':
			end := strings.IndexByte(s[j:], '}')
			if end < 0 {
				return errAt(d.at(i), "unterminated ${ in variable reference")
			}
			name = s[j+1 : j+end]
			if name == "" {
				return errAt(d.at(i), "empty variable name in ${}")
			}
			for k := 0; k < len(name); k++ {
				if !isVarChar(name[k]) {
					return errAt(d.at(i), "invalid variable name %s", quote(name))
				}
			}
			j += end
		case isVarChar(c):
			k := j
			for k < len(s) && isVarChar(s[k]) {
				k++
			}
			name = s[j:k]
			j = k - 1
		default:
			return errAt(d.at(i), "'$' must be followed by a variable name; nginx has no escape for '$'")
		}
		if err := checkVarName(d, i, name, scope); err != nil {
			return err
		}
	}
	return nil
}

func checkVarName(d *Directive, i int, name string, scope varScope) error {
	lower := strings.ToLower(name)
	if lower == "uri" || lower == "document_uri" {
		return errAt(d.at(i), "variable $%s is not allowed: it holds the decoded URI and can inject line breaks; use $request_uri", name)
	}
	if scope == scopeQuery {
		// The query of an internal rewrite is copied unescaped into the
		// request line sent to a backend, so only variables that come from
		// the request line itself are allowed there.
		if queryVars[lower] || (len(lower) > len("arg_") && strings.HasPrefix(lower, "arg_")) {
			return nil
		}
		return errAt(d.at(i), "variable $%s is not allowed in the query of an internal rewrite; use $args, $arg_name, $query_string, $is_args or $request_uri", name)
	}
	if safeVars[lower] {
		return nil
	}
	for _, p := range safeVarPrefixes {
		if len(lower) > len(p) && strings.HasPrefix(lower, p) {
			return nil
		}
	}
	return errAt(d.at(i), "variable $%s is not allowed", name)
}
