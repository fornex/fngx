// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// builtin is the initial client whitelist (T-8). "location" is the only
// block directive a client may use.
var builtin = []string{"add_header", "allow", "deny", "expires", "location", "return", "rewrite"}

// BuiltinDirectives returns the initial client whitelist (T-8).
func BuiltinDirectives() []string { return slices.Clone(builtin) }

// Default limits. Config fields left at zero take these values.
const (
	DefaultMaxBytes      = 64 << 10
	DefaultMaxDirectives = 500
	DefaultMaxDepth      = 3

	// Upper bounds an administrator cannot exceed.
	ceilingMaxBytes      = 1 << 20
	ceilingMaxDirectives = 10000
	ceilingMaxDepth      = 8

	// maxArgs limits the arguments of one directive.
	maxArgs = 16
)

// Config configures a Validator.
type Config struct {
	// ExtraDirectives are simple (non-block) directives the administrator
	// adds to the client whitelist (T-7). A name on the hard-deny list is
	// refused by New.
	ExtraDirectives []string

	// MaxBytes limits the input size. Zero means DefaultMaxBytes.
	MaxBytes int
	// MaxDirectives limits the number of directives, nested ones included.
	// Zero means DefaultMaxDirectives.
	MaxDirectives int
	// MaxDepth limits how deeply location blocks nest; 1 allows a location
	// but no location inside it. Zero means DefaultMaxDepth.
	MaxDepth int
}

// Validator checks client rules. It is safe for concurrent use.
type Validator struct {
	allowed       map[string]bool
	maxBytes      int
	maxDirectives int
	maxDepth      int
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// New returns a Validator for cfg.
func New(cfg Config) (*Validator, error) {
	v := &Validator{allowed: map[string]bool{}}
	var err error
	if v.maxBytes, err = limit("MaxBytes", cfg.MaxBytes, DefaultMaxBytes, ceilingMaxBytes); err != nil {
		return nil, err
	}
	if v.maxDirectives, err = limit("MaxDirectives", cfg.MaxDirectives, DefaultMaxDirectives, ceilingMaxDirectives); err != nil {
		return nil, err
	}
	if v.maxDepth, err = limit("MaxDepth", cfg.MaxDepth, DefaultMaxDepth, ceilingMaxDepth); err != nil {
		return nil, err
	}
	for _, n := range builtin {
		v.allowed[n] = true
	}
	for _, n := range cfg.ExtraDirectives {
		if !namePattern.MatchString(n) {
			return nil, fmt.Errorf("invalid directive name %s", quote(n))
		}
		if reason := HardDenyReason(n); reason != "" {
			return nil, fmt.Errorf("directive %q cannot be allowed for clients: %s", n, reason)
		}
		v.allowed[n] = true
	}
	return v, nil
}

func limit(name string, val, def, ceiling int) (int, error) {
	switch {
	case val == 0:
		return def, nil
	case val < 0 || val > ceiling:
		return 0, fmt.Errorf("%s must be between 1 and %d, got %d", name, ceiling, val)
	}
	return val, nil
}

// Directives returns the sorted list of directive names a client may use.
func (v *Validator) Directives() []string {
	names := make([]string, 0, len(v.allowed))
	for n := range v.allowed {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func (v *Validator) isAllowed(name string) bool {
	return v.allowed[name] && HardDenyReason(name) == ""
}

// Reasons for the hard-deny list.
const (
	reasonFiles    = "it reads or writes files by path"
	reasonUpstream = "it connects to other servers or local services"
	reasonInternal = "it makes internal requests that can reach locations closed to clients"
	reasonCode     = "it runs code or loads rules"
	reasonVars     = "it changes variables or conditions the server configuration relies on"
	reasonServer   = "it changes server-wide behavior or exposes server-wide data"
)

// The hard-deny list is an executor proposal (requirement source "executor"
// in SPEC.md), pending the customer's confirmation. Names on it can never be whitelisted, not even by the
// administrator (T-8). Client rules are included at server level, so a
// directive there is inherited by the administrator's own locations; that is
// why whole families such as proxy_* and fastcgi_* are listed, not only the
// *_pass directives.
var hardDenyExact = map[string]string{
	// T-8.
	"alias":   reasonFiles,
	"root":    reasonFiles,
	"include": reasonFiles,

	// Internal redirects to a URI or a file, which can escape the document
	// root through "..", reach "internal" locations, or probe paths.
	"try_files":         reasonInternal,
	"index":             reasonInternal,
	"error_page":        reasonInternal,
	"post_action":       reasonInternal,
	"add_before_body":   reasonInternal,
	"add_after_body":    reasonInternal,
	"disable_symlinks":  reasonFiles, // turning it off allows symlink attacks on other users' files
	"xml_entities":      reasonFiles,
	"load_module":       reasonCode,
	"working_directory": reasonFiles,
	"pid":               reasonFiles,

	// "set" can overwrite a variable used by the administrator's templates,
	// for example in proxy_pass. "if" is outside the supported grammar and
	// its -f/-d/-e/-x operators probe arbitrary paths.
	"set":               reasonVars,
	"if":                reasonVars,
	"map":               reasonVars,
	"geo":               reasonVars,
	"split_clients":     reasonVars,
	"set_real_ip_from":  reasonVars,
	"real_ip_header":    reasonVars,
	"real_ip_recursive": reasonVars,

	// "server_name" in a client's server block could take over another
	// user's domain: nginx only warns about conflicting server names.
	"server_name": reasonServer,
	"listen":      reasonServer,
	"server":      reasonServer,
	"upstream":    reasonUpstream,
	"resolver":    reasonUpstream,
	"stub_status": reasonServer,
	"api":         reasonServer,
	"status":      reasonServer,
	"user":        reasonServer,
	"env":         reasonServer,
}

var hardDenyPrefix = []struct{ prefix, reason string }{
	{"proxy_", reasonUpstream},
	{"fastcgi_", reasonUpstream}, // fastcgi_param PHP_ADMIN_VALUE would override PHP limits
	{"uwsgi_", reasonUpstream},
	{"scgi_", reasonUpstream},
	{"grpc_", reasonUpstream},
	{"memcached_", reasonUpstream},
	{"mirror", reasonInternal},
	{"auth_", reasonInternal}, // auth_request subrequests, auth_basic_user_file paths
	{"ssi", reasonInternal},   // SSI include virtual/file
	{"ssl_", reasonFiles},     // certificates and private keys
	{"xslt_", reasonFiles},
	{"geoip", reasonFiles},
	{"perl", reasonCode},
	{"js_", reasonCode},
	{"modsecurity_rules", reasonCode}, // inline rules, rule files and remote rule URLs
}

var hardDenySuffix = []struct{ suffix, reason string }{
	{"_pass", reasonUpstream},
	{"_file", reasonFiles},
	{"_path", reasonFiles},
	{"_log", reasonFiles}, // access_log and error_log are opened by the master process as root
}

// HardDenyReason returns why name can never be allowed for clients, or ""
// if it is not on the hard-deny list.
func HardDenyReason(name string) string {
	if r, ok := hardDenyExact[name]; ok {
		return r
	}
	for _, p := range hardDenyPrefix {
		if strings.HasPrefix(name, p.prefix) {
			return p.reason
		}
	}
	for _, s := range hardDenySuffix {
		if strings.HasSuffix(name, s.suffix) {
			return s.reason
		}
	}
	if strings.Contains(name, "lua") {
		return reasonCode
	}
	return ""
}
