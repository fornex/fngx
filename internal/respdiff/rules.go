// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Severity ranks a difference. The zero value means "ignore".
type Severity int

// Severities in increasing order.
const (
	SevIgnore Severity = iota
	SevInfo
	SevWarning
	SevCritical
)

var severityNames = [...]string{"ignore", "info", "warning", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity parses "ignore", "info", "warning" or "critical".
func ParseSeverity(s string) (Severity, error) {
	for i, n := range severityNames {
		if s == n {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("%w: unknown severity %q", ErrInvalid, s)
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) {
	if s < 0 || int(s) >= len(severityNames) {
		return nil, fmt.Errorf("%w: severity %d", ErrInvalid, int(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Rules configure normalization and severities. A rules file is merged
// over the defaults ([DefaultRulesJSON]) unless NoDefaults is set:
// patterns are appended, header rules replace the default rule for the
// same header names, and OtherHeaders replaces the default.
type Rules struct {
	NoDefaults bool `json:"no_defaults,omitempty"`
	// BodyPatterns are applied to text bodies when a snapshot is taken.
	// Each regular expression (RE2 syntax) has exactly one capture
	// group; the captured text is replaced by "-" before hashing.
	BodyPatterns []Pattern `json:"body_patterns,omitempty"`
	// HeaderPatterns work like BodyPatterns on one header's value and
	// are applied when snapshots are compared.
	HeaderPatterns []HeaderPattern `json:"header_patterns,omitempty"`
	// Headers set the severity of a change per header.
	Headers []HeaderRule `json:"headers,omitempty"`
	// OtherHeaders is the severity for headers not listed in Headers.
	OtherHeaders *Severity `json:"other_headers,omitempty"`
}

// Pattern is a named regular expression with one capture group.
type Pattern struct {
	Name   string `json:"name"`
	Regexp string `json:"regexp"`
	Note   string `json:"note,omitempty"`
}

// HeaderPattern is a Pattern applied to the value of one header.
type HeaderPattern struct {
	Header string `json:"header"`
	Pattern
}

// HeaderRule sets the severity of a change of the named headers.
// Removed, if set, is used instead when the header disappears.
type HeaderRule struct {
	Names    []string  `json:"names"`
	Severity Severity  `json:"severity"`
	Removed  *Severity `json:"removed,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// Limits on a rules file.
const (
	maxRulesSize   = 1 << 20
	maxPatterns    = 200
	maxPatternLen  = 2000
	maxHeaderRules = 500
)

// DefaultRulesJSON is the built-in rule set. Run "respdiff rules" to
// print it; a rules file uses the same format.
const DefaultRulesJSON = `{
  "body_patterns": [
    {
      "name": "csrf-meta",
      "regexp": "(?i)<meta\\s+name=[\"'](?:csrf-token|csrf-param|_token|xsrf-token)[\"']\\s+content=[\"']([^\"']*)[\"']",
      "note": "per-session CSRF token in a meta tag (Laravel, Rails)"
    },
    {
      "name": "csrf-meta-reversed",
      "regexp": "(?i)<meta\\s+content=[\"']([^\"']*)[\"']\\s+name=[\"'](?:csrf-token|_token|xsrf-token)[\"']",
      "note": "the same with the attributes in the other order"
    },
    {
      "name": "token-input",
      "regexp": "(?i)<input\\b[^>]*\\bname=[\"'](?:_token|_?csrf[\\w-]*|[\\w-]*nonce|authenticity_token|form_key|form_build_id|form_token|__RequestVerificationToken|__VIEWSTATE|__EVENTVALIDATION|token)[\"'][^>]*\\bvalue=[\"']([^\"']*)[\"']",
      "note": "hidden form fields with per-request tokens (WordPress, Drupal, Magento, Laravel, ASP.NET)"
    },
    {
      "name": "token-input-reversed",
      "regexp": "(?i)<input\\b[^>]*\\bvalue=[\"']([^\"']*)[\"'][^>]*\\bname=[\"'](?:_token|_?csrf[\\w-]*|[\\w-]*nonce|authenticity_token|form_key|form_build_id|form_token|__RequestVerificationToken|__VIEWSTATE|__EVENTVALIDATION|token)[\"']",
      "note": "the same with value before name"
    },
    {
      "name": "joomla-token",
      "regexp": "(?i)<input\\b[^>]*\\bname=[\"']([0-9a-f]{32})[\"'][^>]*\\bvalue=[\"']1[\"']",
      "note": "Joomla puts the token in the field name"
    },
    {
      "name": "nonce-attribute",
      "regexp": "(?i)\\bnonce=[\"']([^\"']*)[\"']",
      "note": "CSP nonces on script and style tags"
    },
    {
      "name": "nonce-json",
      "regexp": "(?i)[\"'](?:[\\w-]*nonce|_?csrf[\\w-]*|_token)[\"']\\s*:\\s*[\"']([^\"']*)[\"']",
      "note": "nonces in inline JavaScript objects (WordPress wpApiSettings and plugins)"
    }
  ],
  "header_patterns": [
    {
      "header": "Content-Security-Policy",
      "name": "csp-nonce",
      "regexp": "'nonce-([^']*)'",
      "note": "per-response CSP nonce"
    },
    {
      "header": "Content-Security-Policy-Report-Only",
      "name": "csp-nonce",
      "regexp": "'nonce-([^']*)'",
      "note": "per-response CSP nonce"
    }
  ],
  "headers": [
    {
      "names": ["Date", "Age", "Expires", "ETag", "Last-Modified", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "X-Request-Id", "Request-Id", "X-Correlation-Id", "CF-Ray", "Server-Timing", "X-Cache", "X-Cache-Status", "X-Cache-Hits", "X-Proxy-Cache", "X-Varnish", "X-Runtime", "X-Response-Time"],
      "severity": "ignore",
      "note": "change between identical requests, or describe the transfer rather than the content; Content-Length is covered by the body comparison. Remove ETag and Last-Modified from this list to compare them"
    },
    {
      "names": ["Location", "Refresh"],
      "severity": "critical",
      "note": "redirect target; relative and absolute forms of the same URL are equal"
    },
    {
      "names": ["Content-Type"],
      "severity": "critical",
      "note": "a different media type is critical; a parameter-only change (charset spelling) is at most a warning"
    },
    {
      "names": ["Strict-Transport-Security", "Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy", "X-XSS-Protection"],
      "severity": "warning",
      "removed": "critical",
      "note": "security headers: a lost header weakens the site"
    },
    {
      "names": ["Cache-Control", "Pragma", "Vary", "Content-Encoding", "Content-Language", "Content-Disposition", "WWW-Authenticate", "Set-Cookie", "X-Robots-Tag", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Expose-Headers", "Access-Control-Max-Age", "Allow", "Link"],
      "severity": "warning",
      "note": "change caching, compression, cookies or browser behaviour; Set-Cookie is compared by cookie names and attributes, never values"
    },
    {
      "names": ["Server", "X-Powered-By", "Accept-Ranges", "Alt-Svc", "Report-To", "NEL"],
      "severity": "info",
      "note": "expected to change when the web server changes"
    }
  ],
  "other_headers": "info"
}`

// compiledRules is the merged, validated form of Rules.
type compiledRules struct {
	body        []*regexp.Regexp
	bodyFP      string // fingerprint of the body patterns, stored in snapshots
	headerRx    map[string][]*regexp.Regexp
	header      map[string]HeaderRule
	other       Severity
	description Rules // the merged rules, for reports
}

// ParseRules decodes a rules file. Unknown fields are rejected.
func ParseRules(data []byte) (Rules, error) {
	var r Rules
	if len(data) > maxRulesSize {
		return r, fmt.Errorf("%w: rules larger than %d bytes", ErrInvalid, maxRulesSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("%w: rules: %w", ErrInvalid, err)
	}
	if dec.More() {
		return r, fmt.Errorf("%w: rules: trailing data", ErrInvalid)
	}
	return r, nil
}

func defaultRules() Rules {
	r, err := ParseRules([]byte(DefaultRulesJSON))
	if err != nil {
		panic("respdiff: invalid default rules: " + err.Error())
	}
	return r
}

// merge returns the rules in effect: user over the defaults.
func merge(user *Rules) Rules {
	if user == nil {
		return defaultRules()
	}
	if user.NoDefaults {
		return *user
	}
	m := defaultRules()
	m.BodyPatterns = append(m.BodyPatterns, user.BodyPatterns...)
	m.HeaderPatterns = append(m.HeaderPatterns, user.HeaderPatterns...)
	override := make(map[string]bool)
	for _, hr := range user.Headers {
		for _, n := range hr.Names {
			override[http.CanonicalHeaderKey(n)] = true
		}
	}
	var kept []HeaderRule
	for _, hr := range m.Headers {
		var names []string
		for _, n := range hr.Names {
			if !override[http.CanonicalHeaderKey(n)] {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			hr.Names = names
			kept = append(kept, hr)
		}
	}
	m.Headers = append(kept, user.Headers...)
	if user.OtherHeaders != nil {
		m.OtherHeaders = user.OtherHeaders
	}
	return m
}

func compilePattern(p Pattern) (*regexp.Regexp, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("%w: pattern without a name", ErrInvalid)
	}
	if len(p.Regexp) > maxPatternLen {
		return nil, fmt.Errorf("%w: pattern %q longer than %d bytes", ErrInvalid, p.Name, maxPatternLen)
	}
	rx, err := regexp.Compile(p.Regexp)
	if err != nil {
		return nil, fmt.Errorf("%w: pattern %q: %w", ErrInvalid, p.Name, err)
	}
	if rx.NumSubexp() != 1 {
		return nil, fmt.Errorf("%w: pattern %q must have exactly one capture group, has %d", ErrInvalid, p.Name, rx.NumSubexp())
	}
	return rx, nil
}

// Compile validates user rules (nil means defaults only) and merges them
// over the defaults.
func compileRules(user *Rules) (*compiledRules, error) {
	m := merge(user)
	if len(m.BodyPatterns)+len(m.HeaderPatterns) > maxPatterns {
		return nil, fmt.Errorf("%w: more than %d patterns", ErrInvalid, maxPatterns)
	}
	if len(m.Headers) > maxHeaderRules {
		return nil, fmt.Errorf("%w: more than %d header rules", ErrInvalid, maxHeaderRules)
	}
	c := &compiledRules{
		headerRx:    make(map[string][]*regexp.Regexp),
		header:      make(map[string]HeaderRule),
		other:       SevInfo,
		description: m,
	}
	fp := sha256.New()
	for _, p := range m.BodyPatterns {
		rx, err := compilePattern(p)
		if err != nil {
			return nil, err
		}
		c.body = append(c.body, rx)
		fmt.Fprintf(fp, "%d:%s\n", len(p.Regexp), p.Regexp)
	}
	c.bodyFP = hex.EncodeToString(fp.Sum(nil))
	for _, p := range m.HeaderPatterns {
		if p.Header == "" {
			return nil, fmt.Errorf("%w: header pattern %q without a header", ErrInvalid, p.Name)
		}
		rx, err := compilePattern(p.Pattern)
		if err != nil {
			return nil, err
		}
		k := http.CanonicalHeaderKey(p.Header)
		c.headerRx[k] = append(c.headerRx[k], rx)
	}
	for _, hr := range m.Headers {
		if len(hr.Names) == 0 {
			return nil, fmt.Errorf("%w: header rule without names", ErrInvalid)
		}
		for _, n := range hr.Names {
			k := http.CanonicalHeaderKey(n)
			if k == "" || strings.ContainsAny(k, " \t:") {
				return nil, fmt.Errorf("%w: header name %q", ErrInvalid, n)
			}
			if _, dup := c.header[k]; dup {
				return nil, fmt.Errorf("%w: header %q listed twice", ErrInvalid, k)
			}
			c.header[k] = hr
		}
	}
	if m.OtherHeaders != nil {
		c.other = *m.OtherHeaders
	}
	return c, nil
}

// headerSeverity returns the severity of a change of header k and of its
// removal.
func (c *compiledRules) headerSeverity(k string) (changed, removed Severity) {
	hr, ok := c.header[k]
	if !ok {
		return c.other, c.other
	}
	removed = hr.Severity
	if hr.Removed != nil {
		removed = *hr.Removed
	}
	return hr.Severity, removed
}

// mask replaces the first capture group of every match of rx in b with
// "-".
func mask(b []byte, rx *regexp.Regexp) []byte {
	idx := rx.FindAllSubmatchIndex(b, -1)
	if len(idx) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	last := 0
	for _, m := range idx {
		s, e := m[2], m[3]
		if s < 0 || s < last {
			continue
		}
		out = append(out, b[last:s]...)
		out = append(out, '-')
		last = e
	}
	return append(out, b[last:]...)
}

func (c *compiledRules) normalizeBody(b []byte) []byte {
	for _, rx := range c.body {
		b = mask(b, rx)
	}
	return b
}

func (c *compiledRules) normalizeHeader(k, v string) string {
	for _, rx := range c.headerRx[k] {
		v = string(mask([]byte(v), rx))
	}
	return v
}
