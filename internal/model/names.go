// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalid is wrapped by every validation and parse error in this
// package and in package store.
var ErrInvalid = errors.New("invalid value")

// Length limits.
const (
	maxDomainLen = 253 // RFC 1035 section 2.3.4, without the trailing dot
	maxLabelLen  = 63  // RFC 1035 section 2.3.4
	maxUserLen   = 32  // Linux login name limit; cPanel rules are stricter
	maxIdentLen  = 64
)

func invalid(what, value, reason string) error {
	return fmt.Errorf("%w: %s %s: %s", ErrInvalid, what, quote(value), reason)
}

// quote returns a printable, length-limited representation of s for
// error messages, so hostile input cannot flood or corrupt logs.
func quote(s string) string {
	const limit = 80
	if len(s) > limit {
		return fmt.Sprintf("%q...", s[:limit])
	}
	return fmt.Sprintf("%q", s)
}

// byteName formats a single byte for an error message; bytes of
// multi-byte UTF-8 sequences are shown as escapes, not as Latin-1.
func byteName(c byte) string {
	if c >= 0x20 && c < 0x7f {
		return fmt.Sprintf("%q", rune(c))
	}
	return fmt.Sprintf("'\\x%02x'", c)
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Domain is a fully qualified domain or subdomain name in canonical form:
// lower-case ASCII, IDN labels in punycode ("xn--"), no trailing dot.
type Domain string

// ParseDomain validates a domain name from untrusted input (N-6). ASCII
// upper case is folded to lower case. Non-ASCII (Unicode IDN) input is
// rejected: the caller must pass the punycode form, which is what nginx
// matches against the Host header.
func ParseDomain(s string) (Domain, error) {
	b := []byte(s)
	for i, c := range b {
		if c >= 0x80 {
			return "", invalid("domain", s, "non-ASCII characters; use the punycode (xn--) form")
		}
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	d := Domain(b)
	if err := d.Validate(); err != nil {
		return "", err
	}
	return d, nil
}

// Validate checks that d is in canonical form. Rules:
//   - 1 to 253 characters, at least two labels separated by dots;
//   - each label 1 to 63 characters of a-z, 0-9 and '-', not starting
//     or ending with '-' (RFC 1123 host names, so no '_' and no '*');
//   - a label with '-' in positions 3 and 4 must be an "xn--" A-label
//     (RFC 5891 section 4.2.3.1) whose punycode decodes (RFC 3492) to a
//     non-ASCII string; IDNA code point tables are not checked;
//   - the last label is not all digits, so IPv4 addresses are rejected
//     (RFC 3696 section 2).
//
// Wildcard names ("*.example.com") are rejected for now: how cPanel
// reports wildcard subdomains is not verified yet, and accepting them
// later only relaxes validation, so stored files stay valid.
func (d Domain) Validate() error {
	s := string(d)
	if s == "" {
		return invalid("domain", s, "empty")
	}
	if len(s) > maxDomainLen {
		return invalid("domain", s, fmt.Sprintf("longer than %d characters", maxDomainLen))
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return invalid("domain", s, "must contain at least two labels")
	}
	for _, l := range labels {
		if reason := checkLabel(l); reason != "" {
			return invalid("domain", s, reason)
		}
	}
	tld := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(tld); i++ {
		if !isDigit(tld[i]) {
			allDigits = false
			break
		}
	}
	if allDigits {
		return invalid("domain", s, "top-level label is numeric")
	}
	return nil
}

func checkLabel(l string) string {
	if l == "" {
		return "empty label"
	}
	if len(l) > maxLabelLen {
		return fmt.Sprintf("label longer than %d characters", maxLabelLen)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !isLower(c) && !isDigit(c) && c != '-' {
			return fmt.Sprintf("character %s not allowed", byteName(c))
		}
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return "label starts or ends with '-'"
	}
	if len(l) >= 4 && l[2] == '-' && l[3] == '-' {
		if !strings.HasPrefix(l, "xn--") {
			return "'--' in positions 3-4 is reserved for xn-- labels"
		}
		if reason := checkPunycode(l[4:]); reason != "" {
			return "invalid xn-- label: " + reason
		}
	}
	return ""
}

func (d Domain) String() string { return string(d) }

// User is a cPanel account name.
type User string

// ParseUser validates an account name from untrusted input (N-6).
func ParseUser(s string) (User, error) {
	u := User(s)
	if err := u.Validate(); err != nil {
		return "", err
	}
	return u, nil
}

// Validate accepts 1 to 32 characters: a lower-case letter followed by
// lower-case letters, digits, '_' and '-'. This is meant as a superset of
// the names cPanel creates and is restricted to characters safe in file
// names and configuration. It does not check that the account exists.
func (u User) Validate() error {
	s := string(u)
	if s == "" {
		return invalid("user", s, "empty")
	}
	if len(s) > maxUserLen {
		return invalid("user", s, fmt.Sprintf("longer than %d characters", maxUserLen))
	}
	if !isLower(s[0]) {
		return invalid("user", s, "must start with a lower-case letter")
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isLower(c) && !isDigit(c) && c != '_' && c != '-' {
			return invalid("user", s, fmt.Sprintf("character %s not allowed", byteName(c)))
		}
	}
	return nil
}

func (u User) String() string { return string(u) }

// checkIdent validates a short identifier: 1 to 64 characters of a-z,
// 0-9, '_', '-' (and '.' if allowDot), starting with a letter or digit,
// not ending with '.' or '-'; a '.' must sit between letters or digits.
func checkIdent(what, s string, allowDot bool) error {
	if s == "" {
		return invalid(what, s, "empty")
	}
	if len(s) > maxIdentLen {
		return invalid(what, s, fmt.Sprintf("longer than %d characters", maxIdentLen))
	}
	if !isLower(s[0]) && !isDigit(s[0]) {
		return invalid(what, s, "must start with a lower-case letter or digit")
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case isLower(c), isDigit(c), c == '_', c == '-':
		case c == '.' && allowDot:
			if !isLower(s[i-1]) && !isDigit(s[i-1]) {
				return invalid(what, s, "'.' must follow a letter or digit")
			}
			if i+1 < len(s) && !isLower(s[i+1]) && !isDigit(s[i+1]) {
				return invalid(what, s, "'.' must precede a letter or digit")
			}
		default:
			return invalid(what, s, fmt.Sprintf("character %s not allowed", byteName(c)))
		}
	}
	if last := s[len(s)-1]; last == '.' || last == '-' {
		return invalid(what, s, "must not end with '.' or '-'")
	}
	return nil
}

// PHPVersion identifies a PHP-FPM build (PHP-1), for example the name of
// an EasyApache 4 or alt-php package. Only the syntax is checked here;
// whether the version is installed is checked where it is used.
type PHPVersion string

// ParsePHPVersion validates a PHP version identifier from untrusted
// input (N-6).
func ParsePHPVersion(s string) (PHPVersion, error) {
	v := PHPVersion(s)
	if err := v.Validate(); err != nil {
		return "", err
	}
	return v, nil
}

// Validate accepts 1 to 64 characters of a-z, 0-9, '.', '_' and '-'.
func (v PHPVersion) Validate() error { return checkIdent("PHP version", string(v), true) }

func (v PHPVersion) String() string { return string(v) }

// TemplateName names an application template (T-2, T-3, T-4).
type TemplateName string

// TemplateNone explicitly selects no application template, so a domain
// can opt out of a template set on the user or server layer.
const TemplateNone TemplateName = "none"

// ParseTemplateName validates a template name from untrusted input (N-6).
func ParseTemplateName(s string) (TemplateName, error) {
	t := TemplateName(s)
	if err := t.Validate(); err != nil {
		return "", err
	}
	return t, nil
}

// Validate accepts 1 to 64 characters of a-z, 0-9, '_' and '-'. Dots are
// not allowed so a name never looks like a file name with an extension.
// It does not check that the template exists.
func (t TemplateName) Validate() error { return checkIdent("template", string(t), false) }

func (t TemplateName) String() string { return string(t) }
