// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/fornex/fngx/internal/model"
)

// Limits on the target list.
const (
	MaxTargets = 200_000
	maxLineLen = 2048
	maxPathLen = 1024
)

// ErrInvalid is wrapped by every error about invalid input: target
// lists, rules and snapshot files.
var ErrInvalid = errors.New("invalid input")

// Target is one URL to probe on every scheme: a domain and a request
// path with an optional query.
type Target struct {
	Domain model.Domain
	Path   string // starts with "/"
}

// String returns the canonical form: the domain alone when the path is
// "/", otherwise the domain followed by the path. ParseTarget accepts it.
func (t Target) String() string {
	if t.Path == "/" {
		return string(t.Domain)
	}
	return string(t.Domain) + t.Path
}

// URL returns the request URL for the scheme and port. Default ports are
// omitted, so the Host header is the bare domain.
func (t Target) URL(scheme string, port int) string {
	host := string(t.Domain)
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		host = fmt.Sprintf("%s:%d", host, port)
	}
	return scheme + "://" + host + t.Path
}

// ParseTarget parses "example.com", "example.com/path" or
// "example.com/path?query" from untrusted input (N-6). The domain is
// validated with [model.ParseDomain]; the path must be printable ASCII
// without spaces or a fragment.
func ParseTarget(s string) (Target, error) {
	host, path := s, "/"
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		host, path = s[:i], s[i:]
		if path[0] == '?' {
			path = "/" + path
		}
	}
	d, err := model.ParseDomain(host)
	if err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := checkPath(path); err != nil {
		return Target{}, err
	}
	return Target{Domain: d, Path: path}, nil
}

func checkPath(p string) error {
	if len(p) > maxPathLen {
		return fmt.Errorf("%w: path longer than %d bytes", ErrInvalid, maxPathLen)
	}
	if strings.HasPrefix(p, "//") {
		return fmt.Errorf("%w: path %q starts with \"//\"", ErrInvalid, p)
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c >= 0x7f || c == '#' {
			return fmt.Errorf("%w: path %q: byte 0x%02x not allowed", ErrInvalid, p, c)
		}
	}
	if _, err := url.ParseRequestURI(p); err != nil {
		return fmt.Errorf("%w: path %q: %w", ErrInvalid, p, err)
	}
	return nil
}

// ParseTargets reads one target per line. Blank lines and lines starting
// with '#' are skipped, surrounding white space is trimmed, and repeated
// targets are kept once, in first-seen order.
func ParseTargets(r io.Reader) ([]Target, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLineLen)
	seen := make(map[string]bool)
	var out []Target
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || s[0] == '#' {
			continue
		}
		t, err := ParseTarget(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		k := t.String()
		if seen[k] {
			continue
		}
		if len(out) == MaxTargets {
			return nil, fmt.Errorf("%w: more than %d targets", ErrInvalid, MaxTargets)
		}
		seen[k] = true
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("line %d: %w: line longer than %d bytes", line+1, ErrInvalid, maxLineLen)
		}
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no targets", ErrInvalid)
	}
	return out, nil
}
