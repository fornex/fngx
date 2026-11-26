// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"errors"
	"fmt"
	"strings"
)

// errUnsafe is wrapped by every error about a value that cannot be placed
// into the configuration safely (N-6).
var errUnsafe = errors.New("value is not safe for nginx configuration")

// Arg is one directive parameter that is safe to print into an nginx
// configuration file. The only way to obtain a non-zero Arg is newArg (or
// rawArg for text built by this package), so templates never see a raw
// string from the input: every value they print is an Arg, and printing an
// Arg always yields exactly one nginx token.
//
// nginx's documentation does not describe quoting and escaping
// (https://nginx.org/en/docs/beginners_guide.html#conf_structure only says
// that parameters are separated by spaces and directives end with ';').
// This type therefore takes the narrowest reading:
//
//   - a value made only of characters with no meaning to the tokenizer is
//     printed bare;
//   - anything else is printed in double quotes, with '"' and '\' escaped;
//   - values that no quoting can make inert are rejected: control
//     characters and line breaks, non-ASCII bytes, and '$', which nginx
//     expands as a variable inside quotes too and has no escape for.
type Arg struct {
	s   string // the printed form, already quoted if needed
	set bool
}

// String returns the printed form. text/template calls it when an Arg is
// printed.
func (a Arg) String() string {
	if !a.set {
		// Unreachable from templates: empty optional values are nil
		// pointers or empty lists. Print something nginx rejects rather
		// than an empty token.
		return `"<unset>"`
	}
	return a.s
}

// IsSet reports whether a holds a value.
func (a Arg) IsSet() bool { return a.set }

// bareByte reports bytes that are printed without quotes. The set leaves out
// everything the nginx tokenizer treats specially (whitespace, ';', '{', '}',
// quotes, '\', '#') and '$'.
func bareByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("/._-:@+,=%~[]", c) >= 0
}

// newArg checks s and returns its printed form. what names the value in
// errors.
func newArg(what, s string) (Arg, error) {
	if s == "" {
		return Arg{}, fmt.Errorf("%s: empty: %w", what, errUnsafe)
	}
	bare := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x20 || c == 0x7f:
			return Arg{}, fmt.Errorf("%s %q: control character: %w", what, s, errUnsafe)
		case c >= 0x80:
			return Arg{}, fmt.Errorf("%s %q: non-ASCII character: %w", what, s, errUnsafe)
		case c == '$':
			return Arg{}, fmt.Errorf("%s %q: '$' would be expanded as a variable: %w", what, s, errUnsafe)
		case !bareByte(c):
			bare = false
		}
	}
	if bare {
		return Arg{s: s, set: true}, nil
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return Arg{s: b.String(), set: true}, nil
}

// mustArg is newArg for values built by this package from already validated
// parts. A failure is a bug in this package.
func mustArg(what, s string) Arg {
	a, err := newArg(what, s)
	if err != nil {
		panic(err)
	}
	return a
}

// rawArg wraps text built by this package that must keep characters newArg
// rejects, such as the '$' of a regular expression anchor or nginx
// variables. It must never receive input data.
func rawArg(s string) Arg { return Arg{s: s, set: true} }

// argPtr returns a pointer to a, for optional template fields.
func argPtr(a Arg) *Arg { return &a }

// quoteFunc is the "q" template function: it makes a literal string from a
// custom template safe in the same way as input values, and fails the
// template if that is impossible.
func quoteFunc(s string) (Arg, error) { return newArg("template value", s) }

// joinFunc is the "join" template function.
func joinFunc(args []Arg, sep string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = a.String()
	}
	return strings.Join(parts, sep)
}
