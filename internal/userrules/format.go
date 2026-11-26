// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import "strings"

// Format returns the normalized configuration text for r. It is built from
// the parsed tree only; comments and original spacing are dropped. The text
// ends with a line feed unless r is empty.
func (r *Rules) Format() string {
	var b strings.Builder
	writeList(&b, r.Directives, 0)
	return b.String()
}

func writeList(b *strings.Builder, list []*Directive, depth int) {
	for _, d := range list {
		indent := strings.Repeat("    ", depth)
		b.WriteString(indent)
		b.WriteString(d.Name)
		for _, a := range d.Args {
			b.WriteByte(' ')
			b.WriteString(formatArg(a))
		}
		if !d.Block {
			b.WriteString(";\n")
			continue
		}
		b.WriteString(" {\n")
		writeList(b, d.Children, depth+1)
		b.WriteString(indent)
		b.WriteString("}\n")
	}
}

// bareByte reports bytes that have no special meaning to the nginx
// tokenizer in a bare word.
func bareByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("/._-~:?&=%+,@!*^|$()[]<>", c) >= 0
}

// canBeBare reports whether s can be printed without quotes and read back
// unchanged. A backslash is kept literally by nginx before any character
// except a quote, a backslash and the control escapes t, r, n, so it may stay bare
// only before a bare byte other than those.
func canBeBare(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 >= len(s) {
				return false
			}
			n := s[i+1]
			if !bareByte(n) || n == 't' || n == 'r' || n == 'n' {
				return false
			}
			continue
		}
		if !bareByte(c) {
			return false
		}
	}
	return true
}

// formatArg prints s so that nginx and this package read it back as s.
func formatArg(s string) string {
	if canBeBare(s) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}
