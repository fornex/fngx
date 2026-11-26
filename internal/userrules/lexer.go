// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxTokenBytes limits the decoded length of a single argument.
const maxTokenBytes = 4096

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokWord
	tokSemicolon
	tokLBrace
	tokRBrace
)

type token struct {
	kind   tokenKind
	value  string // decoded value of a word
	quoted bool
	pos    pos
}

// runeCtx tells check where a character appears.
type runeCtx int

const (
	ctxComment runeCtx = iota
	ctxToken
)

type lexer struct {
	src  []byte
	off  int
	line int
	col  int
}

func newLexer(src []byte) *lexer {
	return &lexer{src: src, line: 1, col: 1}
}

func (l *lexer) cur() pos { return pos{l.line, l.col} }

// peek returns the character at the current offset. ok is false at the end
// of input. Invalid UTF-8 decodes to utf8.RuneError with size 1.
func (l *lexer) peek() (r rune, size int, ok bool) {
	if l.off >= len(l.src) {
		return 0, 0, false
	}
	r, size = utf8.DecodeRune(l.src[l.off:])
	return r, size, true
}

func (l *lexer) advance(r rune, size int) {
	l.off += size
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
}

// crlf consumes a carriage return that must be followed by a line feed.
func (l *lexer) crlf() error {
	if l.off+1 >= len(l.src) || l.src[l.off+1] != '\n' {
		return errAt(l.cur(), "carriage return must be followed by a line feed")
	}
	l.off++ // the CR takes no column
	l.advance('\n', 1)
	return nil
}

// check rejects characters that are never allowed in ctx. Space, tab, CR and
// LF are handled by the callers.
func (l *lexer) check(r rune, size int, ctx runeCtx) error {
	switch {
	case r == utf8.RuneError && size == 1:
		return errAt(l.cur(), "invalid UTF-8 byte sequence")
	case r == 0:
		return errAt(l.cur(), "NUL character is not allowed")
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return errAt(l.cur(), "control character %s is not allowed", runeName(r))
	case unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029':
		return errAt(l.cur(), "invisible formatting character %s is not allowed", runeName(r))
	case ctx == ctxToken && r >= utf8.RuneSelf && !unicode.IsLetter(r) && !unicode.IsDigit(r):
		return errAt(l.cur(), "non-ASCII character %s is not allowed outside comments", runeName(r))
	}
	return nil
}

func runeName(r rune) string { return fmt.Sprintf("U+%04X", r) }

// next returns the next token, skipping whitespace and comments.
func (l *lexer) next() (token, error) {
	for {
		r, size, ok := l.peek()
		if !ok {
			return token{kind: tokEOF, pos: l.cur()}, nil
		}
		switch r {
		case ' ', '\t', '\n':
			l.advance(r, size)
		case '\r':
			if err := l.crlf(); err != nil {
				return token{}, err
			}
		case '#':
			if err := l.comment(); err != nil {
				return token{}, err
			}
		case ';', '{', '}':
			p := l.cur()
			l.advance(r, size)
			kind := tokSemicolon
			switch r {
			case '{':
				kind = tokLBrace
			case '}':
				kind = tokRBrace
			}
			return token{kind: kind, pos: p}, nil
		case '"', '\'':
			return l.quoted(r)
		default:
			return l.word()
		}
	}
}

// comment skips a comment up to, not including, the line break.
func (l *lexer) comment() error {
	l.advance('#', 1)
	for {
		r, size, ok := l.peek()
		if !ok || r == '\n' {
			return nil
		}
		if r == '\r' {
			if l.off+1 >= len(l.src) || l.src[l.off+1] != '\n' {
				return errAt(l.cur(), "carriage return must be followed by a line feed")
			}
			return nil
		}
		if r != '\t' {
			if err := l.check(r, size, ctxComment); err != nil {
				return err
			}
		}
		l.advance(r, size)
	}
}

// structural reports characters that end a bare word or start a comment.
func structural(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', ';', '{', '}', '#':
		return true
	}
	return false
}

// escape handles the character after a backslash at bs. inQuotes is true
// inside a quoted string.
func (l *lexer) escape(b *strings.Builder, bs pos, inQuotes bool) error {
	r, size, ok := l.peek()
	if !ok {
		return errAt(bs, "backslash at the end of input")
	}
	switch r {
	case '"', '\'', '\\':
		b.WriteRune(r)
		l.advance(r, size)
		return nil
	case 't', 'r', 'n':
		return errAt(bs, "escape sequence \\%c is not allowed", r)
	case '\n', '\r':
		return errAt(bs, "line break after a backslash is not allowed")
	case '\t':
		return errAt(bs, "tab character after a backslash is not allowed")
	}
	if !inQuotes && structural(r) {
		return errAt(bs, "escaped %s in an unquoted argument; quote the argument instead", quote(string(r)))
	}
	if err := l.check(r, size, ctxToken); err != nil {
		return err
	}
	// nginx keeps the backslash for any other character.
	b.WriteByte('\\')
	b.WriteRune(r)
	l.advance(r, size)
	return nil
}

// word reads a bare argument or directive name.
func (l *lexer) word() (token, error) {
	start := l.cur()
	var b strings.Builder
	prevDollar, inBrace := false, false
loop:
	for {
		r, size, ok := l.peek()
		if !ok {
			break
		}
		switch {
		case r == '{' && prevDollar:
			inBrace = true // "${name}"
		case r == '}' && inBrace:
			inBrace = false
		case r == '}':
			return token{}, errAt(l.cur(), "unexpected '}' inside an argument; quote the argument")
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';' || r == '{':
			break loop
		case r == '#':
			return token{}, errAt(l.cur(), "'#' inside an unquoted argument; quote the argument")
		case r == '"' || r == '\'':
			return token{}, errAt(l.cur(), "quote character inside an unquoted argument; quote the whole argument")
		case r == '\\':
			bs := l.cur()
			l.advance(r, size)
			if err := l.escape(&b, bs, false); err != nil {
				return token{}, err
			}
			prevDollar = false
			if b.Len() > maxTokenBytes {
				return token{}, errAt(start, "argument is longer than %d bytes", maxTokenBytes)
			}
			continue
		default:
			if err := l.check(r, size, ctxToken); err != nil {
				return token{}, err
			}
		}
		prevDollar = r == '$'
		b.WriteRune(r)
		l.advance(r, size)
		if b.Len() > maxTokenBytes {
			return token{}, errAt(start, "argument is longer than %d bytes", maxTokenBytes)
		}
	}
	return token{kind: tokWord, value: b.String(), pos: start}, nil
}

// quoted reads a quoted argument that starts with q.
func (l *lexer) quoted(q rune) (token, error) {
	start := l.cur()
	l.advance(q, 1)
	var b strings.Builder
	for {
		r, size, ok := l.peek()
		if !ok {
			return token{}, errAt(start, "unterminated quoted string")
		}
		switch r {
		case q:
			l.advance(r, size)
			if r, _, ok := l.peek(); ok && r != ' ' && r != '\t' && r != '\n' && r != '\r' && r != ';' && r != '{' {
				return token{}, errAt(l.cur(), "expected a space, ';' or '{' after the closing quote")
			}
			return token{kind: tokWord, value: b.String(), quoted: true, pos: start}, nil
		case '\n', '\r':
			return token{}, errAt(l.cur(), "line break inside a quoted string is not allowed")
		case '\t':
			return token{}, errAt(l.cur(), "tab character inside a quoted string is not allowed")
		case '\\':
			bs := l.cur()
			l.advance(r, size)
			if _, _, ok := l.peek(); !ok {
				return token{}, errAt(start, "unterminated quoted string")
			}
			if err := l.escape(&b, bs, true); err != nil {
				return token{}, err
			}
		default:
			if err := l.check(r, size, ctxToken); err != nil {
				return token{}, err
			}
			b.WriteRune(r)
			l.advance(r, size)
		}
		if b.Len() > maxTokenBytes {
			return token{}, errAt(start, "argument is longer than %d bytes", maxTokenBytes)
		}
	}
}
