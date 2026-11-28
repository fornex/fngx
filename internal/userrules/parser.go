// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import (
	"fmt"
	"strings"
)

// Directive is one validated directive. Block is true for a block directive
// (only "location"); its nested directives are in Children.
type Directive struct {
	Name     string
	Args     []string
	Block    bool
	Children []*Directive

	// Line and Column locate the directive name in the client input.
	Line   int
	Column int

	argPos []pos
}

// Rules is a validated set of client rules.
type Rules struct {
	Directives []*Directive
}

// Validate parses and checks client rules. On failure the error is an
// *Error with the position and reason of the first problem found.
func (v *Validator) Validate(src []byte) (*Rules, error) {
	if len(src) > v.maxBytes {
		return nil, &Error{Line: 1, Column: 1, Reason: fmt.Sprintf("rules are larger than %d bytes", v.maxBytes)}
	}
	p := &parser{v: v, lex: newLexer(src)}
	list, err := p.block(0, nil)
	if err != nil {
		return nil, err
	}
	return &Rules{Directives: list}, nil
}

// CheckNoLocation returns an *Error at the first location block, or nil if
// the rules have none (T-8, customer decision 26). Location blocks are
// allowed only for domains in nginx mode: the whitelist has no proxy_pass, so
// in proxy and hybrid mode a client location would make nginx serve that
// path from disk instead of passing it to Apache, sending PHP source and
// ignoring .htaccess.
//
// The Validator does not know the domain's mode, and the mode can change
// after the rules were accepted, so the caller runs this check whenever the
// rules are accepted or rendered for a domain that is not in nginx mode, and
// before switching a domain with rules to proxy or hybrid mode. A nil
// receiver has no rules.
func (r *Rules) CheckNoLocation() error {
	if r == nil {
		return nil
	}
	if d := firstLocation(r.Directives); d != nil {
		return errAt(d.at(-1), "location blocks are available only in nginx mode; in proxy and hybrid mode use directives without location")
	}
	return nil
}

// firstLocation returns the first location in input order, searching
// nested blocks too. Validate only produces locations at the top level or
// inside another location, but Rules is an exported type that callers may
// build themselves.
func firstLocation(list []*Directive) *Directive {
	for _, d := range list {
		if d.Name == "location" {
			return d
		}
		if l := firstLocation(d.Children); l != nil {
			return l
		}
	}
	return nil
}

type parser struct {
	v       *Validator
	lex     *lexer
	count   int
	regexes int
}

// maxRegexes limits regular expressions per rule set; each one may run on
// every request to the domain.
const maxRegexes = 50

func (p *parser) countRegex(d *Directive) error {
	if d.Name == "rewrite" || (d.Name == "location" && len(d.Args) == 2 && strings.HasPrefix(d.Args[0], "~")) {
		p.regexes++
		if p.regexes > maxRegexes {
			return errAt(d.at(-1), "too many regular expressions (limit %d)", maxRegexes)
		}
	}
	return nil
}

// block parses directives until the end of input (open == nil) or the '}'
// that closes the block opened at *open.
func (p *parser) block(depth int, open *pos) ([]*Directive, error) {
	var list []*Directive
	for {
		t, err := p.lex.next()
		if err != nil {
			return nil, err
		}
		switch t.kind {
		case tokEOF:
			if open != nil {
				return nil, errAt(t.pos, "missing '}' for the block opened at line %d, column %d", open.line, open.col)
			}
			return list, nil
		case tokRBrace:
			if open == nil {
				return nil, errAt(t.pos, "unexpected '}' without a matching '{'")
			}
			return list, nil
		case tokSemicolon:
			return nil, errAt(t.pos, "unexpected ';'")
		case tokLBrace:
			return nil, errAt(t.pos, "unexpected '{'")
		}
		d, err := p.directive(t, depth)
		if err != nil {
			return nil, err
		}
		list = append(list, d)
	}
}

func (p *parser) directive(name token, depth int) (*Directive, error) {
	if name.quoted {
		return nil, errAt(name.pos, "directive name must not be quoted")
	}
	if !namePattern.MatchString(name.value) {
		return nil, errAt(name.pos, "invalid directive name %s", quote(name.value))
	}
	if !p.v.isAllowed(name.value) {
		return nil, errAt(name.pos, "directive %q is not allowed; allowed directives: %s",
			name.value, strings.Join(p.v.Directives(), ", "))
	}
	p.count++
	if p.count > p.v.maxDirectives {
		return nil, errAt(name.pos, "too many directives (limit %d)", p.v.maxDirectives)
	}
	d := &Directive{Name: name.value, Line: name.pos.line, Column: name.pos.col}
	for {
		t, err := p.lex.next()
		if err != nil {
			return nil, err
		}
		switch t.kind {
		case tokWord:
			if len(d.Args) >= maxArgs {
				return nil, errAt(t.pos, "too many arguments for %q (limit %d)", d.Name, maxArgs)
			}
			d.Args = append(d.Args, t.value)
			d.argPos = append(d.argPos, t.pos)
		case tokSemicolon:
			if d.Name == "location" {
				return nil, errAt(t.pos, "location needs a block: location /path { ... }")
			}
			if err := p.v.check(d); err != nil {
				return nil, err
			}
			if err := p.countRegex(d); err != nil {
				return nil, err
			}
			return d, nil
		case tokLBrace:
			if d.Name != "location" {
				return nil, errAt(t.pos, "directive %q does not take a block", d.Name)
			}
			if depth+1 > p.v.maxDepth {
				return nil, errAt(t.pos, "locations are nested too deeply (limit %d)", p.v.maxDepth)
			}
			if err := p.v.check(d); err != nil {
				return nil, err
			}
			if err := p.countRegex(d); err != nil {
				return nil, err
			}
			children, err := p.block(depth+1, &t.pos)
			if err != nil {
				return nil, err
			}
			d.Block = true
			d.Children = children
			return d, nil
		default:
			return nil, errAt(t.pos, "missing ';' after directive %q", d.Name)
		}
	}
}
