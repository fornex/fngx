// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDomain_N6(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	// 4 labels of 63 + 3 dots = 255; trim to exactly 253.
	max253 := long63 + "." + long63 + "." + long63 + "." + strings.Repeat("b", 61)
	tests := []struct {
		in   string
		want Domain
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM", "example.com", true},
		{"sub.example.com", "sub.example.com", true},
		{"a.b.c.d.example.co.uk", "a.b.c.d.example.co.uk", true},
		{"xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai", true},
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"xn--a.com", "", false},
		{"xn--zzzzzzzzzzzzzzzzzzzzzzzz.com", "", false},
		{"a.xn--9", "", false},
		{"xn--abc-.com", "", false},
		{"xn---abc.com", "", false},
		{"my-site1.com", "my-site1.com", true},
		{"1example.com", "1example.com", true},
		{"example.xn--p1ai", "example.xn--p1ai", true},
		{long63 + ".com", Domain(long63 + ".com"), true},
		{max253, Domain(max253), true},

		{"", "", false},
		{"localhost", "", false},
		{"example.com.", "", false},
		{".example.com", "", false},
		{"example..com", "", false},
		{"*.example.com", "", false},
		{"ex_ample.com", "", false},
		{"-example.com", "", false},
		{"example-.com", "", false},
		{"ab--cd.com", "", false},
		{"xn--.com", "", false},
		{"1.2.3.4", "", false},
		{"example.123", "", false},
		{"пример.рф", "", false},
		{"exa mple.com", "", false},
		{"example.com\n", "", false},
		{"example.com/../etc", "", false},
		{"../etc/passwd", "", false},
		{"example.com;rm -rf /", "", false},
		{"$(id).com", "", false},
		{strings.Repeat("a", 64) + ".com", "", false},
		{max253 + "b", "", false},
		{"ex\x00ample.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDomain(tt.in)
			if tt.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted invalid domain, got %q", got)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
		})
	}
}

func TestDomainValidateRequiresCanonical(t *testing.T) {
	if err := Domain("Example.com").Validate(); err == nil {
		t.Fatal("upper case must fail Validate; only ParseDomain folds case")
	}
}

func TestParseUser_N6(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"bob", true},
		{"b", true},
		{"user123", true},
		{"a_b-c", true},
		{strings.Repeat("a", 32), true},
		{"", false},
		{"1bob", false},
		{"_bob", false},
		{"Bob", false},
		{"bob.smith", false},
		{"bob/../root", false},
		{"bob smith", false},
		{"bob;id", false},
		{strings.Repeat("a", 33), false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := ParseUser(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("ParseUser(%q) error = %v, want ok=%v", tt.in, err, tt.ok)
			}
		})
	}
}

func TestParsePHPVersion_PHP1(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"ea-php83", true},
		{"alt-php74", true},
		{"8.3", true},
		{"php8.3", true},
		{"", false},
		{".php", false},
		{"php..83", false},
		{"php83.", false},
		{"php83-", false},
		{"a.-b", false},
		{"a-.b", false},
		{"a._b", false},
		{"-php83", false},
		{"EA-PHP83", false},
		{"ea php83", false},
		{"ea-php83/../x", false},
		{"`id`", false},
		{strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := ParsePHPVersion(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("ParsePHPVersion(%q) error = %v, want ok=%v", tt.in, err, tt.ok)
			}
		})
	}
}

func TestParseTemplateName_T4(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"wordpress", true},
		{"none", true},
		{"my_custom-2", true},
		{"7zip", true},
		{"", false},
		{"word.press", false},
		{"WordPress", false},
		{"../default", false},
		{"a/b", false},
		{"tpl-", false},
		{strings.Repeat("t", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := ParseTemplateName(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("ParseTemplateName(%q) error = %v, want ok=%v", tt.in, err, tt.ok)
			}
		})
	}
}

func TestErrorMessageEscapesBytes(t *testing.T) {
	_, err := ParsePHPVersion("ea-php83\xff")
	if err == nil || !strings.Contains(err.Error(), `'\xff'`) {
		t.Fatalf("got %v", err)
	}
}

func TestErrorMessageTruncatesInput(t *testing.T) {
	_, err := ParseUser(strings.Repeat("A", 10000))
	if err == nil || len(err.Error()) > 300 {
		t.Fatalf("error missing or not truncated: %d bytes", len(err.Error()))
	}
}

func FuzzParseDomain(f *testing.F) {
	for _, s := range []string{"example.com", "XN--E1AFMKFD.XN--P1AI", "a..b", "*.x.com", "1.2.3.4", "пример.рф"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDomain(s)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		if len(d) == 0 || len(d) > maxDomainLen {
			t.Fatalf("bad length %d", len(d))
		}
		for i := 0; i < len(d); i++ {
			c := d[i]
			if !isLower(c) && !isDigit(c) && c != '-' && c != '.' {
				t.Fatalf("unsafe byte %q in accepted domain %q", c, d)
			}
		}
		if err := d.Validate(); err != nil {
			t.Fatalf("parsed domain fails Validate: %v", err)
		}
		if again, err := ParseDomain(string(d)); err != nil || again != d {
			t.Fatalf("not idempotent: %q -> %q, %v", d, again, err)
		}
	})
}
