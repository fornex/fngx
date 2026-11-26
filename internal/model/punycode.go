// SPDX-License-Identifier: GPL-3.0-or-later

package model

import "unicode/utf8"

// Punycode parameters, RFC 3492 section 5.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
	pcMaxInt      = 1<<31 - 1
)

// checkPunycode reports why s (the part of an A-label after "xn--") is
// not valid punycode, or "" if it decodes (RFC 3492 section 6.2) to a
// string with at least one non-ASCII code point. s contains only a-z, 0-9
// and '-' (checked by the caller). IDNA2008 code point rules are not
// checked: that needs Unicode tables beyond the standard library, and the
// label is safe for configuration either way.
func checkPunycode(s string) string {
	if s == "" {
		return "empty"
	}
	basic := 0
	rest := s
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '-' {
			if i == 0 {
				return "delimiter without basic code points"
			}
			basic = i
			rest = s[i+1:]
			break
		}
	}
	if rest == "" {
		return "no encoded code points"
	}
	n, bias, i := pcInitialN, pcInitialBias, 0
	out := basic
	for pos := 0; pos < len(rest); {
		oldi, w := i, 1
		for k := pcBase; ; k += pcBase {
			if pos >= len(rest) {
				return "truncated"
			}
			c := rest[pos]
			pos++
			var digit int
			switch {
			case c >= 'a' && c <= 'z':
				digit = int(c - 'a')
			case c >= '0' && c <= '9':
				digit = int(c-'0') + 26
			default:
				return "bad digit"
			}
			if digit > (pcMaxInt-i)/w {
				return "overflow"
			}
			i += digit * w
			t := k - bias
			if t < pcTMin {
				t = pcTMin
			} else if t > pcTMax {
				t = pcTMax
			}
			if digit < t {
				break
			}
			if w > pcMaxInt/(pcBase-t) {
				return "overflow"
			}
			w *= pcBase - t
		}
		out++
		bias = adapt(i-oldi, out, oldi == 0)
		if i/out > pcMaxInt-n {
			return "overflow"
		}
		n += i / out
		i %= out
		// C1 controls (U+0080..U+009F) and surrogates are never valid.
		if n < 0xA0 || n > utf8.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return "invalid code point"
		}
		i++
	}
	// Every iteration inserts n >= 128, so a decoded label with at least
	// one encoded code point always contains non-ASCII.
	return ""
}

func adapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
