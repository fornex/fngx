// SPDX-License-Identifier: GPL-3.0-or-later

package userrules

import (
	"errors"
	"testing"
)

// FuzzValidate checks that Validate never panics, that every rejection is a
// positioned *Error, and that every accepted input normalizes to text that
// is accepted again with the same tree (N-6, Q-6).
func FuzzValidate(f *testing.F) {
	seeds := []string{
		"",
		"return 204;",
		`rewrite ^/old/(.*)$ /new/$1 permanent;`,
		`rewrite ^/p/(\d+)$ /index.php?id=$1 last;`,
		`location ~* \.(jpg|png)$ { expires 30d; add_header Cache-Control "public"; }`,
		"location = /x { location /x { deny all; } }",
		`return 200 "say \"hi\" \\ $remote_addr";`,
		`add_header X 'a"b' always;`,
		"allow 10.0.0.0/8;\r\ndeny all;\r\n",
		"# comment\nexpires modified @15h30m;",
		`return 301 "https://${host}$request_uri";`,
		`location ~ "^/a\.b\\c$" { return 403; }`,
		"limit_rate 10k;",
		"return 200 a}b;",
		"location /x {",
		"alias /;",
		"return 200 \"a\nb\";",
		"r\u0435turn 204;",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	v, err := New(Config{ExtraDirectives: []string{"limit_rate", "autoindex"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := v.Validate(data)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Line < 1 || e.Column < 1 || e.Reason == "" {
				t.Fatalf("bad error %#v for %q", err, data)
			}
			return
		}
		out := r.Format()
		for i := 0; i < len(out); i++ {
			if c := out[i]; c < 0x20 && c != '\n' || c == 0x7f {
				t.Fatalf("normalized output has control byte %#x: %q", c, out)
			}
		}
		roundTrip(t, v, r)
	})
}
