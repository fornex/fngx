// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func snapOf(rs ...Result) *Snapshot {
	return &Snapshot{
		Version: SnapshotVersion,
		Server:  "192.0.2.1",
		Started: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Options: Options{Method: "GET", HTTPPort: 80, HTTPSPort: 443, MaxBody: 1024, TLSMode: TLSStrict, Repeat: 2, BodyRules: "r1"},
		Results: rs,
	}
}

func ok(scheme string, mods ...func(*Result)) Result {
	r := Result{
		Target: "example.com", Scheme: scheme, Status: 200,
		Header: map[string][]string{"Content-Type": {"text/html"}},
		Body:   &BodyInfo{Length: 1, SHA256: "aa", NormSHA256: "aa", Stable: new(true)},
	}
	if scheme == "https" {
		r.TLS = &TLSInfo{Version: "TLS 1.3", CertSHA256: "c1", Verified: true}
	}
	for _, m := range mods {
		m(&r)
	}
	return r
}

func hdr(k string, v ...string) func(*Result) {
	return func(r *Result) {
		if v == nil {
			delete(r.Header, k)
			return
		}
		r.Header[k] = v
	}
}

func TestCompareTable_I11(t *testing.T) {
	tests := []struct {
		name   string
		before Result
		after  Result
		want   map[string]Severity
	}{
		{"identical", ok("http"), ok("http"), nil},
		{"status", ok("http"), ok("http", func(r *Result) { r.Status = 500 }), map[string]Severity{"status": SevCritical}},
		{"new error", ok("http"), ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindTimeout} }),
			map[string]Severity{"error": SevCritical}},
		{"error fixed", ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindRefused} }), ok("http"),
			map[string]Severity{"error": SevWarning}},
		{"same error", ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindRefused, Message: "a"} }),
			ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindRefused, Message: "b"} }), nil},
		{"other error", ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindRefused} }),
			ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindTimeout} }), map[string]Severity{"error": SevWarning}},
		{"location relative vs absolute", ok("https", hdr("Location", "/a")), ok("https", hdr("Location", "https://Example.com:443/a")), nil},
		{"location scheme", ok("http", hdr("Location", "http://example.com/")), ok("http", hdr("Location", "https://example.com/")),
			map[string]Severity{"header:Location": SevCritical}},
		{"location added", ok("http"), ok("http", hdr("Location", "/x")), map[string]Severity{"header:Location": SevCritical}},
		{"media type", ok("http"), ok("http", hdr("Content-Type", "application/json")), map[string]Severity{"header:Content-Type": SevCritical}},
		{"charset case", ok("http", hdr("Content-Type", "text/html; charset=UTF-8")), ok("http", hdr("Content-Type", "text/html;charset=utf-8")), nil},
		{"charset changed", ok("http", hdr("Content-Type", "text/html; charset=utf-8")), ok("http", hdr("Content-Type", "text/html; charset=iso-8859-1")),
			map[string]Severity{"header:Content-Type": SevWarning}},
		{"cache-control order", ok("http", hdr("Cache-Control", "no-cache, Private")), ok("http", hdr("Cache-Control", "private", "no-cache")), nil},
		{"cache-control changed", ok("http", hdr("Cache-Control", "no-cache")), ok("http", hdr("Cache-Control", "max-age=60")),
			map[string]Severity{"header:Cache-Control": SevWarning}},
		{"date and etag ignored", ok("http", hdr("Date", "x"), hdr("ETag", `"1"`)), ok("http", hdr("Date", "y"), hdr("ETag", `"2"`)), nil},
		{"hsts removed", ok("https", hdr("Strict-Transport-Security", "max-age=1")), ok("https"),
			map[string]Severity{"header:Strict-Transport-Security": SevCritical}},
		{"hsts changed", ok("https", hdr("Strict-Transport-Security", "max-age=1")), ok("https", hdr("Strict-Transport-Security", "max-age=2")),
			map[string]Severity{"header:Strict-Transport-Security": SevWarning}},
		{"csp nonce", ok("https", hdr("Content-Security-Policy", "script-src 'nonce-abc'")), ok("https", hdr("Content-Security-Policy", "script-src 'nonce-xyz'")), nil},
		{"cookie names", ok("http", hdr("Set-Cookie", "a; path=/", "b")), ok("http", hdr("Set-Cookie", "b", "a; path=/")), nil},
		{"cookie lost", ok("http", hdr("Set-Cookie", "a; path=/")), ok("http"), map[string]Severity{"header:Set-Cookie": SevWarning}},
		{"unknown header", ok("http"), ok("http", hdr("X-New", "1")), map[string]Severity{"header:X-New": SevInfo}},
		{"body stable", ok("http"), ok("http", func(r *Result) { r.Body = &BodyInfo{SHA256: "bb", NormSHA256: "bb"} }),
			map[string]Severity{"body": SevCritical}},
		{"body unstable", ok("http", func(r *Result) { r.Body.Stable = new(false) }),
			ok("http", func(r *Result) { r.Body = &BodyInfo{Length: 1, SHA256: "bb", NormSHA256: "bb"} }), map[string]Severity{"body": SevInfo}},
		{"body unknown", ok("http", func(r *Result) { r.Body.Stable = nil }),
			ok("http", func(r *Result) { r.Body = &BodyInfo{Length: 1, SHA256: "bb", NormSHA256: "bb"} }), map[string]Severity{"body": SevWarning}},
		{"raw differs, normalized same", ok("http"), ok("http", func(r *Result) { r.Body = &BodyInfo{SHA256: "zz", NormSHA256: "aa"} }), nil},
		{"cert invalid", ok("https"), ok("https", func(r *Result) { r.TLS.Verified = false; r.TLS.VerifyError = "x" }),
			map[string]Severity{"tls.verified": SevCritical}},
		{"cert replaced, valid", ok("https"), ok("https", func(r *Result) { r.TLS.CertSHA256 = "c2" }), map[string]Severity{"tls.cert": SevInfo}},
		{"cert replaced, invalid", ok("https", func(r *Result) { r.TLS.Verified = false }),
			ok("https", func(r *Result) { r.TLS.Verified = false; r.TLS.CertSHA256 = "c2" }), map[string]Severity{"tls.cert": SevWarning}},
		{"cert fixed", ok("https", func(r *Result) { r.TLS.Verified = false }), ok("https"), map[string]Severity{"tls.verified": SevWarning}},
		{"tls version", ok("https"), ok("https", func(r *Result) { r.TLS.Version = "TLS 1.2" }), map[string]Severity{"tls.version": SevInfo}},
		{"strict verify failure both", ok("https", func(r *Result) {
			r.Error = &FetchError{Kind: ErrKindTLSVerify}
			r.TLS.Verified = false
		}), ok("https", func(r *Result) {
			r.Error = &FetchError{Kind: ErrKindTLSVerify}
			r.TLS.Verified = false
		}), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := Compare(snapOf(tt.before), snapOf(tt.after), nil)
			if err != nil {
				t.Fatal(err)
			}
			got := fields(rep)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v (%+v)", got, tt.want, rep.Diffs)
			}
			for f, s := range tt.want {
				if got[f] != s {
					t.Errorf("%s: got %v, want %v", f, got[f], s)
				}
			}
			if tt.want == nil && rep.Counts.Identical != 1 {
				t.Errorf("counts %+v", rep.Counts)
			}
		})
	}
}

func TestCompareMissingAndCounts(t *testing.T) {
	b := snapOf(ok("http"), ok("https"))
	a := snapOf(ok("http"), ok("http", func(r *Result) { r.Target = "new.example.com" }))
	rep, err := Compare(b, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Counts
	if c.Compared != 1 || c.Identical != 1 || c.OnlyBefore != 1 || c.OnlyAfter != 1 || c.Critical != 1 || c.Info != 1 {
		t.Errorf("counts %+v", c)
	}
	if rep.Diffs[0].Severity != SevCritical || rep.Diffs[0].Scheme != "https" {
		t.Errorf("most severe first: %+v", rep.Diffs)
	}
	if !rep.Significant(SevCritical) || !rep.Significant(SevInfo) {
		t.Error("Significant")
	}
}

func TestCompareNotes(t *testing.T) {
	b := snapOf(ok("http"))
	a := snapOf(ok("http", func(r *Result) { r.Body = &BodyInfo{SHA256: "aa", NormSHA256: "different"} }))
	a.Options.BodyRules = "r2"
	b.Options.Repeat = 1
	a.Server = "192.0.2.2"
	rep, err := Compare(b, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(rep.Notes, "\n")
	for _, want := range []string{"different servers", "different body rules", "repeat 1"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q: %s", want, notes)
		}
	}
	// With different body rules the raw hashes decide: equal here.
	if len(rep.Diffs) != 0 {
		t.Errorf("diffs %+v", rep.Diffs)
	}

	a.Options.Method = "HEAD"
	a.Results[0].Body = nil
	rep, _ = Compare(b, a, nil)
	if !strings.Contains(strings.Join(rep.Notes, " "), "Bodies are not compared") || len(rep.Diffs) != 0 {
		t.Errorf("HEAD: notes %q diffs %+v", rep.Notes, rep.Diffs)
	}
}

func TestCompareRulesOverride(t *testing.T) {
	b := snapOf(ok("http", hdr("ETag", `"1"`), hdr("Server", "a")))
	a := snapOf(ok("http", hdr("ETag", `"2"`), hdr("Server", "b")))
	r, err := ParseRules([]byte(`{"headers":[{"names":["etag"],"severity":"critical"}],"other_headers":"ignore"}`))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Compare(b, a, &r)
	if err != nil {
		t.Fatal(err)
	}
	got := fields(rep)
	if got["header:Etag"] != SevCritical {
		t.Errorf("ETag override: %v", got)
	}
	if got["header:Server"] != SevInfo {
		t.Errorf("Server keeps its default rule: %v", got)
	}
}

func TestReportOutput(t *testing.T) {
	b := snapOf(ok("http", hdr("Location", "/a")), ok("https"))
	a := snapOf(ok("http", hdr("Location", "/b\x1b[31m\u202e")), ok("https", hdr("X-New", "1")))
	a.Options.TLSMode = TLSRecord
	rep, err := Compare(b, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	rep.WriteText(&text, false)
	out := text.String()
	if strings.ContainsAny(out, "\x1b\u202e") {
		t.Errorf("control characters reach the terminal: %q", out)
	}
	for _, want := range []string{"CRITICAL:", "http://example.com", "header:Location", "without being required to be valid", "use -v"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	text.Reset()
	rep.WriteText(&text, true)
	if !strings.Contains(text.String(), "X-New") {
		t.Errorf("verbose text lacks info diff:\n%s", text.String())
	}
	var js bytes.Buffer
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Counts != rep.Counts || back.Diffs[0].Severity != SevCritical {
		t.Errorf("JSON round trip: %+v", back.Counts)
	}
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain":       "plain",
		"a\nb":        `a\u000ab`,
		"\x1b[0m":     `\u001b[0m`,
		"\xff":        `\xff`,
		"\u202eevil":  `\u202eevil`,
		"привет":      "привет",
		"\uFFFD kept": "\uFFFD kept",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}
