// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlakyAfter_I11: answers that were stable in the baseline and vary
// after the change are critical, even when the first answer matches.
func TestFlakyAfter_I11(t *testing.T) {
	var sw switchable
	srv := httptest.NewServer(&sw)
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.Repeat = 2
	sw.set(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "site A") })
	before := take(t, cfg, "example.com")

	var n atomic.Int64
	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1)%2 == 0 {
			w.WriteHeader(http.StatusBadGateway)
		}
		fmt.Fprint(w, "site A")
	})
	rep := compare(t, before, take(t, cfg, "example.com"))
	if got := fields(rep); got["body.stability"] != SevCritical || !rep.Significant(SevCritical) {
		t.Errorf("every second request fails after: %v", got)
	}

	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "site %d", n.Add(1)%2)
	})
	rep = compare(t, before, take(t, cfg, "example.com"))
	if got := fields(rep); got["body"] != SevCritical || got["body.stability"] != SevCritical {
		t.Errorf("wrong alternating pages after: %v", got)
	}
}

// TestBrokenPageWithoutRepeat_I11: with a baseline of one request per
// target, a wrong page with the same status and type is still critical
// when the title or the size gives it away.
func TestBrokenPageWithoutRepeat_I11(t *testing.T) {
	site := "<html><head><title>Shop</title></head><body>" + strings.Repeat("goods ", 200) + "</body></html>"
	tests := []struct {
		name  string
		after string
		want  Severity
	}{
		{"default page of another vhost", "<html><head><title>Welcome to nginx!</title></head><body>" + strings.Repeat("x", 1100) + "</body></html>", SevCritical},
		{"blank PHP error", "", SevCritical},
		{"File not found", "File not found.\n", SevCritical},
		{"small edit", strings.Replace(site, "goods goods", "goods  goods", 1), SevWarning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sw switchable
			srv := httptest.NewServer(&sw)
			defer srv.Close()
			cfg := httpConfig(t, srv)
			serve := func(body string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					fmt.Fprint(w, body)
				}
			}
			sw.set(serve(site))
			before := take(t, cfg, "example.com")
			sw.set(serve(tt.after))
			if got := fields(compare(t, before, take(t, cfg, "example.com")))["body"]; got != tt.want {
				t.Errorf("body severity %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateRejectsNonFinite(t *testing.T) {
	for _, r := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 1e-12, -1} {
		c := Config{Server: netip.MustParseAddr("192.0.2.1"), Rate: r}
		if err := c.setDefaults(); err == nil {
			t.Errorf("rate %v accepted", r)
		}
	}
	c := Config{Server: netip.MustParseAddr("fe80::1%eth0")}
	if err := c.setDefaults(); err == nil {
		t.Error("address with zone accepted")
	}
}

// TestTimeoutRace runs many timed-out requests; with -race it checks the
// timing callback against the returning request.
func TestTimeoutRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.Timeout = 20 * time.Millisecond
	cfg.Concurrency = 16
	var names []string
	for i := range 60 {
		names = append(names, fmt.Sprintf("d%d.example.com", i))
	}
	take(t, cfg, names...)
}

func TestEncodedBodies(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	fmt.Fprint(zw, "hello")
	_ = zw.Close()
	var sw switchable
	srv := httptest.NewServer(&sw)
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.Retries = 1

	var calls atomic.Int64
	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
	})
	r := take(t, cfg, "example.com").Results[0]
	if r.Error != nil || r.Body == nil || r.Body.Length != 0 || calls.Load() != 1 {
		t.Errorf("empty gzip body: %+v %+v, %d calls", r.Error, r.Body, calls.Load())
	}

	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		fmt.Fprint(w, "not gzip at all")
	})
	calls.Store(0)
	r = take(t, cfg, "example.com").Results[0]
	if r.Error == nil || r.Error.Kind != ErrKindBody || calls.Load() != 1 {
		t.Errorf("broken gzip must be a body error, not retried: %+v, %d calls", r.Error, calls.Load())
	}

	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		_, _ = w.Write(zbuf.Bytes())
	})
	deflated := take(t, cfg, "example.com").Results[0]
	sw.set(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "hello") })
	plain := take(t, cfg, "example.com").Results[0]
	if deflated.Error != nil || deflated.Body.SHA256 != plain.Body.SHA256 {
		t.Errorf("deflate body not decoded: %+v %+v", deflated.Error, deflated.Body)
	}
}

func TestHeaderRecordLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := range 100 {
			w.Header().Set(fmt.Sprintf("X-H%03d", i), strings.Repeat("v", 200))
		}
	}))
	defer srv.Close()
	r := take(t, httpConfig(t, srv), "example.com").Results[0]
	size := 0
	for k, vs := range r.Header {
		for _, v := range vs {
			size += len(k) + len(v)
		}
	}
	if !r.HeaderTruncated || size > maxRecordedBytes {
		t.Errorf("truncated %v, %d bytes recorded", r.HeaderTruncated, size)
	}
}

func TestReviewCompareCases(t *testing.T) {
	tests := []struct {
		name          string
		before, after Result
		want          map[string]Severity
	}{
		{"same error, different status",
			ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindTimeout} }),
			ok("http", func(r *Result) { r.Error = &FetchError{Kind: ErrKindTimeout}; r.Status = 404 }),
			map[string]Severity{"status": SevCritical}},
		{"invalid certificate to handshake failure",
			ok("https", func(r *Result) { r.Error = &FetchError{Kind: ErrKindTLSVerify}; r.Status = 0 }),
			ok("https", func(r *Result) { r.Error = &FetchError{Kind: ErrKindTLS}; r.Status = 0; r.TLS = nil }),
			map[string]Severity{"error": SevCritical}},
		{"location trailing dot and escape case",
			ok("http", hdr("Location", "http://example.com./a%2fb")), ok("http", hdr("Location", "/a%2Fb")), nil},
		{"location non-default port",
			ok("http", hdr("Location", "http://example.com:8080/")), ok("http", hdr("Location", "http://example.com/")),
			map[string]Severity{"header:Location": SevCritical}},
		{"javascript aliases",
			ok("http", hdr("Content-Type", "application/javascript")), ok("http", hdr("Content-Type", "text/javascript; charset=utf-8")),
			map[string]Severity{"header:Content-Type": SevWarning}},
		{"header names in any case",
			ok("http", hdr("location", "/a")), ok("http", hdr("LOCATION", "/b")),
			map[string]Severity{"header:Location": SevCritical}},
		{"title changed on dynamic page",
			ok("http", func(r *Result) { r.Body.Stable = new(false); r.Body.Title = "Shop" }),
			ok("http", func(r *Result) { r.Body = &BodyInfo{Length: 1, SHA256: "b", NormSHA256: "b", Title: "Index of /"} }),
			map[string]Severity{"body": SevCritical}},
		{"flaky after",
			ok("http"), ok("http", func(r *Result) { r.Body.Stable = new(false); r.Body.Unstable = "repeat 2 returned status 502" }),
			map[string]Severity{"body.stability": SevCritical}},
		{"redirect body only",
			ok("http", func(r *Result) { r.Status = 301 }),
			ok("http", func(r *Result) { r.Status = 301; r.Body = &BodyInfo{SHA256: "b", NormSHA256: "b", Title: "x"} }),
			map[string]Severity{"body": SevInfo}},
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
		})
	}
}

func TestReviewRules(t *testing.T) {
	r, err := ParseRules([]byte(`{"headers":[{"names":["Location"],"removed":"critical"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileRules(&r); err == nil {
		t.Error("header rule without severity accepted")
	}

	c, _ := compileRules(nil)
	a := c.normalizeBody([]byte("<p>x</p><!-- Cached page generated by WP-Super-Cache on 2026-11-26 10:00:00 -->"))
	b := c.normalizeBody([]byte("<p>x</p><!-- Cached page generated by WP-Super-Cache on 2026-11-27 11:00:00 -->"))
	if !bytes.Equal(a, b) {
		t.Errorf("cache comment not masked: %s", a)
	}

	r, _ = ParseRules([]byte(`{"body_patterns":[{"name":"x","regexp":"(a)"}]}`))
	rep, err := Compare(snapOf(ok("http")), snapOf(ok("http")), &r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "no effect here") {
		t.Errorf("notes: %q", rep.Notes)
	}
}

func TestLoadSnapshotRejectsReviewCases(t *testing.T) {
	good := string(mustJSON(t, snapOf(ok("http"))))
	for name, data := range map[string]string{
		"zone":      strings.Replace(good, `"192.0.2.1"`, `"fe80::1%\u001b[2J"`, 1),
		"port zero": strings.Replace(good, `"http_port":80`, `"http_port":0`, 1),
	} {
		if _, err := LoadSnapshot([]byte(data)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
