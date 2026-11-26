// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// switchable serves whatever handler is current, so one server (one
// port) can play "before" and "after".
type switchable struct{ h atomic.Value }

func (s *switchable) set(h http.HandlerFunc) { s.h.Store(h) }
func (s *switchable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.h.Load().(http.HandlerFunc)(w, r)
}

// portRewriter replaces "{port}" in a Location header with the test
// server port.
type portRewriter struct {
	http.ResponseWriter
	port string
}

func (p *portRewriter) WriteHeader(code int) {
	if l := p.Header().Get("Location"); l != "" {
		p.Header().Set("Location", strings.ReplaceAll(l, "{port}", p.port))
	}
	p.ResponseWriter.WriteHeader(code)
}

func port(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func targets(t *testing.T, ss ...string) []Target {
	t.Helper()
	out := make([]Target, len(ss))
	for i, s := range ss {
		tg, err := ParseTarget(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = tg
	}
	return out
}

func httpConfig(t *testing.T, srv *httptest.Server) Config {
	return Config{
		Server:   netip.MustParseAddr("127.0.0.1"),
		Schemes:  []string{"http"},
		HTTPPort: port(t, srv),
		Rate:     MaxRate,
		Timeout:  5 * time.Second,
		Retries:  -1,
	}
}

func take(t *testing.T, cfg Config, tg ...string) *Snapshot {
	t.Helper()
	s, err := Take(context.Background(), cfg, targets(t, tg...))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	// Every snapshot must survive a save/load round trip.
	data := mustJSON(t, s)
	if _, err := LoadSnapshot(data); err != nil {
		t.Fatalf("LoadSnapshot of a fresh snapshot: %v", err)
	}
	return s
}

func compare(t *testing.T, before, after *Snapshot) *Report {
	t.Helper()
	rep, err := Compare(before, after, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func fields(rep *Report) map[string]Severity {
	out := map[string]Severity{}
	for _, d := range rep.Diffs {
		for _, c := range d.Changes {
			out[c.Field] = max(out[c.Field], c.Severity)
		}
	}
	return out
}

func page(token, nonce string) string {
	return `<html><head><meta name="csrf-token" content="` + token + `">
<script nonce="` + nonce + `">var wpApiSettings = {"root":"/","nonce":"` + nonce + `"};</script></head>
<body><form><input type="hidden" name="_wpnonce" value="` + nonce + `"><input name="q"></form>Hello</body></html>`
}

// TestBeforeAfter_I11 runs the scenarios of a migration check against a
// real HTTP server: the handler is swapped between the two snapshots.
func TestBeforeAfter_I11(t *testing.T) {
	var n atomic.Int64
	fresh := func() string { return fmt.Sprintf("tok%d", n.Add(1)) }
	static := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}
	}
	volatile := func(w http.ResponseWriter, _ *http.Request) {
		v := fresh()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"`+v+`"`)
		w.Header().Set("Last-Modified", time.Now().Add(-time.Duration(n.Load())*time.Hour).Format(http.TimeFormat))
		w.Header().Set("Set-Cookie", "session="+v+"; Path=/; HttpOnly; Expires="+time.Now().Format(http.TimeFormat))
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-"+v+"'")
		w.Header().Set("X-Request-Id", v)
		fmt.Fprint(w, page(v, v))
	}
	// Like Apache and nginx, the two "servers" word the redirect page
	// differently; that must not matter.
	redirect := func(loc string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", loc)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusMovedPermanently)
			fmt.Fprint(w, "<p>Moved to "+loc+"</p>")
		}
	}
	tests := []struct {
		name          string
		before, after http.HandlerFunc
		repeat        int
		want          map[string]Severity // fields that must differ; nil = identical
	}{
		{name: "identical", before: static(200, "a"), after: static(200, "a")},
		{name: "changed status", before: static(200, "a"), after: static(502, "a"),
			want: map[string]Severity{"status": SevCritical}},
		{name: "changed redirect target", before: redirect("https://example.com/"), after: redirect("https://www.example.com/"),
			want: map[string]Severity{"header:Location": SevCritical, "body": SevInfo}},
		{name: "relative and absolute redirect are equal", before: redirect("/new"), after: redirect("http://EXAMPLE.com:{port}/new"),
			want: map[string]Severity{"body": SevInfo}},
		{name: "changed body, stable baseline", before: static(200, "a"), after: static(200, "b"), repeat: 2,
			want: map[string]Severity{"body": SevCritical}},
		{name: "changed body, baseline stability unknown", before: static(200, "a"), after: static(200, "b"),
			want: map[string]Severity{"body": SevWarning}},
		{name: "volatile data only", before: volatile, after: volatile, repeat: 2},
		{name: "charset spelling only", before: static(200, "a"), after: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			fmt.Fprint(w, "a")
		}},
		{name: "dynamic page", repeat: 2,
			before: func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, fresh()) },
			after:  func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, fresh()) },
			want:   map[string]Severity{"body": SevInfo}},
		{name: "security header lost", before: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			fmt.Fprint(w, "a")
		}, after: func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "a") },
			want: map[string]Severity{"header:Strict-Transport-Security": SevCritical}},
		{name: "server header changes", before: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Apache")
			fmt.Fprint(w, "a")
		}, after: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "nginx")
			fmt.Fprint(w, "a")
		}, want: map[string]Severity{"header:Server": SevInfo}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sw switchable
			srv := httptest.NewServer(&sw)
			defer srv.Close()
			cfg := httpConfig(t, srv)
			cfg.Repeat = tt.repeat
			sw.set(tt.before)
			before := take(t, cfg, "example.com")
			next := tt.after
			sw.set(func(w http.ResponseWriter, r *http.Request) {
				next(&portRewriter{ResponseWriter: w, port: strconv.Itoa(cfg.HTTPPort)}, r)
			})
			after := take(t, cfg, "example.com")
			rep := compare(t, before, after)
			got := fields(rep)
			if tt.want == nil && len(rep.Diffs) > 0 {
				t.Fatalf("want identical, got %+v", rep.Diffs)
			}
			for f, sev := range tt.want {
				if got[f] != sev {
					t.Errorf("field %s: severity %v, want %v (all: %v)", f, got[f], sev, got)
				}
			}
			for f := range got {
				if _, ok := tt.want[f]; !ok {
					t.Errorf("unexpected difference in %s: %+v", f, rep.Diffs)
				}
			}
			wantSig := false
			for _, s := range tt.want {
				wantSig = wantSig || s == SevCritical
			}
			if rep.Significant(SevCritical) != wantSig {
				t.Errorf("Significant = %v, want %v", !wantSig, wantSig)
			}
		})
	}
}

// TestRequestIsSafe_N7 checks what reaches the probed server: GET only,
// no cookies or credentials, redirects not followed, Host is the domain,
// and proxies from the environment are not used.
func TestRequestIsSafe_N7(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	var mu sync.Mutex
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		mu.Unlock()
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "s", Value: "secret", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/next", http.StatusFound)
		}
	}))
	defer srv.Close()
	cfg := httpConfig(t, srv)
	s := take(t, cfg, "example.com")
	if len(seen) != 1 {
		t.Fatalf("server saw %d requests, want 1 (redirect must not be followed)", len(seen))
	}
	r := seen[0]
	if r.Method != http.MethodGet {
		t.Errorf("method %s", r.Method)
	}
	if want := fmt.Sprintf("example.com:%d", cfg.HTTPPort); r.Host != want {
		t.Errorf("Host = %q, want %q", r.Host, want)
	}
	for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization"} {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("request has %s: %q", h, v)
		}
	}
	if s.Results[0].Status != http.StatusFound {
		t.Errorf("status %d", s.Results[0].Status)
	}
	if got := s.Results[0].Header["Set-Cookie"]; len(got) != 1 || strings.Contains(got[0], "secret") {
		t.Errorf("Set-Cookie recorded as %q; the value must be dropped", got)
	}

	cfg.Method = http.MethodHead
	seen = nil
	s = take(t, cfg, "example.com")
	if seen[0].Method != http.MethodHead || s.Results[0].Body != nil {
		t.Errorf("HEAD: method %s, body %+v", seen[0].Method, s.Results[0].Body)
	}
	cfg.Method = http.MethodPost
	if _, err := Take(context.Background(), cfg, targets(t, "example.com")); err == nil {
		t.Error("POST accepted")
	}
}

func tlsServer(t *testing.T, sni *atomic.Value) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "secure")
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni.Store(h.ServerName)
		return nil, nil
	}}
	srv.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

// TestTLS_I11 covers SNI, strict verification and record mode. The
// httptest certificate is valid for example.com only.
func TestTLS_I11(t *testing.T) {
	var sni atomic.Value
	srv, pool := tlsServer(t, &sni)
	defer srv.Close()
	cfg := Config{
		Server:    netip.MustParseAddr("127.0.0.1"),
		Schemes:   []string{"https"},
		HTTPSPort: port(t, srv),
		RootCAs:   pool,
		Rate:      MaxRate,
		Retries:   -1,
	}

	s := take(t, cfg, "example.com")
	r := s.Results[0]
	if r.Error != nil || r.Status != 200 {
		t.Fatalf("valid certificate: %+v", r)
	}
	if got := sni.Load(); got != "example.com" {
		t.Errorf("SNI = %v, want example.com", got)
	}
	if r.TLS == nil || !r.TLS.Verified || r.TLS.CertSHA256 == "" || r.TLS.Version == "" {
		t.Errorf("TLS info %+v", r.TLS)
	}
	valid := s

	// Strict: a certificate not valid for the name is an error, but the
	// certificate is still recorded.
	s = take(t, cfg, "other.example.org")
	r = s.Results[0]
	if r.Error == nil || r.Error.Kind != ErrKindTLSVerify || r.Status != 0 {
		t.Fatalf("strict, wrong name: %+v", r)
	}
	if r.TLS == nil || r.TLS.Verified || r.TLS.VerifyError == "" || r.TLS.CertSHA256 == "" {
		t.Errorf("strict, wrong name: TLS info %+v", r.TLS)
	}
	if sni.Load() != "other.example.org" {
		t.Errorf("SNI = %v", sni.Load())
	}

	// Record: the request goes on and the failure is recorded.
	cfg.TLSMode = TLSRecord
	s = take(t, cfg, "other.example.org")
	r = s.Results[0]
	if r.Error != nil || r.Status != 200 || r.TLS.Verified || r.TLS.VerifyError == "" {
		t.Fatalf("record, wrong name: %+v %+v", r, r.TLS)
	}

	// Record mode, certificate becomes invalid: critical, and the report
	// says certificates were not required to be valid.
	cfg.RootCAs = x509.NewCertPool() // trusts nothing
	after := take(t, cfg, "example.com")
	rep := compare(t, valid, after)
	if fields(rep)["tls.verified"] != SevCritical {
		t.Errorf("valid -> invalid certificate: %+v", rep.Diffs)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "without being required to be valid") {
		t.Errorf("notes do not mention record mode: %q", rep.Notes)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)
	cfg := httpConfig(t, srv)
	cfg.Timeout = 200 * time.Millisecond
	start := time.Now()
	s := take(t, cfg, "example.com")
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v with a 200ms timeout", d)
	}
	if r := s.Results[0]; r.Error == nil || r.Error.Kind != ErrKindTimeout {
		t.Fatalf("result %+v", r)
	}
}

func TestSlowBodyTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.Timeout = 200 * time.Millisecond
	r := take(t, cfg, "example.com").Results[0]
	if r.Error == nil || r.Error.Kind != ErrKindTimeout || r.Status != 200 {
		t.Fatalf("result %+v, error %+v", r, r.Error)
	}
}

func TestRetries(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			hj, _, _ := w.(http.Hijacker).Hijack()
			_ = hj.Close() // reset the first attempt
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.Retries = 1
	r := take(t, cfg, "example.com").Results[0]
	if r.Error != nil || r.Attempts != 2 {
		t.Fatalf("result %+v", r)
	}
}

func TestConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cfg := Config{Server: netip.MustParseAddr("127.0.0.1"), Schemes: []string{"http"}, HTTPPort: p, Rate: MaxRate, Retries: -1}
	r := take(t, cfg, "example.com").Results[0]
	if r.Error == nil || r.Error.Kind != ErrKindRefused {
		t.Fatalf("result %+v", r)
	}
}

// TestOversizedBody checks that at most MaxBody bytes are read and the
// truncation is recorded.
func TestOversizedBody(t *testing.T) {
	var written atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		for range 1024 { // 32 MiB
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.MaxBody = 1000
	r := take(t, cfg, "example.com").Results[0]
	if r.Error != nil || r.Body == nil || !r.Body.Truncated || r.Body.Length != 1000 {
		t.Fatalf("result %+v body %+v", r, r.Body)
	}
	srv.Close() // wait for the handler
	if w := written.Load(); w >= 32<<20 {
		t.Errorf("server wrote the whole body (%d bytes); the client should stop reading", w)
	}
}

// TestGzipBomb checks that the decoded size is bounded too.
func TestGzipBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(make([]byte, 50<<20))
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()
	cfg := httpConfig(t, srv)
	cfg.MaxBody = 4096
	r := take(t, cfg, "example.com").Results[0]
	if r.Error != nil || !r.Body.Truncated || r.Body.Length != 4096 {
		t.Fatalf("result %+v body %+v", r, r.Body)
	}
}

// TestGzipHashedDecoded checks that compression does not change the
// body hash, only the Content-Encoding header.
func TestGzipHashedDecoded(t *testing.T) {
	const body = "<html>same content</html>"
	var sw switchable
	srv := httptest.NewServer(&sw)
	defer srv.Close()
	cfg := httpConfig(t, srv)
	sw.set(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("Accept-Encoding = %q", r.Header.Get("Accept-Encoding"))
		}
		fmt.Fprint(w, body)
	})
	before := take(t, cfg, "example.com")
	sw.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		fmt.Fprint(zw, body)
		_ = zw.Close()
	})
	after := take(t, cfg, "example.com")
	got := fields(compare(t, before, after))
	if len(got) != 1 || got["header:Content-Encoding"] != SevWarning {
		t.Errorf("differences %v, want only Content-Encoding", got)
	}
}

// TestConcurrencyAndRate_N1 checks the bounds that protect a production
// server: requests in flight and requests per second.
func TestConcurrencyAndRate_N1(t *testing.T) {
	var cur, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		cur.Add(-1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	var names []string
	for i := range 24 {
		names = append(names, fmt.Sprintf("d%d.example.com", i))
	}
	cfg := httpConfig(t, srv)
	cfg.Concurrency = 3
	take(t, cfg, names...)
	if p := peak.Load(); p > 3 || p < 2 {
		t.Errorf("peak concurrency %d, want 2..3", p)
	}

	cfg.Concurrency = 8
	cfg.Rate = 50
	start := time.Now()
	s := take(t, cfg, names[:10]...)
	// 10 requests at 50/s: the last starts 9 intervals after the first.
	if d := time.Since(start); d < 170*time.Millisecond {
		t.Errorf("10 requests at 50/s took %v", d)
	}
	if len(s.Results) != 10 {
		t.Errorf("%d results", len(s.Results))
	}
}

func TestTakeCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Take(ctx, httpConfig(t, srv), targets(t, "example.com")); err == nil {
		t.Error("canceled Take returned no error")
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{Server: netip.MustParseAddr("192.0.2.1")}
	bad := []func(c *Config){
		func(c *Config) { c.Server = netip.Addr{} },
		func(c *Config) { c.Server = netip.MustParseAddr("0.0.0.0") },
		func(c *Config) { c.Server = netip.MustParseAddr("ff02::1") },
		func(c *Config) { c.Schemes = []string{"ftp"} },
		func(c *Config) { c.Schemes = []string{"http", "http"} },
		func(c *Config) { c.HTTPPort = 70000 },
		func(c *Config) { c.Method = "DELETE" },
		func(c *Config) { c.Timeout = -1 },
		func(c *Config) { c.MaxBody = MaxMaxBody + 1 },
		func(c *Config) { c.TLSMode = "off" },
		func(c *Config) { c.Concurrency = MaxConcurrency + 1 },
		func(c *Config) { c.Rate = MaxRate + 1 },
		func(c *Config) { c.Repeat = MaxRepeat + 1 },
		func(c *Config) { c.Retries = MaxRetries + 1 },
	}
	c := ok
	if err := c.setDefaults(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if c.Method != "GET" || c.TLSMode != TLSStrict || c.Rate != DefaultRate || c.Concurrency != DefaultConcurrency {
		t.Errorf("defaults %+v", c)
	}
	for i, f := range bad {
		c := ok
		f(&c)
		if err := c.setDefaults(); err == nil {
			t.Errorf("case %d: accepted %+v", i, c)
		}
	}
}
