// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/fornex/fngx/internal/product"
)

// TLSMode says what to do with a certificate that fails verification.
type TLSMode string

// TLS modes.
const (
	// TLSStrict rejects the connection, like a browser. The certificate
	// details are still recorded with an ErrKindTLSVerify error.
	TLSStrict TLSMode = "strict"
	// TLSRecord records the verification result and goes on with the
	// request, so sites with invalid certificates can be compared too.
	TLSRecord TLSMode = "record"
)

// Defaults and limits for [Config]. The defaults are meant to be gentle
// on a production server: 10,000 domains on two schemes take about
// 35 minutes at 10 requests per second, twice that with Repeat 2.
const (
	DefaultConcurrency = 8
	DefaultRate        = 10
	DefaultTimeout     = 15 * time.Second
	DefaultMaxBody     = 1 << 20
	DefaultRetries     = 1

	MaxConcurrency = 256
	MinRate        = 0.01
	MaxRate        = 1000
	MaxRepeat      = 5
	MaxRetries     = 3
	MaxMaxBody     = 64 << 20

	maxHeaderBytes   = 64 << 10
	maxRecordedBytes = 8 << 10 // header bytes stored per response
	maxMessageLen    = 300
	maxTitle         = 200
)

// Config configures [Take].
type Config struct {
	// Server is the address every request is sent to.
	Server netip.Addr
	// Schemes to request; default both "http" and "https".
	Schemes   []string
	HTTPPort  int // default 80
	HTTPSPort int // default 443
	// Method is GET (default) or HEAD.
	Method string
	// Timeout bounds each attempt, including reading the body.
	Timeout time.Duration
	// MaxBody is the number of body bytes read and hashed.
	MaxBody int64
	TLSMode TLSMode // default TLSStrict
	// RootCAs to verify certificates against; nil means the system roots.
	RootCAs *x509.CertPool
	// Concurrency bounds the requests in flight.
	Concurrency int
	// Rate bounds the requests started per second.
	Rate float64
	// Repeat is the number of requests per target and scheme used to
	// detect unstable bodies; 0 and 1 mean one request.
	Repeat int
	// Retries is the number of extra attempts after a network error or
	// timeout; zero or negative means none.
	Retries int
	// Rules are merged over the defaults; nil means the defaults.
	Rules *Rules
	// Progress, if set, is called after each target and scheme is done.
	Progress func(done, total int)
}

func (c *Config) setDefaults() error {
	if !c.Server.IsValid() || c.Server.IsUnspecified() || c.Server.IsMulticast() || c.Server.Zone() != "" {
		return fmt.Errorf("%w: server address %q", ErrInvalid, c.Server)
	}
	c.Server = c.Server.Unmap()
	if len(c.Schemes) == 0 {
		c.Schemes = []string{"http", "https"}
	}
	seen := map[string]bool{}
	for _, s := range c.Schemes {
		if s != "http" && s != "https" {
			return fmt.Errorf("%w: scheme %q", ErrInvalid, s)
		}
		if seen[s] {
			return fmt.Errorf("%w: scheme %q given twice", ErrInvalid, s)
		}
		seen[s] = true
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.HTTPPort < 1 || c.HTTPPort > 65535 || c.HTTPSPort < 1 || c.HTTPSPort > 65535 {
		return fmt.Errorf("%w: port out of range", ErrInvalid)
	}
	switch c.Method {
	case "":
		c.Method = http.MethodGet
	case http.MethodGet, http.MethodHead:
	default:
		return fmt.Errorf("%w: method %q; only GET and HEAD are allowed", ErrInvalid, c.Method)
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.Timeout < 0 {
		return fmt.Errorf("%w: negative timeout", ErrInvalid)
	}
	if c.MaxBody == 0 {
		c.MaxBody = DefaultMaxBody
	}
	if c.MaxBody < 0 || c.MaxBody > MaxMaxBody {
		return fmt.Errorf("%w: max body must be 1..%d bytes", ErrInvalid, MaxMaxBody)
	}
	switch c.TLSMode {
	case "":
		c.TLSMode = TLSStrict
	case TLSStrict, TLSRecord:
	default:
		return fmt.Errorf("%w: TLS mode %q", ErrInvalid, c.TLSMode)
	}
	if c.Concurrency == 0 {
		c.Concurrency = DefaultConcurrency
	}
	if c.Concurrency < 1 || c.Concurrency > MaxConcurrency {
		return fmt.Errorf("%w: concurrency must be 1..%d", ErrInvalid, MaxConcurrency)
	}
	if c.Rate == 0 {
		c.Rate = DefaultRate
	}
	// The negated form also rejects NaN, which compares false with
	// everything and would disable the limiter.
	if !(c.Rate >= MinRate && c.Rate <= MaxRate) {
		return fmt.Errorf("%w: rate must be %g..%d requests per second", ErrInvalid, MinRate, MaxRate)
	}
	if c.Repeat < 1 {
		c.Repeat = 1
	}
	if c.Repeat > MaxRepeat {
		return fmt.Errorf("%w: repeat must be 1..%d", ErrInvalid, MaxRepeat)
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	if c.Retries > MaxRetries {
		return fmt.Errorf("%w: retries must be 0..%d", ErrInvalid, MaxRetries)
	}
	return nil
}

// Take requests every target over every configured scheme and returns
// the snapshot. Results are sorted by target and scheme. It returns an
// error only for invalid configuration or when ctx is canceled; failed
// requests are recorded in the results.
func Take(ctx context.Context, cfg Config, targets []Target) (*Snapshot, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: no targets", ErrInvalid)
	}
	rules, err := compileRules(cfg.Rules)
	if err != nil {
		return nil, err
	}
	p := newProber(&cfg, rules)
	defer p.client.CloseIdleConnections()

	type job struct {
		t      Target
		scheme string
		i      int
	}
	jobs := make(chan job)
	results := make([]Result, len(targets)*len(cfg.Schemes))
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		done int
	)
	for range cfg.Concurrency {
		wg.Go(func() {
			for j := range jobs {
				results[j.i] = p.probe(ctx, j.t, j.scheme)
				if cfg.Progress != nil {
					mu.Lock()
					done++
					cfg.Progress(done, len(results))
					mu.Unlock()
				}
			}
		})
	}
	started := time.Now().UTC()
	i := 0
feed:
	for _, t := range targets {
		for _, s := range cfg.Schemes {
			select {
			case jobs <- job{t: t, scheme: s, i: i}:
				i++
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(results, func(a, b int) bool {
		if results[a].Target != results[b].Target {
			return results[a].Target < results[b].Target
		}
		return results[a].Scheme < results[b].Scheme
	})
	return &Snapshot{
		Version:  SnapshotVersion,
		Tool:     fmt.Sprintf("%s %s", product.Name, product.Version),
		Server:   cfg.Server.String(),
		Started:  started,
		Finished: time.Now().UTC(),
		Options: Options{
			Method:      cfg.Method,
			HTTPPort:    cfg.HTTPPort,
			HTTPSPort:   cfg.HTTPSPort,
			TimeoutMS:   cfg.Timeout.Milliseconds(),
			MaxBody:     cfg.MaxBody,
			TLSMode:     cfg.TLSMode,
			Repeat:      cfg.Repeat,
			Retries:     cfg.Retries,
			Concurrency: cfg.Concurrency,
			Rate:        cfg.Rate,
			BodyRules:   rules.bodyFP,
		},
		Results: results,
	}, nil
}

type prober struct {
	cfg     *Config
	rules   *compiledRules
	client  *http.Client
	limiter *limiter
}

// certError carries the certificate details out of a handshake that
// failed verification in strict mode.
type certError struct {
	info *TLSInfo
	err  error
}

func (e *certError) Error() string { return "certificate verification failed: " + e.err.Error() }
func (e *certError) Unwrap() error { return e.err }

func newProber(cfg *Config, rules *compiledRules) *prober {
	p := &prober{cfg: cfg, rules: rules, limiter: newLimiter(cfg.Rate)}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	server := cfg.Server.String()
	tlsConf := &tls.Config{
		// Verification is done in VerifyConnection (strict mode) or after
		// the response (record mode) so that the certificate is recorded
		// either way.
		InsecureSkipVerify: true, //nolint:gosec // verified below; see TLSMode
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	if cfg.TLSMode == TLSStrict {
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			if err := verifyChain(cs, cfg.RootCAs); err != nil {
				info := tlsInfo(cs)
				info.VerifyError = truncate(err.Error())
				return &certError{info: info, err: err}
			}
			return nil
		}
	}
	tr := &http.Transport{
		// Never use a proxy from the environment: requests go to Server.
		Proxy: nil,
		// Ignore the host in addr: the URL carries the domain for the
		// Host header and SNI, the connection always goes to Server.
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, port))
		},
		TLSClientConfig:        tlsConf,
		TLSHandshakeTimeout:    cfg.Timeout,
		ResponseHeaderTimeout:  cfg.Timeout,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxHeaderBytes,
		// A non-nil empty map disables HTTP/2.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	p.client = &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return p
}

func verifyChain(cs tls.ConnectionState, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Roots:         roots,
		Intermediates: inter,
	})
	return err
}

func tlsInfo(cs tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version: tls.VersionName(cs.Version),
		Cipher:  tls.CipherSuiteName(cs.CipherSuite),
		ALPN:    cs.NegotiatedProtocol,
	}
	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		sum := sha256.Sum256(c.Raw)
		info.CertSHA256 = hex.EncodeToString(sum[:])
		info.Subject = truncate(c.Subject.String())
		info.Issuer = truncate(c.Issuer.String())
		if len(c.DNSNames) > 100 {
			info.DNSNames = append([]string(nil), c.DNSNames[:100]...)
		} else {
			info.DNSNames = append([]string(nil), c.DNSNames...)
		}
		info.NotBefore = c.NotBefore.UTC()
		info.NotAfter = c.NotAfter.UTC()
	}
	return info
}

// probe requests one target over one scheme Repeat times and returns the
// first result, with Body.Stable set when Repeat >= 2.
func (p *prober) probe(ctx context.Context, t Target, scheme string) Result {
	first := p.attempt(ctx, t, scheme)
	if p.cfg.Repeat < 2 || first.Body == nil || first.Error != nil {
		return first
	}
	stable := true
	for n := 1; n < p.cfg.Repeat && stable; n++ {
		r := p.attempt(ctx, t, scheme)
		switch {
		case r.Error != nil:
			first.Body.Unstable = fmt.Sprintf("repeat %d failed: %s", n+1, r.Error.Kind)
		case r.Status != first.Status:
			first.Body.Unstable = fmt.Sprintf("repeat %d returned status %d", n+1, r.Status)
		case r.Body == nil || r.Body.NormSHA256 != first.Body.NormSHA256:
			first.Body.Unstable = fmt.Sprintf("repeat %d returned another body", n+1)
		default:
			continue
		}
		stable = false
	}
	first.Body.Stable = &stable
	return first
}

// attempt makes the request with retries on transient errors.
func (p *prober) attempt(ctx context.Context, t Target, scheme string) Result {
	var r Result
	for n := 0; n <= p.cfg.Retries; n++ {
		if n > 0 && sleep(ctx, time.Duration(n)*time.Second) != nil {
			break
		}
		r = p.once(ctx, t, scheme)
		r.Attempts = n + 1
		if r.Error == nil || !retryable(r.Error.Kind) {
			break
		}
	}
	return r
}

func retryable(kind string) bool {
	switch kind {
	case ErrKindTimeout, ErrKindRefused, ErrKindReset:
		return true
	}
	return false
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *prober) once(parent context.Context, t Target, scheme string) Result {
	r := Result{Target: t.String(), Scheme: scheme}
	if err := p.limiter.wait(parent); err != nil {
		r.Error = &FetchError{Kind: ErrKindCanceled, Message: err.Error()}
		return r
	}
	ctx, cancel := context.WithTimeout(parent, p.cfg.Timeout)
	defer cancel()
	port := p.cfg.HTTPPort
	if scheme == "https" {
		port = p.cfg.HTTPSPort
	}
	start := time.Now()
	// The trace callback runs on a transport goroutine that may still be
	// running when a timed-out request returns.
	var ttfb atomic.Int64
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotFirstResponseByte: func() { ttfb.Store(time.Since(start).Milliseconds()) },
	})
	req, err := http.NewRequestWithContext(ctx, p.cfg.Method, t.URL(scheme, port), nil)
	if err != nil {
		r.Error = &FetchError{Kind: ErrKindOther, Message: truncate(err.Error())}
		return r
	}
	req.Header.Set("User-Agent", product.Name+"-respdiff/"+product.Version)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := p.client.Do(req)
	if err != nil {
		r.TimeMS = time.Since(start).Milliseconds()
		r.TTFBMS = ttfb.Load()
		r.Error = classify(parent, err)
		if ce := (*certError)(nil); errors.As(err, &ce) {
			r.TLS = ce.info
		}
		return r
	}
	defer func() { _ = resp.Body.Close() }()
	r.Status = resp.StatusCode
	r.Proto = resp.Proto
	r.Header, r.HeaderTruncated = recordHeader(resp.Header)
	if resp.TLS != nil {
		r.TLS = tlsInfo(*resp.TLS)
		if p.cfg.TLSMode == TLSStrict {
			r.TLS.Verified = true
		} else if err := verifyChain(*resp.TLS, p.cfg.RootCAs); err != nil {
			r.TLS.VerifyError = truncate(err.Error())
		} else {
			r.TLS.Verified = true
		}
	}
	if p.cfg.Method != http.MethodHead {
		body, err := p.readBody(resp)
		if err != nil {
			// Only a deadline or cancellation keeps its kind: decode errors
			// are not network failures and must not be retried.
			// When the deadline closes the connection the read error
			// does not say so; the request context does.
			r.Error = classify(parent, err)
			switch {
			case r.Error.Kind == ErrKindCanceled:
			case ctx.Err() != nil:
				r.Error.Kind = ErrKindTimeout
			case r.Error.Kind != ErrKindTimeout:
				r.Error.Kind = ErrKindBody
			}
		} else {
			r.Body = body
		}
	}
	r.TimeMS = time.Since(start).Milliseconds()
	r.TTFBMS = ttfb.Load()
	return r
}

func (p *prober) readBody(resp *http.Response) (*BodyInfo, error) {
	b := &BodyInfo{Encoding: strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))}
	br := bufio.NewReader(resp.Body)
	var src io.Reader = br
	enc := b.Encoding
	if _, err := br.Peek(1); errors.Is(err, io.EOF) {
		enc = "" // an empty body is empty whatever its declared encoding
	}
	switch enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = zr.Close() }()
		src = zr
	case "deflate":
		zr, err := zlib.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("deflate: %w", err)
		}
		defer func() { _ = zr.Close() }()
		src = zr
	default:
		b.Undecoded = true
	}
	// Read one byte more than the limit to detect truncation. Reading
	// stops there: the connection is closed, not drained.
	data, err := io.ReadAll(io.LimitReader(src, p.cfg.MaxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > p.cfg.MaxBody {
		data = data[:p.cfg.MaxBody]
		b.Truncated = true
	}
	b.Length = int64(len(data))
	sum := sha256.Sum256(data)
	b.SHA256 = hex.EncodeToString(sum[:])
	b.NormSHA256 = b.SHA256
	if !b.Undecoded && isText(resp.Header.Get("Content-Type")) {
		norm := p.rules.normalizeBody(data)
		b.Title = htmlTitle(norm)
		if !bytes.Equal(norm, data) {
			sum := sha256.Sum256(norm)
			b.NormSHA256 = hex.EncodeToString(sum[:])
		}
	}
	return b, nil
}

var titleRx = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title`)

// htmlTitle returns the normalized text of the first <title> element, at
// most maxTitle characters, or "".
func htmlTitle(b []byte) string {
	m := titleRx.FindSubmatch(b)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(string(m[1])), " ")
	if !utf8.ValidString(t) {
		t = strings.ToValidUTF8(t, "\uFFFD")
	}
	if r := []rune(t); len(r) > maxTitle {
		t = string(r[:maxTitle])
	}
	return t
}

// isText reports whether body patterns apply to a body of this type. A
// missing Content-Type counts as text: servers often omit it for HTML.
func isText(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"),
		mt == "application/json", mt == "application/javascript",
		mt == "application/xml", mt == "application/x-javascript":
		return true
	}
	return false
}

// recordHeader copies the response header. Set-Cookie values are
// replaced by their names and attributes: they may be session secrets
// and change on every request anyway.
//
// At most maxRecordedBytes are stored per response, so snapshots stay
// loadable whatever the sites send; headers are taken in name order and
// the rest is dropped, which truncated reports.
func recordHeader(h http.Header) (out map[string][]string, truncated bool) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out = make(map[string][]string, len(h))
	size := 0
	for _, k := range keys {
		for _, v := range h[k] {
			if k == "Set-Cookie" {
				v = redactCookie(v)
			}
			size += len(k) + len(v)
			if size > maxRecordedBytes {
				return out, true
			}
			out[k] = append(out[k], v)
		}
	}
	return out, false
}

// redactCookie keeps the cookie name and its attributes, lower-cased
// and sorted, without the value and the volatile Expires attribute.
func redactCookie(v string) string {
	parts := strings.Split(v, ";")
	name, _, _ := strings.Cut(parts[0], "=")
	var attrs []string
	for _, a := range parts[1:] {
		k, val, hasVal := strings.Cut(strings.TrimSpace(a), "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" || k == "expires" {
			continue
		}
		if hasVal {
			k += "=" + strings.ToLower(strings.TrimSpace(val))
		}
		attrs = append(attrs, k)
	}
	sort.Strings(attrs)
	return strings.Join(append([]string{strings.TrimSpace(name)}, attrs...), "; ")
}

// classify maps a request error to a FetchError. parent is the context
// of the whole run, to tell cancellation from a per-request timeout.
func classify(parent context.Context, err error) *FetchError {
	fe := &FetchError{Kind: ErrKindOther, Message: truncate(err.Error())}
	var (
		ce  *certError
		ne  net.Error
		rhe tls.RecordHeaderError
		ae  tls.AlertError
		cve *tls.CertificateVerificationError
	)
	switch {
	case parent.Err() != nil:
		fe.Kind = ErrKindCanceled
	case errors.As(err, &ce):
		fe.Kind = ErrKindTLSVerify
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		fe.Kind = ErrKindTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		fe.Kind = ErrKindRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		fe.Kind = ErrKindReset
	case errors.As(err, &rhe), errors.As(err, &ae), errors.As(err, &cve),
		strings.Contains(err.Error(), "tls: "):
		fe.Kind = ErrKindTLS
	case strings.Contains(err.Error(), "malformed HTTP"),
		strings.Contains(err.Error(), "server response headers exceeded"):
		fe.Kind = ErrKindProtocol
	}
	return fe
}

func truncate(s string) string {
	if len(s) > maxMessageLen {
		return s[:maxMessageLen] + "..."
	}
	return s
}

// limiter spaces request starts at least 1/rate apart. All requests go
// to one IP, so this is the per-IP rate limit.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rate float64) *limiter {
	return &limiter{interval: time.Duration(float64(time.Second) / rate)}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		return sleep(ctx, d)
	}
	return ctx.Err()
}
