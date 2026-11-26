// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ReportVersion is the version of the JSON report format.
const ReportVersion = 1

// Report is the result of [Compare].
type Report struct {
	Version int          `json:"version"`
	Before  SnapshotMeta `json:"before"`
	After   SnapshotMeta `json:"after"`
	// Notes explain conditions that affect how to read the report, such
	// as certificates recorded without verification.
	Notes  []string `json:"notes"`
	Counts Counts   `json:"counts"`
	// Diffs lists every result with at least one difference that is not
	// ignored, most severe first.
	Diffs []Diff `json:"diffs"`
}

// SnapshotMeta summarizes a compared snapshot.
type SnapshotMeta struct {
	Server   string  `json:"server"`
	Tool     string  `json:"tool"`
	Started  string  `json:"started"`
	Results  int     `json:"results"`
	Errors   int     `json:"errors"`
	BadCerts int     `json:"invalid_certificates"`
	MedianMS int64   `json:"median_ms"`
	Options  Options `json:"options"`
}

// Counts are per result (one target over one scheme).
type Counts struct {
	Compared  int `json:"compared"`
	Identical int `json:"identical"`
	Critical  int `json:"critical"`
	Warning   int `json:"warning"`
	Info      int `json:"info"`
	// OnlyBefore and OnlyAfter count results present in one snapshot.
	OnlyBefore int `json:"only_before"`
	OnlyAfter  int `json:"only_after"`
}

// Diff lists the differences of one result.
type Diff struct {
	Target   string   `json:"target"`
	Scheme   string   `json:"scheme"`
	Severity Severity `json:"severity"`
	Changes  []Change `json:"changes"`
}

// URL returns the URL of the result for display.
func (d *Diff) URL() string { return d.Scheme + "://" + d.Target }

// Change is one difference.
type Change struct {
	// Field is "missing", "error", "status", "header:<Name>", "body",
	// or "tls.verified", "tls.cert", "tls.version", "tls.alpn".
	Field    string   `json:"field"`
	Severity Severity `json:"severity"`
	Before   string   `json:"before,omitempty"`
	After    string   `json:"after,omitempty"`
	Note     string   `json:"note,omitempty"`
}

// Significant reports whether any difference is at least as severe as
// threshold.
func (r *Report) Significant(threshold Severity) bool {
	if threshold <= SevIgnore {
		threshold = SevInfo
	}
	for i := range r.Diffs {
		if r.Diffs[i].Severity >= threshold {
			return true
		}
	}
	return false
}

// Compare compares two snapshots under rules (nil means the defaults).
func Compare(before, after *Snapshot, rules *Rules) (*Report, error) {
	c, err := compileRules(rules)
	if err != nil {
		return nil, err
	}
	cmp := comparer{rules: c, before: before, after: after}
	cmp.setup()
	if rules != nil && len(rules.BodyPatterns) > 0 {
		cmp.note("The body patterns of the rules file have no effect here: they apply when a snapshot is taken (pass -rules to snapshot).")
	}
	rep := &Report{
		Version: ReportVersion,
		Before:  meta(before),
		After:   meta(after),
		Notes:   cmp.notes,
		Diffs:   []Diff{},
	}
	am := make(map[string]*Result, len(after.Results))
	for i := range after.Results {
		am[after.Results[i].Key()] = &after.Results[i]
	}
	seen := make(map[string]bool, len(before.Results))
	add := func(d Diff) {
		if len(d.Changes) == 0 {
			rep.Counts.Identical++
			return
		}
		for _, ch := range d.Changes {
			d.Severity = max(d.Severity, ch.Severity)
		}
		switch d.Severity {
		case SevCritical:
			rep.Counts.Critical++
		case SevWarning:
			rep.Counts.Warning++
		default:
			rep.Counts.Info++
		}
		rep.Diffs = append(rep.Diffs, d)
	}
	for i := range before.Results {
		b := &before.Results[i]
		seen[b.Key()] = true
		d := Diff{Target: b.Target, Scheme: b.Scheme}
		a, ok := am[b.Key()]
		if !ok {
			rep.Counts.OnlyBefore++
			d.Changes = []Change{{Field: "missing", Severity: SevCritical, Before: "present", After: "absent",
				Note: "not checked after; cannot confirm it answers the same"}}
			add(d)
			continue
		}
		rep.Counts.Compared++
		d.Changes = cmp.result(b, a)
		add(d)
	}
	for i := range after.Results {
		a := &after.Results[i]
		if seen[a.Key()] {
			continue
		}
		rep.Counts.OnlyAfter++
		add(Diff{Target: a.Target, Scheme: a.Scheme, Changes: []Change{{
			Field: "missing", Severity: SevInfo, Before: "absent", After: "present",
			Note: "not in the baseline"}}})
	}
	sort.SliceStable(rep.Diffs, func(i, j int) bool {
		x, y := &rep.Diffs[i], &rep.Diffs[j]
		if x.Severity != y.Severity {
			return x.Severity > y.Severity
		}
		if x.Target != y.Target {
			return x.Target < y.Target
		}
		return x.Scheme < y.Scheme
	})
	return rep, nil
}

func meta(s *Snapshot) SnapshotMeta {
	m := SnapshotMeta{
		Server:  s.Server,
		Tool:    s.Tool,
		Started: s.Started.UTC().Format("2006-01-02 15:04:05Z"),
		Results: len(s.Results),
		Options: s.Options,
	}
	times := make([]int64, 0, len(s.Results))
	for i := range s.Results {
		r := &s.Results[i]
		if r.Error != nil {
			m.Errors++
		} else {
			times = append(times, r.TimeMS)
		}
		if r.TLS != nil && !r.TLS.Verified {
			m.BadCerts++
		}
	}
	if len(times) > 0 {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		m.MedianMS = times[len(times)/2]
	}
	return m
}

type comparer struct {
	rules         *compiledRules
	before, after *Snapshot
	notes         []string
	rawBody       bool // compare raw hashes: body rules differ
	noBody        bool // a snapshot was taken with HEAD
}

func (c *comparer) setup() {
	bo, ao := c.before.Options, c.after.Options
	if c.before.Server != c.after.Server {
		c.note("The snapshots were taken from different servers (%s and %s).", c.before.Server, c.after.Server)
	}
	if bo.Method != ao.Method || bo.Method == "HEAD" {
		c.noBody = true
		c.note("Bodies are not compared: method %s before, %s after.", bo.Method, ao.Method)
	}
	if bo.BodyRules != ao.BodyRules {
		c.rawBody = true
		c.note("The snapshots were taken with different body rules; raw body hashes are compared, so CSRF tokens and nonces may show up as differences.")
	}
	if bo.MaxBody != ao.MaxBody {
		c.note("Body size limits differ (%d and %d bytes); truncated bodies may differ for that reason only.", bo.MaxBody, ao.MaxBody)
	}
	if bo.HTTPPort != ao.HTTPPort || bo.HTTPSPort != ao.HTTPSPort {
		c.note("Ports differ: %d/%d before, %d/%d after.", bo.HTTPPort, bo.HTTPSPort, ao.HTTPPort, ao.HTTPSPort)
	}
	for _, s := range []struct {
		name string
		snap *Snapshot
	}{{"before", c.before}, {"after", c.after}} {
		m := meta(s.snap)
		if s.snap.Options.TLSMode == TLSRecord {
			c.note("TLS certificates were recorded without being required to be valid in the %s snapshot (mode %q): %d responses had a certificate that failed verification and were still compared. A certificate that becomes invalid is reported as critical.",
				s.name, TLSRecord, m.BadCerts)
		} else if m.BadCerts > 0 {
			c.note("%d HTTPS requests in the %s snapshot failed certificate verification (mode %q) and have no response to compare.",
				m.BadCerts, s.name, TLSStrict)
		}
	}
	if !c.noBody && c.before.Options.Repeat < 2 {
		c.note("The baseline was taken with repeat 1, so it is unknown which bodies are dynamic: a body change is critical only if the page title or the size changed sharply, otherwise a warning. Take the baseline with -repeat 2 to classify them.")
	}
}

func (c *comparer) note(format string, a ...any) {
	c.notes = append(c.notes, fmt.Sprintf(format, a...))
}

func (c *comparer) result(b, a *Result) []Change {
	var ch []Change
	if b.Error != nil || a.Error != nil {
		if e := compareErrors(b, a); e != nil {
			ch = append(ch, *e)
		} else if b.Status != a.Status {
			// Same failure (a body timeout, say) after different answers.
			ch = append(ch, Change{Field: "status", Severity: SevCritical,
				Before: fmt.Sprint(b.Status), After: fmt.Sprint(a.Status)})
		}
		if b.TLS != nil && a.TLS != nil {
			ch = append(ch, c.tls(b.TLS, a.TLS)...)
		}
		return ch
	}
	if b.Status != a.Status {
		ch = append(ch, Change{Field: "status", Severity: SevCritical,
			Before: fmt.Sprint(b.Status), After: fmt.Sprint(a.Status)})
	}
	ch = append(ch, c.headers(b, a)...)
	if !c.noBody && b.Body != nil && a.Body != nil {
		ch = append(ch, c.body(b.Body, a.Body, b.Status, a.Status)...)
	}
	if b.TLS != nil && a.TLS != nil {
		ch = append(ch, c.tls(b.TLS, a.TLS)...)
	}
	return ch
}

func errText(r *Result) string {
	if r.Error == nil {
		return fmt.Sprintf("status %d", r.Status)
	}
	return r.Error.Kind + ": " + r.Error.Message
}

func compareErrors(b, a *Result) *Change {
	ch := &Change{Field: "error", Before: errText(b), After: errText(a)}
	switch {
	case b.Error == nil:
		ch.Severity = SevCritical
		ch.Note = "answered before, fails after"
	case a.Error == nil:
		ch.Severity = SevWarning
		ch.Note = "failed before, answers after"
	case b.Error.Kind == ErrKindTLSVerify && a.Error.Kind != ErrKindTLSVerify:
		ch.Severity = SevCritical
		ch.Note = "the TLS handshake reached the certificate before, fails otherwise after"
	case b.Error.Kind != a.Error.Kind:
		ch.Severity = SevWarning
		ch.Note = "fails differently"
	default:
		return nil
	}
	return ch
}

// headerNorm returns the comparable value of header k with values vs.
func (c *comparer) headerNorm(k string, vs []string, r *Result, port int) string {
	var v string
	switch k {
	case "Location", "Content-Location":
		v = normLocation(strings.Join(vs, ", "), r, port)
	case "Content-Type":
		v = normContentType(strings.Join(vs, ", "))
	case "Set-Cookie":
		s := append([]string(nil), vs...)
		sort.Strings(s)
		v = strings.Join(s, " | ")
	case "Cache-Control", "Pragma", "Vary", "Content-Encoding", "Allow", "Content-Language",
		"Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Expose-Headers":
		v = normList(vs)
	default:
		parts := make([]string, len(vs))
		for i, s := range vs {
			parts[i] = strings.Join(strings.Fields(s), " ")
		}
		v = strings.Join(parts, ", ")
	}
	return c.rules.normalizeHeader(k, v)
}

// canonHeader returns h with canonical keys; snapshots are untrusted
// input and may carry any spelling.
func canonHeader(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		out[ck] = append(out[ck], vs...)
	}
	return out
}

func (c *comparer) headers(b, a *Result) []Change {
	bh, ah := canonHeader(b.Header), canonHeader(a.Header)
	keys := make(map[string]bool)
	for k := range bh {
		keys[k] = true
	}
	for k := range ah {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	bport, aport := c.before.Options.HTTPPort, c.after.Options.HTTPPort
	if b.Scheme == "https" {
		bport, aport = c.before.Options.HTTPSPort, c.after.Options.HTTPSPort
	}
	var out []Change
	for _, k := range sorted {
		changed, removed := c.rules.headerSeverity(k)
		if changed == SevIgnore && removed == SevIgnore {
			continue
		}
		bvs, inB := bh[k]
		avs, inA := ah[k]
		var bv, av string
		if inB {
			bv = c.headerNorm(k, bvs, b, bport)
		}
		if inA {
			av = c.headerNorm(k, avs, a, aport)
		}
		if inB == inA && bv == av {
			continue
		}
		ch := Change{Field: "header:" + k, Before: bv, After: av, Severity: changed}
		switch {
		case !inA:
			ch.Severity = removed
			ch.Note = "removed"
		case !inB:
			ch.Note = "added"
		case k == "Content-Type" && mediaType(bv) == mediaType(av):
			ch.Severity = min(changed, SevWarning)
			ch.Note = "parameters only"
		}
		if ch.Severity != SevIgnore {
			out = append(out, ch)
		}
	}
	return out
}

func normList(vs []string) string {
	var items []string
	seen := map[string]bool{}
	for _, v := range vs {
		for _, it := range strings.Split(v, ",") {
			it = strings.ToLower(strings.Join(strings.Fields(it), ""))
			if it != "" && !seen[it] {
				seen[it] = true
				items = append(items, it)
			}
		}
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func normContentType(v string) string {
	mt, params, err := mime.ParseMediaType(v)
	if err != nil {
		return strings.ToLower(strings.Join(strings.Fields(v), ""))
	}
	if jsAliases[mt] {
		mt = "text/javascript" // RFC 9239
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(mt)
	for _, k := range keys {
		val := params[k]
		if k == "charset" {
			val = strings.ToLower(val)
		}
		fmt.Fprintf(&sb, "; %s=%s", k, val)
	}
	return sb.String()
}

func mediaType(v string) string {
	mt, _, _ := strings.Cut(v, ";")
	return mt
}

// normLocation resolves a redirect target against the request URL and
// drops default ports, so "/a" and "http://example.com/a" are equal.
func normLocation(v string, r *Result, port int) string {
	t, err := ParseTarget(r.Target)
	if err != nil {
		return v
	}
	base, err := url.Parse(t.URL(r.Scheme, port))
	if err != nil {
		return v
	}
	ref, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return v
	}
	u := base.ResolveReference(ref)
	u.Scheme = strings.ToLower(u.Scheme)
	host, p := strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), u.Port()
	if (u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443") || p == "" {
		u.Host = host
	} else {
		u.Host = host + ":" + p
	}
	// Percent-encodings are case-insensitive (RFC 3986 section 6.2.2.1).
	return pctRx.ReplaceAllStringFunc(u.String(), strings.ToUpper)
}

var pctRx = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

// jsAliases are media types servers use for JavaScript; mime.types of
// Apache and of nginx versions disagree on which one to send.
var jsAliases = map[string]bool{
	"application/javascript": true, "application/x-javascript": true,
	"application/ecmascript": true, "text/ecmascript": true,
}

func bodyText(b *BodyInfo, raw bool) string {
	h := b.NormSHA256
	if raw {
		h = b.SHA256
	}
	if len(h) > 12 {
		h = h[:12]
	}
	s := fmt.Sprintf("%d bytes, sha256 %s", b.Length, h)
	if b.Truncated {
		s += ", truncated"
	}
	return s
}

// body compares two bodies. The baseline decides how much a change
// matters: proved stable, critical; proved dynamic, info; unknown,
// warning. Two signals do not depend on that and make a change critical:
// a different page title and a sharp change in size, which is what a
// wrong virtual host, a default page or a blank PHP error look like.
func (c *comparer) body(b, a *BodyInfo, bstatus, astatus int) []Change {
	var out []Change
	bStable, aStable := b.Stable != nil && *b.Stable, a.Stable != nil && *a.Stable
	if bStable && a.Stable != nil && !aStable {
		out = append(out, Change{Field: "body.stability", Severity: SevCritical,
			Before: "stable", After: "varies: " + a.Unstable,
			Note: "identical requests get different answers after; the first one is compared below"})
	}
	same := b.NormSHA256 == a.NormSHA256
	if c.rawBody {
		same = b.SHA256 == a.SHA256
	}
	if same {
		return out
	}
	ch := Change{Field: "body", Before: bodyText(b, c.rawBody), After: bodyText(a, c.rawBody)}
	switch {
	case b.Stable != nil && !bStable:
		ch.Severity = SevInfo
		ch.Note = "the body changes between identical requests in the baseline (" + b.Unstable + ")"
	case bStable:
		ch.Severity = SevCritical
		ch.Note = "the body was stable across repeated requests in the baseline"
	default:
		ch.Severity = SevWarning
		ch.Note = "unknown whether the page is dynamic; take the baseline with -repeat 2"
	}
	if ch.Severity < SevCritical && bstatus == astatus && bstatus < 300 {
		switch {
		case b.Title != a.Title:
			ch.Severity = SevCritical
			ch.Note = "the page title changed"
			ch.Before += ", title " + strconv.Quote(b.Title)
			ch.After += ", title " + strconv.Quote(a.Title)
		case sharpSizeChange(b, a):
			ch.Severity = SevCritical
			ch.Note = "the size changed more than twofold"
		}
	}
	// Redirect and error pages are generated by the web server, and
	// Apache and nginx word them differently; the status and Location
	// carry the meaning.
	switch {
	case bstatus == astatus && bstatus >= 300 && bstatus < 400:
		ch.Severity = min(ch.Severity, SevInfo)
		ch.Note += "; redirect body"
	case bstatus == astatus && bstatus >= 400:
		ch.Severity = min(ch.Severity, SevWarning)
		ch.Note += "; error page body"
	}
	if b.Undecoded || a.Undecoded {
		ch.Note += "; an encoded body was hashed without decoding"
	}
	return append(out, ch)
}

// sharpSizeChange reports a change of more than a factor of two, or to
// or from empty, ignoring small bodies where that is common.
func sharpSizeChange(b, a *BodyInfo) bool {
	const small = 512
	if b.Truncated && a.Truncated {
		return false
	}
	lo, hi := min(b.Length, a.Length), max(b.Length, a.Length)
	if hi < small {
		return b.Length > 0 && a.Length == 0
	}
	return lo*2 < hi
}

func certText(t *TLSInfo) string {
	fp := t.CertSHA256
	if len(fp) > 16 {
		fp = fp[:16]
	}
	s := fmt.Sprintf("%s, issuer %s, expires %s, sha256 %s", t.Subject, t.Issuer, t.NotAfter.Format("2006-01-02"), fp)
	if !t.Verified {
		s += ", INVALID: " + t.VerifyError
	}
	return s
}

func (c *comparer) tls(b, a *TLSInfo) []Change {
	var out []Change
	switch {
	case b.Verified && !a.Verified:
		out = append(out, Change{Field: "tls.verified", Severity: SevCritical,
			Before: "valid", After: "invalid: " + a.VerifyError})
	case !b.Verified && a.Verified:
		out = append(out, Change{Field: "tls.verified", Severity: SevWarning,
			Before: "invalid: " + b.VerifyError, After: "valid"})
	}
	if b.CertSHA256 != a.CertSHA256 {
		sev := SevInfo
		note := "another valid certificate"
		if !b.Verified || !a.Verified {
			sev = SevWarning
			note = "certificate changed"
		}
		out = append(out, Change{Field: "tls.cert", Severity: sev, Before: certText(b), After: certText(a), Note: note})
	}
	if b.Version != a.Version {
		out = append(out, Change{Field: "tls.version", Severity: SevInfo, Before: b.Version, After: a.Version})
	}
	if b.ALPN != a.ALPN {
		out = append(out, Change{Field: "tls.alpn", Severity: SevInfo, Before: b.ALPN, After: a.ALPN})
	}
	return out
}
