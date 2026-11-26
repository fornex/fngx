// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// SnapshotVersion is the version of the snapshot file format.
const SnapshotVersion = 1

// MaxSnapshotSize is the largest snapshot file LoadSnapshot reads. A
// snapshot of 10,000 domains on two schemes is about 30 MB.
const MaxSnapshotSize = 512 << 20

// Snapshot is the record of one run of [Take].
type Snapshot struct {
	Version  int       `json:"version"`
	Tool     string    `json:"tool"`
	Server   string    `json:"server"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Options  Options   `json:"options"`
	Results  []Result  `json:"results"`
}

// Options are the settings a snapshot was taken with.
type Options struct {
	Method      string  `json:"method"`
	HTTPPort    int     `json:"http_port"`
	HTTPSPort   int     `json:"https_port"`
	TimeoutMS   int64   `json:"timeout_ms"`
	MaxBody     int64   `json:"max_body"`
	TLSMode     TLSMode `json:"tls_mode"`
	Repeat      int     `json:"repeat"`
	Retries     int     `json:"retries"`
	Concurrency int     `json:"concurrency"`
	Rate        float64 `json:"rate"`
	// BodyRules is the fingerprint of the body patterns the normalized
	// body hashes were computed with.
	BodyRules string `json:"body_rules"`
}

// Result is the outcome of requesting one target over one scheme.
type Result struct {
	Target string `json:"target"`
	Scheme string `json:"scheme"`
	// Error is set when no complete response was received. Status,
	// Header and TLS may still be set, for example when the body read
	// timed out or the certificate failed verification.
	Error  *FetchError         `json:"error,omitempty"`
	Status int                 `json:"status,omitempty"`
	Proto  string              `json:"proto,omitempty"`
	Header map[string][]string `json:"header,omitempty"`
	// HeaderTruncated is set when the headers exceeded the recorded size
	// limit and some were dropped.
	HeaderTruncated bool      `json:"header_truncated,omitempty"`
	Body            *BodyInfo `json:"body,omitempty"`
	TLS             *TLSInfo  `json:"tls,omitempty"`
	// TimeMS is the time of the last attempt, until the body was read;
	// TTFBMS until the first response byte.
	TimeMS   int64 `json:"time_ms"`
	TTFBMS   int64 `json:"ttfb_ms,omitempty"`
	Attempts int   `json:"attempts"`
}

// FetchError describes a failed request. Kind is one of the Err*
// constants.
type FetchError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Error kinds.
const (
	ErrKindTimeout   = "timeout"
	ErrKindRefused   = "refused"
	ErrKindReset     = "reset"
	ErrKindTLS       = "tls"        // handshake failed
	ErrKindTLSVerify = "tls-verify" // certificate rejected in strict mode
	ErrKindProtocol  = "protocol"   // malformed HTTP response
	ErrKindBody      = "body"       // body could not be read or decoded
	ErrKindCanceled  = "canceled"
	ErrKindOther     = "error"
)

// BodyInfo describes a response body. Length and hashes are of the body
// after Content-Encoding is removed, limited to MaxBody bytes.
type BodyInfo struct {
	Length    int64  `json:"length"`
	Truncated bool   `json:"truncated,omitempty"`
	SHA256    string `json:"sha256"`
	// NormSHA256 is the hash after the body patterns were applied. It
	// equals SHA256 for non-text bodies.
	NormSHA256 string `json:"norm_sha256"`
	// Encoding is the Content-Encoding as received. Undecoded is set when
	// the encoding is not supported and the raw bytes were hashed.
	Encoding  string `json:"encoding,omitempty"`
	Undecoded bool   `json:"undecoded,omitempty"`
	// Stable is set when the snapshot was taken with Repeat >= 2: true
	// when every repeat returned the same status and normalized body.
	Stable *bool `json:"stable,omitempty"`
	// Unstable says how a repeat differed when Stable is false.
	Unstable string `json:"unstable,omitempty"`
	// Title is the normalized HTML <title>, if any.
	Title string `json:"title,omitempty"`
}

// TLSInfo describes the TLS connection and the server certificate.
type TLSInfo struct {
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	ALPN       string    `json:"alpn,omitempty"`
	CertSHA256 string    `json:"cert_sha256,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	// Verified reports whether the chain is valid for the domain against
	// the system roots; VerifyError says why not.
	Verified    bool   `json:"verified"`
	VerifyError string `json:"verify_error,omitempty"`
}

// Key identifies a result within a snapshot.
func (r *Result) Key() string { return r.Scheme + "://" + r.Target }

// LoadSnapshot decodes and validates a snapshot. The data is untrusted:
// unknown fields, trailing data, invalid targets and duplicate results
// are rejected.
func LoadSnapshot(data []byte) (*Snapshot, error) {
	if len(data) > MaxSnapshotSize {
		return nil, fmt.Errorf("%w: snapshot larger than %d bytes", ErrInvalid, MaxSnapshotSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: snapshot: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: snapshot: trailing data", ErrInvalid)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadSnapshotFile reads a snapshot file.
func LoadSnapshotFile(path string) (*Snapshot, error) {
	f, err := os.Open(path) //nolint:gosec // the path is given by the administrator
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxSnapshotSize+1))
	if err != nil {
		return nil, err
	}
	s, err := LoadSnapshot(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func (s *Snapshot) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: snapshot: "+format, append([]any{ErrInvalid}, a...)...)
	}
	if s.Version != SnapshotVersion {
		return bad("unsupported version %d, want %d", s.Version, SnapshotVersion)
	}
	if a, err := netip.ParseAddr(s.Server); err != nil || a.Zone() != "" {
		return bad("server %q", s.Server)
	}
	o := s.Options
	if o.Method != http.MethodGet && o.Method != http.MethodHead {
		return bad("method %q", o.Method)
	}
	if o.TLSMode != TLSStrict && o.TLSMode != TLSRecord {
		return bad("tls_mode %q", o.TLSMode)
	}
	if o.MaxBody < 0 || o.Repeat < 0 || o.Retries < 0 || o.TimeoutMS < 0 {
		return bad("negative option")
	}
	if o.HTTPPort < 1 || o.HTTPPort > 65535 || o.HTTPSPort < 1 || o.HTTPSPort > 65535 {
		return bad("port out of range")
	}
	seen := make(map[string]bool, len(s.Results))
	for i := range s.Results {
		r := &s.Results[i]
		if r.Scheme != "http" && r.Scheme != "https" {
			return bad("result %d: scheme %q", i, r.Scheme)
		}
		t, err := ParseTarget(r.Target)
		if err != nil {
			return bad("result %d: %v", i, err)
		}
		if t.String() != r.Target {
			return bad("result %d: target %q is not in canonical form", i, r.Target)
		}
		if seen[r.Key()] {
			return bad("result %d: duplicate %s", i, r.Key())
		}
		seen[r.Key()] = true
		if r.Status != 0 && (r.Status < 100 || r.Status > 999) {
			return bad("result %d: status %d", i, r.Status)
		}
		if r.Error == nil && r.Status == 0 {
			return bad("result %d: neither status nor error", i)
		}
		if r.Body != nil && (r.Body.Length < 0 || r.Body.SHA256 == "") {
			return bad("result %d: invalid body", i)
		}
	}
	return nil
}

// WriteFile stores the snapshot atomically with mode 0600. Unless
// overwrite is set it fails when path exists, so a baseline is not lost
// by a mistyped command.
//
// If the last step fails, the complete snapshot is kept in a temporary
// file next to path and the error names it: a snapshot of a large server
// takes long to retake.
func (s *Snapshot) WriteFile(path string, overwrite bool) (err error) {
	data, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".respdiff-*.tmp")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if err == nil || !complete {
			_ = os.Remove(tmp.Name())
		} else {
			err = fmt.Errorf("%w; the snapshot is kept in %s", err, tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	complete = true
	if overwrite {
		return os.Rename(tmp.Name(), path)
	}
	// A hard link fails if path exists, unlike rename. Some file systems
	// have no hard links; there, check and rename (not atomic).
	err = os.Link(tmp.Name(), path)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("%s exists; refusing to overwrite", path)
	}
	if _, serr := os.Lstat(path); !errors.Is(serr, os.ErrNotExist) {
		return fmt.Errorf("%s exists or cannot be checked; refusing to overwrite (link: %w)", path, err)
	}
	return os.Rename(tmp.Name(), path)
}
