// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fornex/fngx/internal/apply"
	"github.com/fornex/fngx/internal/model"
)

// These tests run a real nginx binary, like those of internal/apply. They
// are skipped when no nginx is found unless NGINX_TEST_REQUIRED is set (CI
// sets it). NGINX_TEST_BINARY overrides the binary.
//
// The templates need nginx 1.25.1 or later (the "http2" directive). HTTP/3
// needs nginx built with --with-http_v3_module; without it the cases are
// tested with HTTP/3 turned off and the test says so in its log, unless
// NGINX_TEST_REQUIRE_HTTP3 is set, which makes it a failure.

type nginxInfo struct {
	bin   string
	http3 bool
}

var versionRe = regexp.MustCompile(`nginx version: [^/]+/(\d+)\.(\d+)\.(\d+)`)

func nginxForTest(t *testing.T) nginxInfo {
	t.Helper()
	required := os.Getenv("NGINX_TEST_REQUIRED") != ""
	bin := os.Getenv("NGINX_TEST_BINARY")
	if bin == "" {
		if p, err := exec.LookPath("nginx"); err == nil {
			bin = p
		}
	}
	if bin == "" {
		for _, p := range []string{"/usr/sbin/nginx", "/usr/local/sbin/nginx", "/opt/homebrew/bin/nginx"} {
			if _, err := os.Stat(p); err == nil {
				bin = p
				break
			}
		}
	}
	if bin == "" {
		if required {
			t.Fatal("nginx binary not found and NGINX_TEST_REQUIRED is set")
		}
		t.Skip("nginx binary not found")
	}
	out, err := exec.Command(bin, "-V").CombinedOutput() //nolint:gosec // test binary from the environment
	if err != nil {
		t.Fatalf("%s -V: %v\n%s", bin, err, out)
	}
	m := versionRe.FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("cannot parse nginx version from:\n%s", out)
	}
	v := [3]int{}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	if v[0] < 1 || v[0] == 1 && (v[1] < 25 || v[1] == 25 && v[2] < 1) {
		msg := "nginx " + m[1] + "." + m[2] + "." + m[3] + " is older than 1.25.1, which the templates need"
		if required {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	info := nginxInfo{bin: bin, http3: strings.Contains(string(out), "--with-http_v3_module")}
	if !info.http3 {
		if os.Getenv("NGINX_TEST_REQUIRE_HTTP3") != "" {
			t.Fatal("nginx lacks --with-http_v3_module and NGINX_TEST_REQUIRE_HTTP3 is set")
		}
		t.Log("nginx lacks --with-http_v3_module: HTTP/3 is NOT tested, cases run with HTTP3=false")
	}
	return info
}

// testEnv is an env backed by temporary directories.
type testEnv struct {
	*env
	work  string
	ng    nginxInfo
	eng   *apply.Engine
	exec  *apply.ExecNginx
	certs map[string]bool
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ng := nginxForTest(t)
	work := t.TempDir()
	for _, d := range []string{"home", "certs", "php", "temp", "logs"} {
		if err := os.MkdirAll(filepath.Join(work, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	mime := filepath.Join(work, "mime.types")
	writeFile(t, mime, "types {\n    text/html html;\n    text/plain txt;\n    image/png png;\n    text/css css;\n}\n")
	te := &testEnv{work: work, ng: ng, certs: map[string]bool{}}
	te.env = &env{
		home:       filepath.Join(work, "home"),
		certDir:    filepath.Join(work, "certs"),
		phpDir:     filepath.Join(work, "php"),
		httpPort:   freePort(t),
		httpsPort:  freePort(t),
		apache:     netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(freePort(t))), //nolint:gosec // port from the kernel
		apacheTLS:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(freePort(t))), //nolint:gosec // port from the kernel
		dedicated4: netip.MustParseAddr("127.0.0.2"),
		dedicated6: netip.MustParseAddr("::1"),
	}
	te.server = func() Server {
		s := DefaultServer()
		s.User = ""
		if os.Geteuid() == 0 {
			// As root nginx would start workers as "nobody", which cannot
			// read the test's private temporary directory.
			s.User = "root"
		}
		s.PIDFile = filepath.Join(work, "nginx.pid")
		s.ErrorLog = filepath.Join(work, "logs", "error.log")
		s.AccessLog = filepath.Join(work, "logs", "access.log")
		s.MimeTypes = mime
		s.TempDir = filepath.Join(work, "temp")
		s.HTTP3 = ng.http3
		return s
	}
	te.exec = &apply.ExecNginx{
		Binary:        ng.bin,
		Prefix:        work,
		ExtraArgs:     []string{"-e", filepath.Join(work, "logs", "error.log")},
		PIDFile:       filepath.Join(work, "nginx.pid"),
		TestTimeout:   2 * time.Minute,
		ReloadTimeout: 30 * time.Second,
	}
	eng, err := apply.New(apply.Config{
		Root: filepath.Join(work, "root"), MainFile: mainFile, Keep: 2, MaxTests: 4,
		Nginx: te.exec, Logger: apply.NewLogger(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	te.eng = eng
	return te
}

func writeFile(t testing.TB, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// prepare creates the files a domain refers to: document root and a
// self-signed certificate for its names.
func (te *testEnv) prepare(t testing.TB, d *Domain) {
	t.Helper()
	if err := os.MkdirAll(d.DocRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if d.TLS != nil && !te.certs[d.TLS.Cert] {
		names := []string{string(d.Name)}
		for _, a := range d.Aliases {
			names = append(names, string(a))
		}
		selfSigned(t, d.TLS.Cert, d.TLS.Key, names)
		te.certs[d.TLS.Cert] = true
	}
}

func selfSigned(t testing.TB, certPath, keyPath string, names []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})))
}

// TestIntegrationGoldenCases runs nginx -t, through internal/apply, on the
// complete set generated for every golden case (Q-1, T-9, A-5).
func TestIntegrationGoldenCases(t *testing.T) {
	te := newTestEnv(t)
	r := newRenderer(t)
	ctx := context.Background()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, d := c.build(t, te.env)
			te.prepare(t, &d)
			res, err := r.All(&s, []Domain{d})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Failed) > 0 {
				t.Fatal(res.Failed)
			}
			ch := res.Change
			ch.AllOrNothing = true
			if _, err := te.eng.Check(ctx, ch); err != nil {
				t.Fatalf("nginx -t rejected the set: %v", err)
			}
		})
	}
	for _, c := range mainCases {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(te.env)
			s.Addresses = nil // the golden addresses are not local
			if s.TempDir != "" {
				s.TempDir = te.server().TempDir // nginx -t creates it
			}
			if !te.ng.http3 {
				s.HTTP3 = false
			}
			files, err := r.Common(&s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := te.eng.Check(ctx, apply.Change{Full: true, AllOrNothing: true, Common: files}); err != nil {
				t.Fatalf("nginx -t rejected the set: %v", err)
			}
		})
	}
}

// TestIntegrationManyDomains checks that nginx accepts 10,000 generated
// domains with aliases, which exercises the server name hash sizes (N-1).
func TestIntegrationManyDomains(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	te := newTestEnv(t)
	r := newRenderer(t)
	s := te.baseServer()
	domains := manyDomains(te.env, 10000)
	res, err := r.All(&s, domains)
	if err != nil || len(res.Failed) > 0 {
		t.Fatal(err, res.Failed)
	}
	ch := res.Change
	ch.AllOrNothing = true
	start := time.Now()
	if _, err := te.eng.Check(context.Background(), ch); err != nil {
		t.Fatalf("nginx -t rejected 10,000 domains: %v", err)
	}
	t.Logf("nginx -t on 10,000 domains took %v", time.Since(start))
}

// manyDomains returns n domains in all three modes, without TLS (loading
// thousands of certificates would only measure OpenSSL), with a long alias
// to exercise the hash bucket size.
func manyDomains(e *env, n int) []Domain {
	ms := modes()
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63)
	out := make([]Domain, n)
	for i := range out {
		name := "site" + strconv.Itoa(i) + ".example"
		d := e.domain(name, ms[i%len(ms)])
		d.Aliases = []model.Domain{model.Domain("www." + name), model.Domain(strconv.Itoa(i) + "." + long + ".example")}
		out[i] = d
	}
	return out
}
