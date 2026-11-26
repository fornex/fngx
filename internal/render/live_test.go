// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fornex/fngx/internal/model"
)

// TestIntegrationLive starts a real nginx with a generated set and sends it
// requests: proxy and hybrid domains in front of a fake Apache, an nginx
// mode domain in front of a fake PHP-FPM (net/http/fcgi), a dedicated
// address, admin and client includes, and the default servers (M-6, M-7,
// M-9, T-6, T-7, Q-6). HTTP/3 is configured but not exercised: the Go
// standard library has no HTTP/3 client.
func TestIntegrationLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		// 127.0.0.2 is a local address only on Linux.
		t.Skip("needs Linux")
	}
	te := newTestEnv(t)
	r := newRenderer(t)

	// Fake Apache: plain and TLS.
	apacheHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sni := ""
		if req.TLS != nil {
			sni = req.TLS.ServerName
		}
		_, _ = fmt.Fprintf(w, "apache host=%s real=%s xff=%s proto=%s sni=%s uri=%s", //nolint:gosec // plain-text test echo
			req.Host, req.Header.Get("X-Real-IP"), req.Header.Get("X-Forwarded-For"),
			req.Header.Get("X-Forwarded-Proto"), sni, req.RequestURI)
	})
	serve(t, "tcp", te.apache.String(), nil, apacheHandler)
	selfSigned(t, filepath.Join(te.work, "apache.crt"), filepath.Join(te.work, "apache.key"), []string{"localhost"})
	cert, err := tls.LoadX509KeyPair(filepath.Join(te.work, "apache.crt"), filepath.Join(te.work, "apache.key"))
	if err != nil {
		t.Fatal(err)
	}
	serve(t, "tcp", te.apacheTLS.String(), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, apacheHandler)

	s := te.baseServer()
	s.Apache.HTTPS = te.apacheTLS
	s.StaticExtensions = []string{"png", "txt"}
	s.Dedicated = []netip.Addr{te.dedicated4}

	proxy := te.domain("proxy.example", model.ModeProxy)
	proxy.Aliases = []model.Domain{"www.proxy.example"}
	proxy.TLS = te.tls("proxy.example")

	hybrid := te.domain("hybrid.example", model.ModeHybrid)
	hybrid.TLS = te.tls("hybrid.example")

	php := te.domain("php.example", model.ModeNginx)
	php.TLS = te.tls("php.example")
	php.Admin = adminRules
	php.Client = clientRules(t)

	dedicated := te.domain("dedicated.example", model.ModeNginx)
	dedicated.IPs = []netip.Addr{te.dedicated4}

	domains := []Domain{proxy, hybrid, php, dedicated}
	for i := range domains {
		te.prepare(t, &domains[i])
	}
	writeFile(t, filepath.Join(hybrid.DocRoot, "img.png"), "PNGDATA")
	writeFile(t, filepath.Join(php.DocRoot, "index.php"), "<?php // never read by nginx")
	writeFile(t, filepath.Join(php.DocRoot, "page.html"), "static page")
	writeFile(t, filepath.Join(php.DocRoot, ".git", "config"), "secret")
	writeFile(t, filepath.Join(php.DocRoot, ".htaccess"), "secret")
	writeFile(t, filepath.Join(php.DocRoot, ".well-known", "acme-challenge", "tok"), "challenge")
	writeFile(t, filepath.Join(dedicated.DocRoot, "index.html"), "dedicated site")

	// Fake PHP-FPM.
	fcgiHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// net/http/fcgi turns HTTPS=on into req.TLS.
		_, _ = fmt.Fprintf(w, "php script=%s https=%t host=%s", fcgi.ProcessEnv(req)["SCRIPT_FILENAME"], req.TLS != nil, req.Host) //nolint:gosec // plain-text test echo
	})
	sock := php.PHPSocket
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = fcgi.Serve(ln, fcgiHandler) }()

	res, err := r.All(&s, domains)
	if err != nil || len(res.Failed) > 0 {
		t.Fatal(err, res.Failed)
	}
	if _, err := te.eng.Apply(context.Background(), res.Change); err != nil {
		t.Fatalf("apply: %v", err)
	}
	startNginx(t, te)

	h := httpClient("127.0.0.1")
	hs := httpClient("127.0.0.1")
	httpURL := func(host, p string) string { return fmt.Sprintf("http://%s:%d%s", host, te.httpPort, p) }
	httpsURL := func(host, p string) string { return fmt.Sprintf("https://%s:%d%s", host, te.httpsPort, p) }

	// proxy mode (M-6): everything goes to Apache with the visitor's
	// address, the requested host and the scheme.
	expect(t, h, httpURL("proxy.example", "/a?b=1"), 200,
		"apache host=proxy.example real=127.0.0.1 xff=127.0.0.1 proto=http sni= uri=/a?b=1")
	expect(t, hs, httpsURL("www.proxy.example", "/x"), 200,
		"apache host=www.proxy.example real=127.0.0.1 xff=127.0.0.1 proto=https sni=www.proxy.example uri=/x")
	if resp := get(t, hs, httpsURL("proxy.example", "/")); resp.proto != 2 {
		t.Errorf("HTTPS answered with HTTP/%d, want HTTP/2 (M-1)", resp.proto)
	}

	// hybrid mode (M-7): listed extensions from disk, the rest and missing
	// files from Apache.
	expect(t, h, httpURL("hybrid.example", "/img.png"), 200, "PNGDATA")
	expect(t, hs, httpsURL("hybrid.example", "/img.png"), 200, "PNGDATA")
	expect(t, h, httpURL("hybrid.example", "/missing.png"), 200, "apache host=hybrid.example real=127.0.0.1 xff=127.0.0.1 proto=http sni= uri=/missing.png")
	expect(t, h, httpURL("hybrid.example", "/index.php"), 200, "apache host=hybrid.example real=127.0.0.1 xff=127.0.0.1 proto=http sni= uri=/index.php")

	// nginx mode (M-9).
	script := "php script=" + filepath.Join(php.DocRoot, "index.php")
	expect(t, h, httpURL("php.example", "/index.php"), 200, fmt.Sprintf("%s https=false host=php.example:%d", script, te.httpPort))
	expect(t, hs, httpsURL("php.example", "/"), 200, fmt.Sprintf("%s https=true host=php.example:%d", script, te.httpsPort))
	expect(t, h, httpURL("php.example", "/missing.php"), 404, "")
	expect(t, h, httpURL("php.example", "/page.html"), 200, "static page")
	expect(t, h, httpURL("php.example", "/.git/config"), 403, "")
	expect(t, h, httpURL("php.example", "/.htaccess"), 403, "")
	expect(t, h, httpURL("php.example", "/.well-known/acme-challenge/tok"), 200, "challenge")

	// Admin includes per scheme (T-6) and client rules (T-7).
	expect(t, h, httpURL("php.example", "/admin-http"), 200, "admin http\n")
	expect(t, h, httpURL("php.example", "/admin-https"), 404, "")
	expect(t, hs, httpsURL("php.example", "/admin-https"), 200, "admin https\n")
	expect(t, h, httpURL("php.example", "/teapot"), 418, "")
	expect(t, hs, httpsURL("php.example", "/teapot"), 418, "")
	if resp := get(t, h, httpURL("php.example", "/old/x")); resp.status != 301 || !strings.HasSuffix(resp.location, "/new/x") {
		t.Errorf("client rewrite: got %d %q", resp.status, resp.location)
	}
	if resp := get(t, h, httpURL("php.example", "/admin-old")); resp.status != 301 || !strings.HasSuffix(resp.location, "/admin-new") {
		t.Errorf("admin rewrite: got %d %q", resp.status, resp.location)
	}

	// Dedicated address: the domain answers there; on the shared address
	// its name is unknown and reaches the default server, which passes
	// the request to Apache.
	expect(t, httpClient("127.0.0.2"), httpURL("dedicated.example", "/"), 200, "dedicated site")
	expect(t, h, httpURL("dedicated.example", "/"), 200, "apache host=dedicated.example real=127.0.0.1 xff=127.0.0.1 proto=http sni= uri=/")

	// Unknown names over HTTPS are rejected during the handshake.
	if resp, err := hs.Get(httpsURL("unknown.example", "/")); err == nil {
		_ = resp.Body.Close()
		t.Error("handshake for an unknown name succeeded")
	}

	// Symbolic links to files of another owner are not followed (Q-6).
	if os.Geteuid() == 0 {
		other := filepath.Join(te.work, "other", "secret.txt")
		writeFile(t, other, "other user's file")
		if err := os.Chown(other, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{hybrid.DocRoot, php.DocRoot} {
			if err := os.Symlink(other, filepath.Join(root, "link.txt")); err != nil {
				t.Fatal(err)
			}
		}
		// nginx does not open the link, so try_files moves on: to =404 in
		// nginx mode, and to Apache in hybrid mode, whose own rules then
		// apply.
		expect(t, h, httpURL("php.example", "/link.txt"), 404, "")
		expect(t, h, httpURL("hybrid.example", "/link.txt"), 200, "apache host=hybrid.example real=127.0.0.1 xff=127.0.0.1 proto=http sni= uri=/link.txt")
	} else {
		t.Log("not root: symbolic link ownership check skipped")
	}
}

func serve(t *testing.T, network, addr string, cfg *tls.Config, h http.Handler) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func startNginx(t *testing.T, te *testEnv) {
	t.Helper()
	conf := te.eng.LiveConf()
	cmd := exec.Command(te.ng.bin, "-p", te.work, "-c", conf, //nolint:gosec // test binary
		"-e", filepath.Join(te.work, "logs", "error.log"), "-g", "daemon off;")
	out := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		if t.Failed() {
			log, _ := os.ReadFile(filepath.Join(te.work, "logs", "error.log"))
			t.Logf("nginx output:\n%s\nerror log:\n%s", out, log)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", te.httpPort))
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nginx did not start: %v\n%s", err, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// httpClient connects every request to addr, whatever the URL host, and
// does not follow redirects.
func httpClient(addr string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(a)
			return dialer.DialContext(ctx, network, net.JoinHostPort(addr, port))
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificates
		ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type response struct {
	status   int
	proto    int
	body     string
	location string
}

func get(t *testing.T, c *http.Client, url string) response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("GET %s: %v", url, err)
	}
	return response{resp.StatusCode, resp.ProtoMajor, string(body), resp.Header.Get("Location")}
}

// expect checks the status and, when want is not empty, the exact body.
func expect(t *testing.T, c *http.Client, url string, status int, want string) {
	t.Helper()
	r := get(t, c, url)
	if r.status != status || want != "" && r.body != want {
		t.Errorf("GET %s: got %d %q, want %d %q", url, r.status, r.body, status, want)
	}
}
