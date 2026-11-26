// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run a real nginx binary. They are skipped when none is found,
// unless NGINX_TEST_REQUIRED is set (CI sets it so they cannot silently
// disappear). NGINX_TEST_BINARY overrides the binary.

func nginxForTest(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("NGINX_TEST_BINARY"); p != "" {
		return p
	}
	if p, err := exec.LookPath("nginx"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/nginx", "/usr/local/sbin/nginx", "/usr/local/bin/nginx", "/opt/homebrew/bin/nginx"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if os.Getenv("NGINX_TEST_REQUIRED") != "" {
		t.Fatal("nginx binary not found and NGINX_TEST_REQUIRED is set")
	}
	t.Skip("nginx binary not found")
	return ""
}

type realEnv struct {
	root, work string
	port       int
	nginx      *ExecNginx
	engine     *Engine
}

func newRealEnv(t *testing.T, ng Nginx) *realEnv {
	t.Helper()
	bin := nginxForTest(t)
	work := t.TempDir()
	env := &realEnv{root: filepath.Join(work, "root"), work: work, port: freePort(t)}
	env.nginx = &ExecNginx{
		Binary:        bin,
		Prefix:        work,
		ExtraArgs:     []string{"-e", filepath.Join(work, "error.log")},
		TestTimeout:   30 * time.Second,
		ReloadTimeout: 10 * time.Second,
	}
	if ng == nil {
		ng = env.nginx
	}
	e, err := New(Config{
		Root: env.root, MainFile: "nginx.conf", Keep: 2, MaxTests: 16,
		Nginx: ng, Logger: NewLogger(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.engine = e
	return env
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

// mainConf includes the vhosts with a relative path. Temporary paths are
// set explicitly so that nginx does not need the compiled-in directories,
// which an unprivileged test user cannot write.
func (env *realEnv) mainConf() File {
	w := env.work
	conf := fmt.Sprintf(`pid %[1]s/nginx.pid;
error_log %[1]s/error.log;
worker_processes 1;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path %[1]s/body;
    proxy_temp_path %[1]s/proxy;
    fastcgi_temp_path %[1]s/fastcgi;
    uwsgi_temp_path %[1]s/uwsgi;
    scgi_temp_path %[1]s/scgi;
    include vhosts/*.conf;
}
`, w)
	return File{Path: "nginx.conf", Data: []byte(conf)}
}

func (env *realEnv) vhost(name, body string) Unit {
	conf := fmt.Sprintf("server {\n    listen 127.0.0.1:%d;\n    server_name %s;\n    location / { return 200 %q; }\n}\n", env.port, name, body)
	return Unit{ID: name, Files: []File{{Path: "vhosts/" + name + ".conf", Data: []byte(conf)}}}
}

func (env *realEnv) full(units ...Unit) Change {
	return Change{Full: true, Common: []File{env.mainConf()}, Units: units}
}

func brokenVhost(name string) Unit {
	return Unit{ID: name, Files: []File{{Path: "vhosts/" + name + ".conf", Data: []byte("server {\n    bogus_directive on;\n}\n")}}}
}

func TestIntegrationNginxTest(t *testing.T) { // A-5, T-9, N-4
	env := newRealEnv(t, nil)
	ctx := context.Background()

	if _, err := env.engine.Check(ctx, env.full(env.vhost("a.test", "a"))); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}

	// The error must come from the candidate's own vhost file, which shows
	// that the relative include was resolved inside the candidate.
	_, err := env.engine.Check(ctx, Change{
		Full: true, AllOrNothing: true, Common: []File{env.mainConf()},
		Units: []Unit{env.vhost("a.test", "a"), brokenVhost("b.test")},
	})
	var te *TestError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want *TestError", err)
	}
	if !strings.Contains(te.Output, `unknown directive "bogus_directive"`) || !strings.Contains(te.Output, "vhosts/b.test.conf:2") {
		t.Fatalf("unexpected nginx output: %q", te.Output)
	}
	if strings.Contains(te.Output, env.root) {
		t.Fatalf("output exposes the candidate path: %q", te.Output)
	}

	// Isolation uses the file name nginx prints: one test fails, the retest
	// without the named unit passes.
	res, err := env.engine.Check(ctx, env.full(env.vhost("a.test", "a"), brokenVhost("b.test")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Unit != "b.test" || res.Tests != 2 {
		t.Fatalf("result = %+v", res)
	}
}

// starter starts nginx on the first reload, when no master is running yet,
// and stops it when the test ends.
type starter struct {
	*ExecNginx
	t       *testing.T
	pidFile string
	started bool
}

func (s *starter) Reload(ctx context.Context, conf string) (string, error) {
	if s.started {
		return s.ExecNginx.Reload(ctx, conf)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := ExecRunner{}.Run(ctx, s.Binary, s.args(conf)...)
	if err != nil {
		return string(out), err
	}
	s.started = true
	s.t.Cleanup(func() {
		data, err := os.ReadFile(s.pidFile)
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			_ = syscall.Kill(pid, syscall.SIGQUIT)
		}
	})
	return string(out), nil
}

func TestIntegrationNginxReload(t *testing.T) { // A-5, N-5
	s := &starter{t: t}
	env := newRealEnv(t, s)
	s.ExecNginx = env.nginx
	s.pidFile = filepath.Join(env.work, "nginx.pid")
	ctx := context.Background()

	if _, err := env.engine.Apply(ctx, env.full(env.vhost("a.test", "v1"), env.vhost("b.test", "b"))); err != nil {
		t.Fatal(err)
	}
	waitBody(t, env.port, "a.test", "v1")

	// The running master was started with -c root/live/nginx.conf. After the
	// swap and reload it must serve the new generation.
	if _, err := env.engine.Apply(ctx, Change{Units: []Unit{env.vhost("a.test", "v2")}}); err != nil {
		t.Fatal(err)
	}
	waitBody(t, env.port, "a.test", "v2")

	// A broken unit keeps its live version; the other change is applied.
	res, err := env.engine.Apply(ctx, Change{Units: []Unit{brokenVhost("a.test"), env.vhost("b.test", "b2")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Unit != "a.test" {
		t.Fatalf("rejected = %+v", res.Rejected)
	}
	waitBody(t, env.port, "b.test", "b2")
	waitBody(t, env.port, "a.test", "v2")
}

// waitBody polls until the server returns want. A reload is asynchronous:
// the signal is delivered at once, new workers start later
// (https://nginx.org/en/docs/control.html).
func waitBody(t *testing.T, port int, host, want string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	var last string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			last = err.Error()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		last = string(body)
		if last == want {
			return
		}
	}
	t.Fatalf("%s: got %q, want %q", host, last, want)
}
