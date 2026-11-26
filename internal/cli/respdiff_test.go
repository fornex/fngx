// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fornex/fngx/internal/respdiff"
)

func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRespdiffUsage(t *testing.T) {
	for _, tt := range []struct {
		args     []string
		wantCode int
		wantErr  string
	}{
		{[]string{"respdiff"}, ExitUsage, "Usage:"},
		{[]string{"respdiff", "bogus"}, ExitUsage, "unknown subcommand"},
		{[]string{"respdiff", "snapshot"}, ExitUsage, "required"},
		{[]string{"respdiff", "snapshot", "-server", "example.com", "-targets", "x", "-out", "y"}, ExitUsage, "-server"},
		{[]string{"respdiff", "snapshot", "-server", "127.0.0.1", "-targets", "x", "-out", "y", "-rate", "0"}, ExitUsage, "must be positive"},
		{[]string{"respdiff", "compare", "one"}, ExitUsage, "exactly two"},
		{[]string{"respdiff", "compare", "-fail-on", "ignore", "a", "b"}, ExitUsage, "-fail-on"},
		{[]string{"respdiff", "compare", "-nope"}, ExitUsage, "flag provided but not defined"},
		{[]string{"respdiff", "rules", "x"}, ExitUsage, "unexpected"},
	} {
		code, _, errOut := run(tt.args...)
		if code != tt.wantCode || !strings.Contains(errOut, tt.wantErr) {
			t.Errorf("%q: code %d stderr %q; want %d and %q", tt.args, code, errOut, tt.wantCode, tt.wantErr)
		}
	}
	code, out, _ := run("respdiff", "rules")
	if code != ExitOK || !strings.Contains(out, "body_patterns") {
		t.Errorf("rules: %d %q", code, out)
	}
	if _, err := respdiff.ParseRules([]byte(out)); err != nil {
		t.Errorf("printed rules do not parse: %v", err)
	}
}

// TestRespdiffEndToEnd_I11 takes two snapshots through the CLI and
// compares them; the exit code tells whether they differ.
func TestRespdiffEndToEnd_I11(t *testing.T) {
	var status atomic.Int64
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte("# test\nexample.com\nwww.example.com/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := func(name string) {
		t.Helper()
		code, _, errOut := run("respdiff", "snapshot", "-server", "127.0.0.1", "-targets", list,
			"-out", filepath.Join(dir, name), "-schemes", "http", "-http-port", port, "-rate", "500", "-repeat", "2")
		if code != ExitOK {
			t.Fatalf("snapshot %s: %d %s", name, code, errOut)
		}
		if !strings.Contains(errOut, "Wrote") {
			t.Errorf("no summary: %s", errOut)
		}
	}
	snap("a.json")
	snap("b.json")
	status.Store(503)
	snap("c.json")

	code, _, errOut := run("respdiff", "snapshot", "-server", "127.0.0.1", "-targets", list, "-out", filepath.Join(dir, "a.json"))
	if code != ExitError || !strings.Contains(errOut, "exists") {
		t.Errorf("overwrite without -force: %d %q", code, errOut)
	}

	code, out, _ := run("respdiff", "compare", filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"))
	if code != ExitOK || !strings.Contains(out, "Result: SAME") || !strings.Contains(out, "2 identical") {
		t.Errorf("same: %d\n%s", code, out)
	}
	jsonPath := filepath.Join(dir, "report.json")
	code, out, _ = run("respdiff", "compare", "-json", jsonPath, filepath.Join(dir, "a.json"), filepath.Join(dir, "c.json"))
	if code != ExitDiff || !strings.Contains(out, "Result: DIFFERENT") || !strings.Contains(out, "status: 200 -> 503") {
		t.Errorf("different: %d\n%s", code, out)
	}
	data, err := os.ReadFile(jsonPath) //nolint:gosec // test file in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	var rep respdiff.Report
	if err := json.Unmarshal(data, &rep); err != nil || rep.Counts.Critical != 2 {
		t.Errorf("JSON report: %v %+v", err, rep.Counts)
	}
	code, out, _ = run("respdiff", "compare", "-json", "-", filepath.Join(dir, "a.json"), filepath.Join(dir, "c.json"))
	if code != ExitDiff || !json.Valid([]byte(out)) {
		t.Errorf("JSON to stdout: %d %q", code, out)
	}
	code, _, errOut = run("respdiff", "compare", list, filepath.Join(dir, "a.json"))
	if code != ExitError || !strings.Contains(errOut, "invalid") {
		t.Errorf("not a snapshot: %d %q", code, errOut)
	}
}
