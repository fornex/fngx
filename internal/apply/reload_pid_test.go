// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeProc is a stand-in for /proc with a real "master" process (sleep) so
// that the signal can actually be delivered.
type fakeProc struct {
	dir, pidFile string
	pid          int
}

func newFakeProc(t *testing.T) (*fakeProc, string) {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	cmd := exec.Command(sleep, "60") //nolint:gosec // test helper process
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	p := &fakeProc{dir: t.TempDir(), pid: cmd.Process.Pid}
	p.pidFile = filepath.Join(t.TempDir(), "nginx.pid")
	if err := os.WriteFile(p.pidFile, []byte(strconv.Itoa(p.pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.add(t, p.pid, 1, "sleep")
	p.add(t, 900001, p.pid, "sleep") // an existing worker
	return p, sleep
}

func (p *fakeProc) add(t *testing.T, pid, ppid int, comm string) {
	t.Helper()
	d := filepath.Join(p.dir, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S %d 0 0", pid, comm, ppid)
	if err := os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadWaitsForNewWorkers(t *testing.T) { // A-5, N-5
	p, bin := newFakeProc(t)
	n := &ExecNginx{Binary: bin, PIDFile: p.pidFile, ProcRoot: p.dir, ReloadTimeout: 5 * time.Second}
	worker := filepath.Join(p.dir, "900002")
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = os.MkdirAll(worker, 0o750)
		_ = os.WriteFile(filepath.Join(worker, "stat"), []byte(fmt.Sprintf("900002 (sleep) S %d 0", p.pid)), 0o600)
	}()
	start := time.Now()
	if _, err := n.Reload(context.Background(), "unused"); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("reload returned before a new worker appeared")
	}
}

func TestReloadWithoutNewWorkersFails(t *testing.T) { // A-5
	p, bin := newFakeProc(t)
	n := &ExecNginx{Binary: bin, PIDFile: p.pidFile, ProcRoot: p.dir, ReloadTimeout: 300 * time.Millisecond}
	_, err := n.Reload(context.Background(), "unused")
	if err == nil || errors.Is(err, ErrNotRunning) {
		t.Fatalf("err = %v", err)
	}
}

func TestReloadNotRunning(t *testing.T) {
	p, bin := newFakeProc(t)
	ctx := context.Background()
	for name, n := range map[string]*ExecNginx{
		"no pid file":  {Binary: bin, PIDFile: filepath.Join(t.TempDir(), "none.pid"), ProcRoot: p.dir},
		"other binary": {Binary: "/usr/sbin/nginx", PIDFile: p.pidFile, ProcRoot: p.dir},
		"stale pid":    {Binary: bin, PIDFile: p.pidFile, ProcRoot: t.TempDir()},
	} {
		n.ReloadTimeout = time.Second
		if _, err := n.Reload(ctx, "unused"); !errors.Is(err, ErrNotRunning) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestExecNginxSignalledTestIsNotInvalid(t *testing.T) {
	script := filepath.Join(t.TempDir(), "nginx")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nkill -KILL $$\n"), 0o700); err != nil { //nolint:gosec // test helper must be executable
		t.Fatal(err)
	}
	n := &ExecNginx{Binary: script, TestTimeout: 5 * time.Second}
	_, err := n.Test(context.Background(), "x")
	if err == nil || errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v", err)
	}
}
