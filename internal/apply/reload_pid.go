// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// signalReload sends SIGHUP to the master named in PIDFile and waits for a
// new child process. See ExecNginx.Reload.
func (n *ExecNginx) signalReload(ctx context.Context) error {
	proc := n.ProcRoot
	if proc == "" {
		proc = "/proc"
	}
	pid, err := n.masterPID(proc)
	if err != nil {
		return err
	}
	before, err := children(proc, pid)
	if err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("%w: master %d exited", ErrNotRunning, pid)
		}
		return fmt.Errorf("apply: signal nginx master %d: %w", pid, err)
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("apply: nginx master %d started no new worker processes: "+
				"it rejected the configuration or is still reading it (see the nginx error log): %w", pid, ctx.Err())
		case <-tick.C:
		}
		now, err := children(proc, pid)
		if err != nil {
			return err
		}
		for c := range now {
			if !before[c] {
				return nil
			}
		}
		if _, err := os.Stat(filepath.Join(proc, strconv.Itoa(pid))); err != nil {
			return fmt.Errorf("apply: nginx master %d exited during reload", pid)
		}
	}
}

// masterPID reads the PID file and checks that the process exists and is
// nginx, so that a stale PID file never makes us signal an unrelated
// process. A missing PID file or process means nginx is not running.
func (n *ExecNginx) masterPID(proc string) (int, error) {
	data, err := os.ReadFile(n.PIDFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%w: no PID file %s", ErrNotRunning, n.PIDFile)
	}
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		// Seen in the integration tests: "nginx -t" creates the PID file
		// named in the configuration without writing a PID, so an empty
		// file is left behind when no master is running.
		return 0, fmt.Errorf("%w: empty PID file %s", ErrNotRunning, n.PIDFile)
	}
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("apply: PID file %s: invalid content", n.PIDFile)
	}
	comm, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "comm")) //nolint:gosec // numeric entry under the proc root
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%w: stale PID file %s", ErrNotRunning, n.PIDFile)
	}
	if err != nil {
		return 0, err
	}
	// comm is the executable name truncated to 15 bytes (proc(5)).
	want := filepath.Base(n.Binary)
	if len(want) > 15 {
		want = want[:15]
	}
	if got := strings.TrimSpace(string(comm)); got != want {
		return 0, fmt.Errorf("%w: PID %d from %s is %q, not %q", ErrNotRunning, pid, n.PIDFile, got, want)
	}
	return pid, nil
}

// children returns the PIDs whose parent is ppid, from /proc/<pid>/stat.
func children(proc string, ppid int) (map[int]bool, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, fmt.Errorf("apply: list processes: %w", err)
	}
	out := map[int]bool{}
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(proc, ent.Name(), "stat")) //nolint:gosec // numeric entry under the proc root
		if err != nil {
			continue // the process exited meanwhile
		}
		// Format: pid (comm) state ppid ...; comm may contain spaces and
		// parentheses, so parse after the last ')'.
		s := string(data)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		if p, err := strconv.Atoi(f[1]); err == nil && p == ppid {
			out[pid] = true
		}
	}
	return out, nil
}
