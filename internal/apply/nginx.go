// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// ErrConfigInvalid is wrapped by Nginx.Test when nginx ran and rejected the
// configuration. Any other error from Test means the test itself could not
// be carried out (missing binary, timeout) and says nothing about the
// configuration.
var ErrConfigInvalid = errors.New("nginx rejected the configuration")

// ErrNotRunning is wrapped by Nginx.Reload when no nginx master process is
// running. The new set is then live on disk and nginx uses it when it
// starts; the engine treats this as success.
var ErrNotRunning = errors.New("nginx is not running")

// Nginx is the part of nginx the engine needs. Tests substitute a fake.
type Nginx interface {
	// Test checks the configuration whose main file is conf and returns the
	// combined output of the check.
	Test(ctx context.Context, conf string) (output string, err error)
	// Reload asks the running nginx to re-read the configuration whose main
	// file is conf. It should return only once nginx has finished reading
	// it, so that the engine does not swap the live set while nginx is still
	// reading files through it.
	Reload(ctx context.Context, conf string) (output string, err error)
}

// Runner runs an external program with an argument list, never through a
// shell (N-6), and returns its combined output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct {
	// Env replaces the environment of the child; nil means a minimal
	// environment with only PATH set. nginx does not need anything else.
	Env []string
}

// Run implements Runner. The caller's context must carry the deadline.
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // argument list, no shell (N-6); the binary comes from configuration
	cmd.Env = r.Env
	if cmd.Env == nil {
		cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// If a killed child leaves grandchildren holding the pipes, stop waiting
	// for them instead of hanging past the deadline.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil && err != nil {
		err = fmt.Errorf("%w (%w)", ctxErr, err)
	}
	return out.Bytes(), err
}

// Default timeouts. Reading 10,000 server blocks has not been measured yet;
// both values are generous assumptions. A reload costs about as much as a
// test because the master parses the whole configuration again.
const (
	DefaultTestTimeout   = 5 * time.Minute
	DefaultReloadTimeout = 5 * time.Minute
)

// ExecNginx drives a real nginx binary.
type ExecNginx struct {
	Binary string // path to the nginx binary
	// Prefix, when set, is passed with -p to every invocation so that test
	// and reload resolve relative paths the same way.
	Prefix string
	// ExtraArgs are appended to every invocation before the action, for
	// example []string{"-e", "/var/log/nginx/error.log"} (nginx 1.19.5+).
	ExtraArgs []string
	// PIDFile is the master's PID file, as set by the "pid" directive of the
	// generated configuration. When set, Reload signals the master directly
	// and waits until it has started new worker processes; see Reload.
	PIDFile string
	// ProcRoot is where the proc file system is mounted; "" means "/proc".
	ProcRoot      string
	TestTimeout   time.Duration
	ReloadTimeout time.Duration
	Runner        Runner // nil means ExecRunner{}
}

func (n *ExecNginx) args(conf string, action ...string) []string {
	var a []string
	if n.Prefix != "" {
		a = append(a, "-p", n.Prefix)
	}
	a = append(a, "-c", conf)
	a = append(a, n.ExtraArgs...)
	return append(a, action...)
}

func (n *ExecNginx) run(ctx context.Context, timeout time.Duration, args []string) (string, error) {
	if timeout <= 0 {
		return "", errors.New("apply: nginx timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r := n.Runner
	if r == nil {
		r = ExecRunner{}
	}
	out, err := r.Run(ctx, n.Binary, args...)
	return string(out), err
}

// Test runs "nginx -t -c conf". According to
// https://nginx.org/en/docs/switches.html, -t checks the syntax and then
// tries to open files referred to in the configuration. A non-zero exit
// status is reported as ErrConfigInvalid; a test killed by a signal (for
// example by the OOM killer) is not, because it says nothing about the
// configuration.
func (n *ExecNginx) Test(ctx context.Context, conf string) (string, error) {
	out, err := n.run(ctx, n.TestTimeout, n.args(conf, "-t"))
	var exitErr *exec.ExitError
	if err != nil && errors.As(err, &exitErr) && exitErr.Exited() && !isTimeout(err) {
		return out, fmt.Errorf("%w: %w", ErrConfigInvalid, err)
	}
	return out, err
}

// Reload makes the running master re-read the configuration.
//
// With PIDFile set (recommended), it sends SIGHUP to the master and waits
// until a new child process appears. Per
// https://nginx.org/en/docs/control.html, on HUP the master checks the new
// configuration and, only if it can apply it, starts new worker processes;
// otherwise it keeps working with the old one. So a new child means the
// configuration was read and accepted, and the live set can safely be
// swapped again. No new child within ReloadTimeout is reported as an error,
// which makes the engine roll back. This needs a Linux-style /proc and a
// master with worker processes (the default "master_process on").
//
// Without PIDFile it runs "nginx -c conf -s reload"
// (https://nginx.org/en/docs/switches.html). That command returns once the
// signal is sent, before the master has read the configuration, so a
// rejected configuration goes unnoticed and a swap shortly afterwards may be
// read halfway. It also parses the whole configuration itself before
// sending the signal.
func (n *ExecNginx) Reload(ctx context.Context, conf string) (string, error) {
	if n.PIDFile == "" {
		return n.run(ctx, n.ReloadTimeout, n.args(conf, "-s", "reload"))
	}
	if n.ReloadTimeout <= 0 {
		return "", errors.New("apply: nginx timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, n.ReloadTimeout)
	defer cancel()
	return "", n.signalReload(ctx)
}

func isTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
