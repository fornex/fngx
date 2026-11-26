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

// Nginx is the part of nginx the engine needs. Tests substitute a fake.
type Nginx interface {
	// Test checks the configuration whose main file is conf and returns the
	// combined output of the check.
	Test(ctx context.Context, conf string) (output string, err error)
	// Reload asks the running nginx to re-read the configuration whose main
	// file is conf.
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

// Default timeouts. "nginx -t" on 10,000 server blocks has not been measured
// yet; the test timeout is a generous assumption.
const (
	DefaultTestTimeout   = 5 * time.Minute
	DefaultReloadTimeout = 30 * time.Second
)

// ExecNginx drives a real nginx binary.
type ExecNginx struct {
	Binary string // path to the nginx binary
	// Prefix, when set, is passed with -p to every invocation so that test
	// and reload resolve relative paths the same way.
	Prefix string
	// ExtraArgs are appended to every invocation before the action, for
	// example []string{"-e", "/var/log/nginx/error.log"} (nginx 1.19.5+).
	ExtraArgs     []string
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
// status is reported as ErrConfigInvalid.
func (n *ExecNginx) Test(ctx context.Context, conf string) (string, error) {
	out, err := n.run(ctx, n.TestTimeout, n.args(conf, "-t"))
	var exitErr *exec.ExitError
	if err != nil && errors.As(err, &exitErr) && !isTimeout(err) {
		return out, fmt.Errorf("%w: %w", ErrConfigInvalid, err)
	}
	return out, err
}

// Reload runs "nginx -c conf -s reload", which sends the reload signal to
// the master process whose PID file is named in conf
// (https://nginx.org/en/docs/switches.html). A zero exit status means the
// signal was delivered; per https://nginx.org/en/docs/control.html the
// master then checks the new configuration itself and keeps the old one if
// it cannot apply it. That outcome is not visible to this command.
func (n *ExecNginx) Reload(ctx context.Context, conf string) (string, error) {
	return n.run(ctx, n.ReloadTimeout, n.args(conf, "-s", "reload"))
}

func isTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
