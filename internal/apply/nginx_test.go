package apply

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"testing"
	"time"
)

type recordingRunner struct {
	name string
	args []string
	out  string
	err  error
	dl   bool
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.name, r.args = name, args
	_, r.dl = ctx.Deadline()
	return []byte(r.out), r.err
}

func TestExecNginxArguments(t *testing.T) { // N-6
	r := &recordingRunner{}
	n := &ExecNginx{
		Binary: "/opt/nginx", Prefix: "/srv/p", ExtraArgs: []string{"-e", "/l/e.log"},
		TestTimeout: time.Second, ReloadTimeout: time.Second, Runner: r,
	}
	ctx := context.Background()
	if _, err := n.Test(ctx, "/r/gen/nginx.conf; rm -rf /"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-p", "/srv/p", "-c", "/r/gen/nginx.conf; rm -rf /", "-e", "/l/e.log", "-t"}
	if r.name != "/opt/nginx" || !slices.Equal(r.args, want) || !r.dl {
		t.Fatalf("test ran %s %q (deadline %v)", r.name, r.args, r.dl)
	}
	if _, err := n.Reload(ctx, "/r/live/nginx.conf"); err != nil {
		t.Fatal(err)
	}
	want = []string{"-p", "/srv/p", "-c", "/r/live/nginx.conf", "-e", "/l/e.log", "-s", "reload"}
	if !slices.Equal(r.args, want) || !r.dl {
		t.Fatalf("reload ran %q", r.args)
	}
	n.TestTimeout = 0
	if _, err := n.Test(ctx, "x"); err == nil {
		t.Fatal("zero timeout accepted")
	}
}

func TestExecNginxClassifiesErrors(t *testing.T) {
	ctx := context.Background()
	// A non-zero exit means nginx rejected the configuration.
	falseBin, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false binary")
	}
	n := &ExecNginx{Binary: falseBin, TestTimeout: 5 * time.Second}
	if _, err := n.Test(ctx, "x"); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v", err)
	}
	// A missing binary is not a configuration error.
	n.Binary = "/nonexistent/nginx"
	if _, err := n.Test(ctx, "x"); err == nil || errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestExecRunnerTimeout(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = ExecRunner{}.Run(ctx, sleep, "10")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
}
