// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestApplyFirstFullChange(t *testing.T) { // A-4, A-5
	env := newEnv(t)
	e := env.engine(t)
	res, err := e.Apply(context.Background(), full(unit("a", "server a"), unit("b", "server b")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != "gen-000000001" || res.Tests != 1 || len(res.Rejected) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if got := env.live(t); got != res.Generation {
		t.Fatalf("live = %s", got)
	}
	if got := env.liveFile(t, "vhosts/b.conf"); got != "server b" {
		t.Fatalf("b.conf = %q", got)
	}
	reloads, _ := env.nginx.snapshot()
	if !slices.Equal(reloads, []string{"gen-000000001"}) {
		t.Fatalf("reloads = %v", reloads)
	}
	if e.LiveConf() != filepath.Join(env.root, "live", "nginx.conf") {
		t.Fatalf("LiveConf = %s", e.LiveConf())
	}
	if _, err := os.Stat(filepath.Join(env.root, ".pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker left behind: %v", err)
	}
}

func TestApplyIncrementalReusesUnchangedFiles(t *testing.T) { // A-4, N-2
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "server a"), unit("b", "server b"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, Change{Units: []Unit{unit("b", "server b2"), unit("c", "server c")}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != "gen-000000002" {
		t.Fatalf("generation = %s", res.Generation)
	}
	if got := env.liveFile(t, "vhosts/b.conf"); got != "server b2" {
		t.Fatalf("b.conf = %q", got)
	}
	if got := env.liveFile(t, "vhosts/c.conf"); got != "server c" {
		t.Fatalf("c.conf = %q", got)
	}
	// The unchanged unit is the same file as in the previous generation.
	g := filepath.Join(env.root, "generations")
	st1, err := os.Stat(filepath.Join(g, "gen-000000001", "vhosts/a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	st2, err := os.Stat(filepath.Join(g, "gen-000000002", "vhosts/a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(st1, st2) {
		t.Fatal("unchanged file was rewritten instead of linked")
	}

	// Removal.
	if _, err := e.Apply(ctx, Change{Remove: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(env.root, "live", "vhosts/a.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed unit still live: %v", err)
	}
	// A full change drops units it does not list.
	if _, err := e.Apply(ctx, full(unit("c", "server c"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(env.root, "live", "vhosts/b.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlisted unit still live after full change: %v", err)
	}
}

func TestApplyTestFailureChangesNothing(t *testing.T) { // A-5, T-9, N-3
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "server a"))); err != nil {
		t.Fatal(err)
	}
	_, err := e.Apply(ctx, Change{AllOrNothing: true, Units: []Unit{unit("a", "server a\nBROKEN")}})
	var te *TestError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want *TestError", err)
	}
	// The author sees the nginx error with paths relative to the set.
	if !strings.Contains(te.Output, `unknown directive "BROKEN" in vhosts/a.conf:2`) {
		t.Fatalf("output = %q", te.Output)
	}
	if strings.Contains(te.Output, env.root) {
		t.Fatalf("output exposes server paths: %q", te.Output)
	}
	if env.live(t) != "gen-000000001" || env.liveFile(t, "vhosts/a.conf") != "server a" {
		t.Fatal("live set changed after a failed test")
	}
	reloads, _ := env.nginx.snapshot()
	if len(reloads) != 1 {
		t.Fatalf("reloads = %v", reloads)
	}
	if gens := env.gens(t); !slices.Equal(gens, []string{"gen-000000001"}) {
		t.Fatalf("failed candidate left behind: %v", gens)
	}
}

func TestApplyFirstChangeBroken(t *testing.T) { // A-5, N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	// All or nothing: no live set is created.
	_, err := e.Apply(ctx, Change{Full: true, AllOrNothing: true, Common: []File{mainFile()}, Units: []Unit{unit("a", "BROKEN"), unit("b", "x")}})
	var te *TestError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(env.root, "live")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live link created: %v", err)
	}
	// Default: the broken unit is left out and the rest goes live.
	res, err := e.Apply(ctx, full(unit("a", "BROKEN"), unit("b", "x")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Unit != "a" {
		t.Fatalf("rejected = %+v", res.Rejected)
	}
	if env.liveFile(t, "vhosts/b.conf") != "x" {
		t.Fatal("good unit not applied")
	}
	if _, err := os.Stat(filepath.Join(env.root, "live", "vhosts/a.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("broken unit applied")
	}
}

func TestApplyIsolatesBrokenUnitByFileName(t *testing.T) { // N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "server a"), unit("b", "server b"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, Change{Units: []Unit{
		unit("a", "server a2"),
		unit("b", "server b2\nBROKEN"),
		unit("new", "BROKEN"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range res.Rejected {
		ids = append(ids, r.Unit)
		if !strings.Contains(r.Output, "vhosts/"+r.Unit+".conf") {
			t.Errorf("unit %s output does not name its file: %q", r.Unit, r.Output)
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"b", "new"}) {
		t.Fatalf("rejected = %v", ids)
	}
	if env.liveFile(t, "vhosts/a.conf") != "server a2" {
		t.Fatal("good unit was not applied")
	}
	if env.liveFile(t, "vhosts/b.conf") != "server b" {
		t.Fatal("broken unit did not keep its previous version")
	}
	if _, err := os.Stat(filepath.Join(env.root, "live", "vhosts/new.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("broken new unit was applied")
	}
	// One failing test, one per attributed unit, one final.
	if res.Tests != 3 {
		t.Fatalf("tests = %d", res.Tests)
	}
}

func TestApplyIsolatesByBisection(t *testing.T) { // N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	var units []Unit
	for i := range 16 {
		units = append(units, unit(fmt.Sprintf("u%02d", i), "ok"))
	}
	if _, err := e.Apply(ctx, full(units...)); err != nil {
		t.Fatal(err)
	}
	var change []Unit
	for i := range 16 {
		body := "changed"
		if i == 3 || i == 11 {
			body = "HIDDEN" // error without a file name: attribution cannot help
		}
		change = append(change, unit(fmt.Sprintf("u%02d", i), body))
	}
	res, err := e.Apply(ctx, Change{Units: change})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range res.Rejected {
		ids = append(ids, r.Unit)
	}
	if !slices.Equal(ids, []string{"u03", "u11"}) {
		t.Fatalf("rejected = %v", ids)
	}
	for i := range 16 {
		id := fmt.Sprintf("u%02d", i)
		want := "changed"
		if i == 3 || i == 11 {
			want = "ok"
		}
		if got := env.liveFile(t, "vhosts/"+id+".conf"); got != want {
			t.Errorf("%s = %q, want %q", id, got, want)
		}
	}
	// 2 broken of 16: first test, baseline, 10 during bisection, final.
	if res.Tests != 13 {
		t.Fatalf("tests = %d", res.Tests)
	}
}

func TestApplyIsolatesConflictBetweenUnits(t *testing.T) { // N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "x"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, Change{Units: []Unit{unit("b", "DUP up"), unit("c", "DUP up"), unit("d", "fine")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Unit != "c" {
		t.Fatalf("rejected = %+v", res.Rejected)
	}
	env.liveFile(t, "vhosts/b.conf")
	env.liveFile(t, "vhosts/d.conf")
}

func TestApplyBrokenCommonFileAppliesNothing(t *testing.T) { // N-3, N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "x"))); err != nil {
		t.Fatal(err)
	}
	_, err := e.Apply(ctx, Change{
		Common: []File{{Path: "snippets/common.conf", Data: []byte("HIDDEN")}},
		Units:  []Unit{unit("a", "y"), unit("b", "z")},
	})
	var te *TestError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v", err)
	}
	if env.live(t) != "gen-000000001" {
		t.Fatal("live changed")
	}
}

func TestApplyAllUnitsRejected(t *testing.T) { // N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "x"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, Change{Units: []Unit{unit("a", "BROKEN")}})
	if !errors.Is(err, ErrNoChange) {
		t.Fatalf("err = %v", err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("rejected = %+v", res.Rejected)
	}
	reloads, _ := env.nginx.snapshot()
	if len(reloads) != 1 {
		t.Fatalf("reloads = %v", reloads)
	}
}

func TestApplyTestCannotRun(t *testing.T) {
	env := newEnv(t)
	env.nginx.testErr = errors.New("exec: nginx: not found")
	e := env.engine(t)
	_, err := e.Apply(context.Background(), full(unit("a", "x")))
	var te *TestError
	if err == nil || errors.As(err, &te) || !strings.Contains(err.Error(), "could not run") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyTestBudget(t *testing.T) { // N-4
	env := newEnv(t)
	env.cfg.MaxTests = 3
	e := env.engine(t)
	ctx := context.Background()
	var units []Unit
	for i := range 8 {
		units = append(units, unit(fmt.Sprintf("u%d", i), "ok"))
	}
	if _, err := e.Apply(ctx, full(units...)); err != nil {
		t.Fatal(err)
	}
	for i := range units {
		units[i] = unit(units[i].ID, "HIDDEN")
	}
	_, err := e.Apply(ctx, Change{Units: units})
	var te *TestError
	if !errors.Is(err, ErrTestBudget) || !errors.As(err, &te) || !strings.Contains(te.Output, "could not build") {
		t.Fatalf("err = %v", err)
	}
	if env.live(t) != "gen-000000001" {
		t.Fatal("live changed")
	}
}

func TestApplyReloadFailureRollsBack(t *testing.T) { // A-5, N-3
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "v1"))); err != nil {
		t.Fatal(err)
	}
	env.nginx.reloadErr = func(n int, _ string) error {
		if n == 2 {
			return errors.New("exit status 1")
		}
		return nil
	}
	res, err := e.Apply(ctx, Change{Units: []Unit{unit("a", "v2")}})
	var re *ReloadError
	if !errors.As(err, &re) || !re.RolledBack {
		t.Fatalf("err = %v", err)
	}
	if res.Generation != "gen-000000001" || env.live(t) != "gen-000000001" {
		t.Fatalf("live = %s, result = %s", env.live(t), res.Generation)
	}
	if env.liveFile(t, "vhosts/a.conf") != "v1" {
		t.Fatal("previous content not restored")
	}
	reloads, _ := env.nginx.snapshot()
	if !slices.Equal(reloads, []string{"gen-000000001", "gen-000000002", "gen-000000001"}) {
		t.Fatalf("reloads = %v", reloads)
	}
	if gens := env.gens(t); !slices.Equal(gens, []string{"gen-000000001"}) {
		t.Fatalf("generations = %v", gens)
	}
	if _, err := os.Stat(filepath.Join(env.root, ".pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending marker left after a successful rollback")
	}
}

func TestApplyRollbackFailureIsReported(t *testing.T) { // A-5, N-3
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "v1"))); err != nil {
		t.Fatal(err)
	}
	env.nginx.reloadErr = func(int, string) error { return errors.New("exit status 1") }
	_, err := e.Apply(ctx, Change{Units: []Unit{unit("a", "v2")}})
	var re *ReloadError
	if !errors.As(err, &re) || re.RolledBack || re.RollbackErr == nil {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("message = %q", err.Error())
	}
	// The marker stays, so the next operation retries the reload.
	if _, err := os.Stat(filepath.Join(env.root, ".pending")); err != nil {
		t.Fatalf("pending marker: %v", err)
	}
	env.nginx.reloadErr = nil
	if err := e.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(env.root, ".pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending marker not cleared by recovery")
	}
	reloads, _ := env.nginx.snapshot()
	if last := reloads[len(reloads)-1]; last != env.live(t) {
		t.Fatalf("recovery reloaded %s, live is %s", last, env.live(t))
	}
}

func TestApplyFirstReloadFailure(t *testing.T) { // A-5
	env := newEnv(t)
	env.nginx.reloadErr = func(int, string) error { return errors.New("no master process") }
	e := env.engine(t)
	_, err := e.Apply(context.Background(), full(unit("a", "x")))
	var re *ReloadError
	if !errors.As(err, &re) || re.RolledBack {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(env.root, "live")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live link kept after failed first reload: %v", err)
	}
}

func TestApplyConcurrentCallers(t *testing.T) { // A-6
	env := newEnv(t)
	env.cfg.Keep = 2
	env.nginx.testDelay = 2 * time.Millisecond
	ctx := context.Background()
	if _, err := env.engine(t).Apply(ctx, full(unit("base", "x"))); err != nil {
		t.Fatal(err)
	}
	shared := env.engine(t)
	const callers = 12
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := shared
			if i%2 == 0 {
				// A separate engine stands in for another process: it has
				// its own lock descriptor.
				var err error
				if e, err = New(env.cfg); err != nil {
					errs <- err
					return
				}
			}
			_, err := e.Apply(ctx, Change{Units: []Unit{unit(fmt.Sprintf("c%02d", i), "x")}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, overlaps := env.nginx.snapshot()
	if overlaps != 0 {
		t.Fatalf("%d nginx calls overlapped", overlaps)
	}
	// No update was lost.
	m, err := readManifest(filepath.Join(env.root, "live"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Units) != callers+1 {
		t.Fatalf("live has %d units, want %d", len(m.Units), callers+1)
	}
	if n := len(env.gens(t)); n != env.cfg.Keep+1 {
		t.Fatalf("%d generations kept, want %d", n, env.cfg.Keep+1)
	}
}

func TestApplyLockRespectsContext(t *testing.T) { // A-6
	env := newEnv(t)
	e := env.engine(t)
	l, err := lockFile(context.Background(), filepath.Join(env.root, ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = e.Apply(ctx, full(unit("a", "x")))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestRecoverRemovesLeftovers(t *testing.T) { // A-5, N-3
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "x"))); err != nil {
		t.Fatal(err)
	}
	// A crash while building gen 2, and while swapping.
	gens := filepath.Join(env.root, "generations")
	if err := os.MkdirAll(filepath.Join(gens, "gen-000000002", "vhosts"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("generations/gen-000000002", filepath.Join(env.root, "live.tmp-dead")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.root, ".pending.tmp-dead"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Foreign files are left alone.
	if err := os.WriteFile(filepath.Join(env.root, "README"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := env.engine(t).Apply(ctx, Change{Units: []Unit{unit("b", "y")}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != "gen-000000002" {
		t.Fatalf("generation = %s", res.Generation)
	}
	for _, n := range []string{"live.tmp-dead", ".pending.tmp-dead"} {
		if _, err := os.Lstat(filepath.Join(env.root, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not removed", n)
		}
	}
	if _, err := os.Stat(filepath.Join(env.root, "README")); err != nil {
		t.Error("foreign file removed")
	}
	if env.liveFile(t, "vhosts/b.conf") != "y" {
		t.Fatal("apply after recovery failed")
	}
}

// A crash after the swap and before the reload: recovery reloads the live
// set.
func TestRecoverReloadsAfterInterruptedSwap(t *testing.T) { // A-5, N-3
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "v1"))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, Change{Units: []Unit{unit("a", "v2")}}); err != nil {
		t.Fatal(err)
	}
	if err := e.writePending("gen-000000001", "gen-000000002"); err != nil {
		t.Fatal(err)
	}
	if err := env.engine(t).Recover(ctx); err != nil {
		t.Fatal(err)
	}
	reloads, _ := env.nginx.snapshot()
	if !slices.Equal(reloads[len(reloads)-1:], []string{"gen-000000002"}) {
		t.Fatalf("reloads = %v", reloads)
	}
	if _, err := os.Stat(filepath.Join(env.root, ".pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending marker not cleared")
	}

	// Same, but nginx refuses the new set: the old one comes back.
	if err := e.writePending("gen-000000001", "gen-000000002"); err != nil {
		t.Fatal(err)
	}
	env.nginx.reloadErr = func(_ int, gen string) error {
		if gen == "gen-000000002" {
			return errors.New("exit status 1")
		}
		return nil
	}
	if err := env.engine(t).Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if env.live(t) != "gen-000000001" || env.liveFile(t, "vhosts/a.conf") != "v1" {
		t.Fatalf("live = %s", env.live(t))
	}
}

func TestPruneKeepsBoundedGenerations(t *testing.T) { // A-5
	env := newEnv(t)
	env.cfg.Keep = 2
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "v0"))); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if _, err := e.Apply(ctx, Change{Units: []Unit{unit("a", fmt.Sprintf("v%d", i))}}); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"gen-000000004", "gen-000000005", "gen-000000006"}
	if gens := env.gens(t); !slices.Equal(gens, want) {
		t.Fatalf("generations = %v, want %v", gens, want)
	}
	if env.live(t) != "gen-000000006" {
		t.Fatal("wrong live generation")
	}
}

func TestCheckDoesNotApply(t *testing.T) { // T-9
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "v1"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Check(ctx, Change{Units: []Unit{unit("a", "v2")}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tests != 1 {
		t.Fatalf("tests = %d", res.Tests)
	}
	_, err = e.Check(ctx, Change{AllOrNothing: true, Units: []Unit{unit("a", "BROKEN")}})
	var te *TestError
	if !errors.As(err, &te) || !strings.Contains(te.Output, "vhosts/a.conf:1") {
		t.Fatalf("err = %v", err)
	}
	if env.live(t) != "gen-000000001" || env.liveFile(t, "vhosts/a.conf") != "v1" {
		t.Fatal("check changed the live set")
	}
	if gens := env.gens(t); len(gens) != 1 {
		t.Fatalf("check left generations: %v", gens)
	}
	if reloads, _ := env.nginx.snapshot(); len(reloads) != 1 {
		t.Fatalf("check reloaded nginx: %v", reloads)
	}
}

func TestApplyRefusesForeignLiveLink(t *testing.T) {
	env := newEnv(t)
	if err := os.Symlink("/etc", filepath.Join(env.root, "live")); err != nil {
		t.Fatal(err)
	}
	_, err := env.engine(t).Apply(context.Background(), full(unit("a", "x")))
	if err == nil || !strings.Contains(err.Error(), "not a generation") {
		t.Fatalf("err = %v", err)
	}
	if target, _ := os.Readlink(filepath.Join(env.root, "live")); target != "/etc" {
		t.Fatal("foreign live link overwritten")
	}
}

func TestOperationsAreLogged(t *testing.T) { // N-9
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "x"))); err != nil {
		t.Fatal(err)
	}
	_, _ = e.Apply(ctx, Change{AllOrNothing: true, Units: []Unit{unit("a", "BROKEN\nBROKEN")}})
	lines := strings.Split(strings.TrimSpace(env.logs.String()), "\n")
	msgs := map[string]bool{}
	for _, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not one JSON object: %q", line)
		}
		if rec["op"] == nil || rec["action"] == nil || rec["component"] != "apply" {
			t.Fatalf("log line lacks context: %q", line)
		}
		msgs[rec["msg"].(string)] = true
	}
	for _, want := range []string{"start", "candidate built", "test passed", "test failed", "swapped", "reloaded", "done", "failed"} {
		if !msgs[want] {
			t.Errorf("no %q record in log", want)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	env := newEnv(t)
	for name, mod := range map[string]func(*Config){
		"relative root": func(c *Config) { c.Root = "etc" },
		"keep 0":        func(c *Config) { c.Keep = 0 },
		"max tests 0":   func(c *Config) { c.MaxTests = 0 },
		"no nginx":      func(c *Config) { c.Nginx = nil },
		"no logger":     func(c *Config) { c.Logger = nil },
		"bad main":      func(c *Config) { c.MainFile = "../nginx.conf" },
	} {
		cfg := env.cfg
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	d := DefaultConfig()
	if !strings.HasPrefix(d.Root, "/etc/") || d.Keep < 1 || d.Nginx == nil {
		t.Fatalf("default config = %+v", d)
	}
}

func TestApplyRejectsInvalidChange(t *testing.T) { // N-6
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	cases := map[string]Change{
		"empty":            {},
		"no main":          {Full: true, Units: []Unit{unit("a", "x")}},
		"incremental only": {Units: []Unit{unit("a", "x")}},
		"escape":           {Full: true, Common: []File{mainFile(), {Path: "../x"}}},
		"absolute":         {Full: true, Common: []File{mainFile(), {Path: "/etc/passwd"}}},
		"unclean":          {Full: true, Common: []File{mainFile(), {Path: "a//b"}}},
		"dotted":           {Full: true, Common: []File{mainFile(), {Path: ".manifest.json"}}},
		"dot dir":          {Full: true, Common: []File{mainFile(), {Path: "a/.hidden/b"}}},
		"newline":          {Full: true, Common: []File{mainFile(), {Path: "a\nb"}}},
		"dup path":         {Full: true, Common: []File{mainFile()}, Units: []Unit{{ID: "a", Files: []File{{Path: "nginx.conf"}}}}},
		"dup unit":         {Full: true, Common: []File{mainFile()}, Units: []Unit{unit("a", "x"), unit("a", "y")}},
		"empty unit":       {Full: true, Common: []File{mainFile()}, Units: []Unit{{ID: "a"}}},
		"bad id":           {Full: true, Common: []File{mainFile()}, Units: []Unit{unit("a\nb", "x")}},
		"remove and add":   {Units: []Unit{unit("a", "x")}, Remove: []string{"a"}},
	}
	for name, ch := range cases {
		if _, err := e.Apply(ctx, ch); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(env.root, "live")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid change went live")
	}
	if gens := env.gens(t); len(gens) != 0 {
		t.Fatalf("generations = %v", gens)
	}
}

func TestBatchMergesChanges(t *testing.T) { // A-6
	var b Batch
	b.Add(Change{Units: []Unit{unit("a", "1"), unit("b", "1")}})
	b.Add(Change{Units: []Unit{unit("a", "2")}, Remove: []string{"b", "c"}})
	b.Add(Change{Units: []Unit{unit("c", "1")}})
	if b.Len() != 3 {
		t.Fatalf("len = %d", b.Len())
	}
	ch := b.Change()
	if ch.Full || len(ch.Units) != 2 || string(ch.Units[0].Files[0].Data) != "2" || ch.Units[1].ID != "c" {
		t.Fatalf("change = %+v", ch)
	}
	if !slices.Equal(ch.Remove, []string{"b"}) {
		t.Fatalf("remove = %v", ch.Remove)
	}
	if b.Len() != 0 {
		t.Fatal("batch not emptied")
	}

	// A full change resets what came before; later removals just drop units.
	b.Add(Change{Units: []Unit{unit("x", "1")}, AllOrNothing: true})
	b.Add(full(unit("a", "1"), unit("b", "1")))
	b.Add(Change{Remove: []string{"b"}})
	ch = b.Change()
	if !ch.Full || ch.AllOrNothing || len(ch.Units) != 1 || ch.Units[0].ID != "a" || len(ch.Remove) != 0 {
		t.Fatalf("change = %+v", ch)
	}

	// Batched changes go out with one reload.
	env := newEnv(t)
	e := env.engine(t)
	b.Add(full(unit("a", "1")))
	b.Add(Change{Units: []Unit{unit("b", "1")}})
	if _, err := e.Apply(context.Background(), b.Change()); err != nil {
		t.Fatal(err)
	}
	if reloads, _ := env.nginx.snapshot(); len(reloads) != 1 {
		t.Fatalf("reloads = %v", reloads)
	}
}

func TestNewRefusesSharedRoot(t *testing.T) {
	env := newEnv(t)
	if err := os.Chmod(env.root, 0o777); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	if _, err := New(env.cfg); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err = %v", err)
	}
}
