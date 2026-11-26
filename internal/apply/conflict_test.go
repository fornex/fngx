// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A broken unit whose previous path was taken by another unit cannot be
// kept at its previous version. Dropping it silently would take a live
// domain offline while reporting it as kept, so nothing is applied.
func TestApplyRejectedUnitWhosePathWasTaken(t *testing.T) { // N-3, N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "server a"))); err != nil {
		t.Fatal(err)
	}
	_, err := e.Apply(ctx, Change{Units: []Unit{
		{ID: "a", Files: []File{{Path: "vhosts/a2.conf", Data: []byte("BROKEN")}}},
		{ID: "b", Files: []File{{Path: "vhosts/a.conf", Data: []byte("server b")}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "cannot keep unit") {
		t.Fatalf("err = %v", err)
	}
	if env.live(t) != "gen-000000001" || env.liveFile(t, "vhosts/a.conf") != "server a" {
		t.Fatal("live set changed")
	}
}

// Units whose files collide with files of other units are rejected on
// their own; the rest of the change applies (N-4).
func TestApplyPathConflictsRejectOnlyTheUnit(t *testing.T) { // N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("keep", "k"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, Change{Units: []Unit{
		// Same path as an unchanged live unit.
		{ID: "dup", Files: []File{{Path: "vhosts/keep.conf", Data: []byte("x")}}},
		// File and directory of the same name.
		{ID: "p", Files: []File{{Path: "vhosts/z", Data: []byte("p")}}},
		{ID: "q", Files: []File{{Path: "vhosts/z/y.conf", Data: []byte("q")}}},
		unit("ok", "fine"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range res.Rejected {
		ids = append(ids, r.Unit)
		if strings.Contains(r.Output, env.root) {
			t.Errorf("output exposes server paths: %q", r.Output)
		}
	}
	if !slices.Equal(ids, []string{"dup", "q"}) {
		t.Fatalf("rejected = %v", ids)
	}
	if env.liveFile(t, "vhosts/keep.conf") != "k" || env.liveFile(t, "vhosts/z") != "p" || env.liveFile(t, "vhosts/ok.conf") != "fine" {
		t.Fatal("wrong live content")
	}

	// All or nothing: a conflict fails the change.
	_, err = e.Check(ctx, Change{AllOrNothing: true, Units: []Unit{{ID: "dup", Files: []File{{Path: "vhosts/keep.conf", Data: []byte("x")}}}}})
	if err == nil {
		t.Fatal("conflict accepted with AllOrNothing")
	}
}

// Directories emptied while isolating units must not block a file of the
// same name later on.
func TestIsolationRemovesEmptiedDirectories(t *testing.T) { // N-4
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(Unit{ID: "a", Files: []File{{Path: "sites/a", Data: []byte("old")}}})); err != nil {
		t.Fatal(err)
	}
	// "a" moves from a file to a directory and is broken; reverting it must
	// remove the directory sites/a again before restoring the file.
	res, err := e.Apply(ctx, Change{Units: []Unit{
		{ID: "a", Files: []File{{Path: "sites/a/x.conf", Data: []byte("BROKEN")}}},
		unit("b", "ok"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || env.liveFile(t, "sites/a") != "old" || env.liveFile(t, "vhosts/b.conf") != "ok" {
		t.Fatalf("result = %+v", res)
	}
}

func TestApplyIdenticalChangeIsNoOp(t *testing.T) { // A-5
	env := newEnv(t)
	e := env.engine(t)
	ctx := context.Background()
	if _, err := e.Apply(ctx, full(unit("a", "x"))); err != nil {
		t.Fatal(err)
	}
	res, err := e.Apply(ctx, full(unit("a", "x")))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unchanged || res.Generation != "gen-000000001" {
		t.Fatalf("result = %+v", res)
	}
	if gens := env.gens(t); len(gens) != 1 {
		t.Fatalf("generations = %v", gens)
	}
	if reloads, _ := env.nginx.snapshot(); len(reloads) != 1 {
		t.Fatalf("reloads = %v", reloads)
	}
}

// With nginx stopped the set still goes live and is used when nginx starts.
func TestApplyWhileNginxIsNotRunning(t *testing.T) { // A-5
	env := newEnv(t)
	env.nginx.reloadErr = func(int, string) error { return ErrNotRunning }
	e := env.engine(t)
	ctx := context.Background()
	res, err := e.Apply(ctx, full(unit("a", "x")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Reloaded || env.live(t) != res.Generation {
		t.Fatalf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(env.root, ".pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending marker left")
	}
	env.nginx.reloadErr = nil
	res, err = e.Apply(ctx, Change{Units: []Unit{unit("a", "y")}})
	if err != nil || !res.Reloaded {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}
