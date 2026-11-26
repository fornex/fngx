package apply

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// ErrTestBudget means isolating broken units (N-4) needed more "nginx -t"
// runs than Config.MaxTests allows. Nothing is applied; the error also wraps
// a *TestError with the first nginx output.
var ErrTestBudget = errors.New("apply: test budget exhausted while isolating broken units")

// settle tests the candidate. If the test fails and isolation is allowed, it
// finds the changed units that break the test, puts their live version back
// (or leaves them out if they are new), and tests again (N-4).
//
// Strategy:
//
//  1. Attribution. nginx usually names the file and line of an error
//     ("... in /path/file.conf:12"). If the output names a file of a changed
//     unit, that unit is reverted and the set is tested again. This costs one
//     test per broken unit.
//  2. Bisection. If the output does not name a changed unit's file (for
//     example a duplicate definition reported elsewhere, or a hash size
//     limit), all changed units are reverted. If that still fails, the cause
//     is in the common files or removals and nothing is applied. Otherwise
//     the changed units are added back in halves; a half that fails is split
//     until single broken units are found. With k broken units out of n
//     this needs about k*log2(n) tests.
//  3. The final set is always tested once more as a whole.
//
// The format of nginx error messages is not a documented interface, so
// attribution is only a hint: every decision is confirmed by a real test,
// and a wrong hint costs one test, never a wrong result.
func (e *Engine) settle(ctx context.Context, c *candidate, ch *Change, res *Result, log *slog.Logger) error {
	conf := c.dir + "/" + e.cfg.MainFile
	test := func() (string, error) {
		if res.Tests >= e.cfg.MaxTests {
			return "", ErrTestBudget
		}
		res.Tests++
		start := time.Now()
		out, err := e.cfg.Nginx.Test(ctx, conf)
		out = c.clean(out)
		attrs := []any{"generation", c.name, "n", res.Tests, "duration_ms", time.Since(start).Milliseconds()}
		if err != nil {
			log.Info("test failed", append(attrs, "error", err, "output", capText(out))...)
		} else {
			log.Info("test passed", attrs...)
		}
		return out, err
	}
	reject := func(id, out string) error {
		res.Rejected = append(res.Rejected, UnitError{Unit: id, Output: out})
		log.Warn("unit rejected", "unit", id, "output", capText(out))
		return c.setOld(id)
	}
	var firstOut string
	// fail turns a test outcome into the error returned to the caller.
	fail := func(out string, err error) error {
		if errors.Is(err, ErrConfigInvalid) {
			return &TestError{Output: out}
		}
		if errors.Is(err, ErrTestBudget) {
			return fmt.Errorf("%w: %w", ErrTestBudget, &TestError{Output: firstOut})
		}
		return fmt.Errorf("apply: nginx test could not run: %w: %s", err, strings.TrimSpace(out))
	}

	out, err := test()
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrConfigInvalid) || ch.AllOrNothing || len(c.suspects) == 0 {
		return fail(out, err)
	}
	firstOut = out

	// 1. Attribution.
	for {
		id := c.attribute(out)
		if id == "" {
			break
		}
		if err := reject(id, out); err != nil {
			return err
		}
		out, err = test()
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrConfigInvalid) {
			return fail(out, err)
		}
	}

	// 2. Bisection over the changed units still at their new version.
	var included []string
	for _, id := range c.suspects {
		if c.isNew(id) {
			included = append(included, id)
			if err := c.setOld(id); err != nil {
				return err
			}
		}
	}
	if len(included) > 0 {
		if out, err := test(); err != nil {
			// Not caused by the changed units.
			if errors.Is(err, ErrConfigInvalid) {
				return &TestError{Output: out}
			}
			return fail(out, err)
		}
	}
	// search adds group to the accepted units and reports whether it passed
	// as a whole. failOut, when not empty, is the output of a failed test
	// that already proves the group fails: its parent failed and the sibling
	// half that went first passed. Such a group is split without testing it
	// again; the units found broken get that output.
	var search func(group []string, failOut string) (bool, error)
	search = func(group []string, failOut string) (bool, error) {
		out := failOut
		if out == "" {
			for _, id := range group {
				if err := c.setNew(id); err != nil {
					return false, err
				}
			}
			var err error
			out, err = test()
			if err == nil {
				return true, nil
			}
			if !errors.Is(err, ErrConfigInvalid) {
				return false, fail(out, err)
			}
			for _, id := range group {
				if err := c.setOld(id); err != nil {
					return false, err
				}
			}
		}
		if len(group) == 1 {
			return false, reject(group[0], out)
		}
		mid := len(group) / 2
		leftOK, err := search(group[:mid], "")
		if err != nil {
			return false, err
		}
		rightOut := ""
		if leftOK {
			rightOut = out
		}
		_, err = search(group[mid:], rightOut)
		return false, err
	}
	if len(included) > 0 {
		if _, err := search(included, ""); err != nil {
			return err
		}
	}

	// 3. Confirm the final set.
	if out, err := test(); err != nil {
		return fail(out, err)
	}
	if len(res.Rejected) == 0 {
		// Bisection found every unit fine on its own; the first failure did
		// not reproduce. Refuse rather than guess.
		return &TestError{Output: firstOut}
	}
	return nil
}

// attribute returns the changed unit, currently at its new version, whose
// file is named in the test output, or "".
func (c *candidate) attribute(out string) string {
	for _, id := range c.suspects {
		if !c.isNew(id) {
			continue
		}
		for _, rel := range c.m.Units[id].Files {
			// Output is already cleaned, so paths are relative.
			if strings.Contains(out, " "+rel+":") || strings.Contains(out, "\""+rel+"\"") {
				return id
			}
		}
	}
	return ""
}

// clean strips the candidate directory from nginx output so that messages
// name files relative to the generation and do not expose server paths.
func (c *candidate) clean(out string) string {
	return strings.ReplaceAll(out, c.dir+"/", "")
}
