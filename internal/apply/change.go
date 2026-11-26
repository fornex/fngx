// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// File is one generated file. Path is relative to the generation root.
type File struct {
	Path string
	Data []byte
}

// Unit is a group of files that is accepted or rejected as a whole, usually
// one domain's configuration (N-4).
type Unit struct {
	ID    string
	Files []File
}

// Change describes a new configuration set relative to the live one.
type Change struct {
	// Full means the change is the complete desired state: common files and
	// units that are not listed are removed. Otherwise the change is applied
	// on top of the live generation.
	Full bool

	// Common files are shared by all units, including Config.MainFile. A
	// broken common file fails the whole change. In an incremental change
	// the listed files replace or add files; they cannot be removed.
	Common []File

	// Units to add or replace.
	Units []Unit

	// Remove lists unit IDs to delete. Ignored when Full is set.
	Remove []string

	// AllOrNothing disables per-unit isolation: if the candidate fails the
	// test, nothing is applied. Use it when the author must see the error,
	// for example a rule or template that is being saved (T-9).
	AllOrNothing bool
}

// Limits on identifiers. Generous, but they keep log lines and manifests sane.
const (
	maxIDLen   = 255
	maxPathLen = 1024
)

var errEmptyChange = errors.New("apply: empty change")

// validate checks identifiers and paths before anything touches disk. Paths
// must be clean, relative and must not escape the generation root; names that
// start with "." are reserved for the engine (N-6).
func (c *Change) validate(mainFile string) error {
	if !c.Full && len(c.Common) == 0 && len(c.Units) == 0 && len(c.Remove) == 0 {
		return errEmptyChange
	}
	owner := map[string]string{} // path -> owner, for duplicate detection
	claim := func(p, who string) error {
		if err := validPath(p); err != nil {
			return fmt.Errorf("apply: %s: %w", who, err)
		}
		if prev, ok := owner[p]; ok {
			return fmt.Errorf("apply: path %q used by both %s and %s", p, prev, who)
		}
		owner[p] = who
		return nil
	}
	hasMain := false
	for _, f := range c.Common {
		if err := claim(f.Path, "common files"); err != nil {
			return err
		}
		if f.Path == mainFile {
			hasMain = true
		}
	}
	if c.Full && !hasMain {
		return fmt.Errorf("apply: full change has no main file %q", mainFile)
	}
	ids := map[string]bool{}
	for _, u := range c.Units {
		if err := validID(u.ID); err != nil {
			return err
		}
		if ids[u.ID] {
			return fmt.Errorf("apply: unit %q listed twice", u.ID)
		}
		ids[u.ID] = true
		if len(u.Files) == 0 {
			return fmt.Errorf("apply: unit %q has no files", u.ID)
		}
		for _, f := range u.Files {
			if err := claim(f.Path, fmt.Sprintf("unit %q", u.ID)); err != nil {
				return err
			}
			if f.Path == mainFile {
				return fmt.Errorf("apply: unit %q must not contain the main file", u.ID)
			}
		}
	}
	if !c.Full {
		for _, id := range c.Remove {
			if err := validID(id); err != nil {
				return err
			}
			if ids[id] {
				return fmt.Errorf("apply: unit %q is both replaced and removed", id)
			}
		}
	}
	return nil
}

func validID(id string) error {
	if id == "" || len(id) > maxIDLen {
		return fmt.Errorf("apply: invalid unit id %q", id)
	}
	for _, r := range id {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return fmt.Errorf("apply: invalid unit id %q", id)
		}
	}
	return nil
}

func validPath(p string) error {
	if p == "" || len(p) > maxPathLen {
		return fmt.Errorf("invalid path %q", p)
	}
	if !filepath.IsLocal(p) || filepath.Clean(p) != p || strings.ContainsRune(p, '\\') {
		return fmt.Errorf("path %q is not a clean relative path", p)
	}
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ".") {
			return fmt.Errorf("path %q: names starting with '.' are reserved", p)
		}
		for _, r := range part {
			if unicode.IsControl(r) {
				return fmt.Errorf("path %q contains a control character", p)
			}
		}
	}
	return nil
}

// Batch merges many changes so they are applied with one test and one reload
// (A-6). It is safe for concurrent use.
type Batch struct {
	mu     sync.Mutex
	full   bool
	common map[string]File
	units  map[string]Unit
	remove map[string]bool
	strict bool
}

// Add merges c into the batch. A full change replaces everything added
// before it; later changes win over earlier ones for the same unit or path.
func (b *Batch) Add(c Change) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.common == nil || c.Full {
		b.common = map[string]File{}
		b.units = map[string]Unit{}
		b.remove = map[string]bool{}
		b.full = false
		b.strict = false
	}
	if c.Full {
		b.full = true
	}
	b.strict = b.strict || c.AllOrNothing
	for _, f := range c.Common {
		b.common[f.Path] = f
	}
	for _, u := range c.Units {
		b.units[u.ID] = u
		delete(b.remove, u.ID)
	}
	if !c.Full {
		for _, id := range c.Remove {
			delete(b.units, id)
			if !b.full {
				b.remove[id] = true
			}
		}
	}
}

// Len reports how many units and common files are pending.
func (b *Batch) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.common) + len(b.units) + len(b.remove)
}

// Change returns the merged change and empties the batch. Order is
// deterministic so that logs and tests are stable.
func (b *Batch) Change() Change {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := Change{Full: b.full, AllOrNothing: b.strict}
	for _, p := range sortedKeys(b.common) {
		c.Common = append(c.Common, b.common[p])
	}
	for _, id := range sortedKeys(b.units) {
		c.Units = append(c.Units, b.units[id])
	}
	c.Remove = sortedKeys(b.remove)
	b.common, b.units, b.remove = nil, nil, nil
	b.full, b.strict = false, false
	return c
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
