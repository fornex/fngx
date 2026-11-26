package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// candidate is a generation being built. Until it is tested and swapped in
// it is private to the engine, so it can be changed in place (A-4).
type candidate struct {
	name    string
	dir     string
	liveDir string    // "" when there is no live generation
	live    *manifest // manifest of liveDir; empty when there is none
	m       *manifest // current content of dir

	owner    map[string]string // path -> unit id ("" for common files)
	dirs     map[string]bool   // directories created inside dir
	written  map[string]bool   // relative paths written (not linked)
	newUnits map[string]Unit   // changed units, by id
	suspects []string          // ids of changed units, sorted
}

// buildCandidate creates dir and fills it from the live generation and the
// change. Unchanged content is linked from the live generation.
func buildCandidate(name, dir, liveDir string, live *manifest, ch *Change) (*candidate, error) {
	if live == nil {
		if !ch.Full {
			return nil, errors.New("apply: there is no live configuration yet; the first change must be full")
		}
		live = newManifest()
	}
	if err := os.Mkdir(dir, dirMode); err != nil {
		return nil, err
	}
	c := &candidate{
		name:     name,
		dir:      dir,
		liveDir:  liveDir,
		live:     live,
		m:        newManifest(),
		owner:    map[string]string{},
		dirs:     map[string]bool{},
		written:  map[string]bool{},
		newUnits: map[string]Unit{},
	}

	// Common files.
	listed := map[string]File{}
	for _, f := range ch.Common {
		listed[f.Path] = f
	}
	if !ch.Full {
		for _, p := range sortedKeys(live.Common) {
			if _, ok := listed[p]; !ok {
				if err := c.linkFile(p, ""); err != nil {
					return c, err
				}
				c.m.Common[p] = live.Common[p]
			}
		}
	}
	for _, p := range sortedKeys(listed) {
		f := listed[p]
		h := fileHash(f.Data)
		var err error
		if live.Common[p] == h {
			err = c.linkFile(p, "")
		} else {
			err = c.writeFile(p, f.Data, "")
		}
		if err != nil {
			return c, err
		}
		c.m.Common[p] = h
	}

	// Units: unchanged ones are linked now; changed ones are written last so
	// that their paths never shadow a unit kept from the live generation.
	changed := map[string]Unit{}
	for _, u := range ch.Units {
		if old, ok := live.Units[u.ID]; ok && old.Hash == unitHash(u) {
			continue
		}
		changed[u.ID] = u
	}
	keep := map[string]bool{}
	if !ch.Full {
		for id := range live.Units {
			keep[id] = true
		}
		for _, id := range ch.Remove {
			delete(keep, id)
		}
	}
	for _, u := range ch.Units {
		keep[u.ID] = true
	}
	for _, id := range sortedKeys(keep) {
		if _, ok := changed[id]; ok {
			continue
		}
		if err := c.setOld(id); err != nil {
			return c, err
		}
	}
	for _, id := range sortedKeys(changed) {
		c.newUnits[id] = changed[id]
		c.suspects = append(c.suspects, id)
		if err := c.setNew(id); err != nil {
			return c, err
		}
	}
	return c, nil
}

func (c *candidate) claim(rel, who string) error {
	if prev, ok := c.owner[rel]; ok {
		return fmt.Errorf("apply: path %q used by both %s and %s", rel, describeOwner(prev), describeOwner(who))
	}
	return nil
}

func describeOwner(id string) string {
	if id == "" {
		return "common files"
	}
	return fmt.Sprintf("unit %q", id)
}

func (c *candidate) writeFile(rel string, data []byte, who string) error {
	if err := c.claim(rel, who); err != nil {
		return err
	}
	if err := mkdirParents(c.dir, rel, c.dirs); err != nil {
		return err
	}
	if err := writeNewFile(filepath.Join(c.dir, rel), data); err != nil {
		return err
	}
	c.owner[rel] = who
	c.written[rel] = true
	return nil
}

func (c *candidate) linkFile(rel, who string) error {
	if err := validPath(rel); err != nil {
		return fmt.Errorf("apply: live manifest: %w", err)
	}
	if err := c.claim(rel, who); err != nil {
		return err
	}
	if err := mkdirParents(c.dir, rel, c.dirs); err != nil {
		return err
	}
	copied, err := linkOrCopy(filepath.Join(c.liveDir, rel), filepath.Join(c.dir, rel))
	if err != nil {
		return err
	}
	c.owner[rel] = who
	if copied {
		c.written[rel] = true
	}
	return nil
}

func (c *candidate) removeUnit(id string) error {
	mu, ok := c.m.Units[id]
	if !ok {
		return nil
	}
	for _, rel := range mu.Files {
		if err := os.Remove(filepath.Join(c.dir, rel)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		delete(c.owner, rel)
		delete(c.written, rel)
	}
	delete(c.m.Units, id)
	return nil
}

// setOld puts the live version of unit id into the candidate, or leaves the
// unit out if it is not live. If the live files would collide with another
// unit's new files, the unit is left out as well.
func (c *candidate) setOld(id string) error {
	if err := c.removeUnit(id); err != nil {
		return err
	}
	old, ok := c.live.Units[id]
	if !ok {
		return nil
	}
	for _, rel := range old.Files {
		if _, taken := c.owner[rel]; taken {
			return nil
		}
	}
	c.m.Units[id] = manifestUnit{Hash: old.Hash, Files: append([]string(nil), old.Files...)}
	for _, rel := range old.Files {
		if err := c.linkFile(rel, id); err != nil {
			return err
		}
	}
	return nil
}

// setNew puts the new version of a changed unit into the candidate.
func (c *candidate) setNew(id string) error {
	if err := c.removeUnit(id); err != nil {
		return err
	}
	u := c.newUnits[id]
	c.m.Units[id] = manifestUnit{Hash: unitHash(u), Files: unitFiles(u)}
	for _, f := range u.Files {
		if err := c.writeFile(f.Path, f.Data, id); err != nil {
			return err
		}
	}
	return nil
}

// isNew reports whether the candidate currently holds the new version of id.
func (c *candidate) isNew(id string) bool {
	u, ok := c.newUnits[id]
	if !ok {
		return false
	}
	mu, ok := c.m.Units[id]
	return ok && mu.Hash == unitHash(u)
}

// sameAsLive reports whether the candidate has the same content as the live
// generation, in which case swapping would change nothing.
func (c *candidate) sameAsLive() bool {
	return reflect.DeepEqual(c.m.Common, c.live.Common) && reflect.DeepEqual(c.m.Units, c.live.Units)
}

// finish writes the manifest and makes the candidate durable: written files,
// every directory inside it, and the candidate directory itself. Linked files
// were made durable when their own generation went live.
func (c *candidate) finish() error {
	if err := writeManifest(c.dir, c.m); err != nil {
		return err
	}
	paths := make([]string, 0, len(c.written)+len(c.dirs)+2)
	for rel := range c.written {
		paths = append(paths, filepath.Join(c.dir, rel))
	}
	paths = append(paths, filepath.Join(c.dir, manifestName))
	if err := syncAll(paths); err != nil {
		return err
	}
	// Directories after their contents, deepest first.
	dirs := sortedKeys(c.dirs)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		if err := syncPath(filepath.Join(c.dir, d)); err != nil {
			return err
		}
	}
	if err := syncPath(c.dir); err != nil {
		return err
	}
	return syncPath(filepath.Dir(c.dir))
}
