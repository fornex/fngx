// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	manifestName    = ".manifest.json"
	manifestVersion = 1
)

// manifest records what a generation contains. Hashes let the engine reuse
// unchanged files from the live generation and limit isolation (N-4) to
// units whose content actually changed.
type manifest struct {
	Version int                     `json:"version"`
	Common  map[string]string       `json:"common"` // path -> sha256 of content
	Units   map[string]manifestUnit `json:"units"`
}

type manifestUnit struct {
	Hash  string   `json:"hash"`
	Files []string `json:"files"`
}

func newManifest() *manifest {
	return &manifest{
		Version: manifestVersion,
		Common:  map[string]string{},
		Units:   map[string]manifestUnit{},
	}
}

func fileHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// unitHash covers paths and contents, so renaming a file changes the hash.
func unitHash(u Unit) string {
	files := append([]File(nil), u.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%d:%s\x00%d:", len(f.Path), f.Path, len(f.Data))
		h.Write(f.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func unitFiles(u Unit) []string {
	paths := make([]string, 0, len(u.Files))
	for _, f := range u.Files {
		paths = append(paths, f.Path)
	}
	sort.Strings(paths)
	return paths
}

func readManifest(dir string) (*manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName)) //nolint:gosec // dir is an engine-owned generation
	if err != nil {
		return nil, err
	}
	m := newManifest()
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("apply: manifest in %s: %w", dir, err)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("apply: manifest in %s: unsupported version %d", dir, m.Version)
	}
	if m.Common == nil {
		m.Common = map[string]string{}
	}
	if m.Units == nil {
		m.Units = map[string]manifestUnit{}
	}
	return m, nil
}

func writeManifest(dir string, m *manifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeNewFile(filepath.Join(dir, manifestName), data)
}
