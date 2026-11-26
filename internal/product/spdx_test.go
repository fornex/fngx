// SPDX-License-Identifier: GPL-3.0-or-later

package product

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spdxLine = "// SPDX-License-Identifier: GPL-3.0-or-later"

// TestSPDXHeaders checks that every Go source file in the repository
// starts with the project license identifier.
func TestSPDXHeaders(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		checked++
		data, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
		if err != nil {
			return err
		}
		first, _, _ := strings.Cut(string(data), "\n")
		if first != spdxLine {
			t.Errorf("%s: first line must be %q", path, spdxLine)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no Go files found")
	}
}
