// SPDX-License-Identifier: GPL-3.0-or-later

package product

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const spdxLine = "// SPDX-License-Identifier: GPL-3.0-or-later"

// generated matches the standard marker of generated Go files
// (https://pkg.go.dev/cmd/go#hdr-Generate_Go_files_by_processing_source).
var generated = regexp.MustCompile(`(?m)^// Code generated .* DO NOT EDIT\.$`)

// TestSPDXHeaders checks that every hand-written Go source file in the
// repository starts with the project license identifier.
// It assumes this package is two directories below the repository root.
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
		if generated.Match(data) {
			return nil
		}
		first, _, _ := strings.Cut(string(data), "\n")
		if strings.TrimSuffix(first, "\r") != spdxLine {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s: first line must be %q", rel, spdxLine)
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
