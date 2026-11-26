// SPDX-License-Identifier: GPL-3.0-or-later

package render

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/fornex/fngx/internal/apply"
)

// Run "go test ./internal/render -update" to regenerate the golden files
// after an intended change, and review the diff (Q-1).
var update = flag.Bool("update", false, "rewrite golden files")

func goldenText(files []apply.File) []byte {
	var b bytes.Buffer
	for _, f := range files {
		b.WriteString("### " + f.Path + "\n")
		b.Write(f.Data)
		if len(f.Data) > 0 && f.Data[len(f.Data)-1] != '\n' {
			b.WriteString("\n")
		}
	}
	return b.Bytes()
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // test data path
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file; run with -update and review the diff.\n--- got:\n%s", path, got)
	}
}

func newRenderer(t testing.TB) *Renderer {
	t.Helper()
	r, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGoldenVhosts(t *testing.T) { // Q-1, T-1, T-6, T-7, M-1, M-6, M-7, M-9
	r := newRenderer(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, d := c.build(t, goldenEnv())
			u, err := r.Domain(&s, &d)
			if err != nil {
				t.Fatal(err)
			}
			if u.ID != string(d.Name) {
				t.Errorf("unit ID %q, want %q", u.ID, d.Name)
			}
			checkGolden(t, c.name, goldenText(u.Files))
		})
	}
}

func TestGoldenMain(t *testing.T) { // Q-1, M-1
	r := newRenderer(t)
	for _, c := range mainCases {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(goldenEnv())
			files, err := r.Common(&s)
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, c.name, goldenText(files))
		})
	}
}
