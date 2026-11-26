// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestDetect_T10_KeepsAtime checks that reading index.php does not update
// its access time (O_NOATIME), so detection leaves the tree as it was.
func TestDetect_T10_KeepsAtime(t *testing.T) {
	root := fixtureDir(t, "laravel-public")
	p := filepath.Join(root, "index.php")
	// atime older than mtime: relatime would update it on read.
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, old, old.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c, ok := detect(t, root).Suggestion(); !ok || c.App != Laravel {
		t.Fatalf("Suggestion = %+v, %v; index.php was not read", c, ok)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(st.Atim.Unix()); !got.Equal(old) {
		t.Errorf("atime = %v, want %v", got, old)
	}
}
