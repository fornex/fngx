// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// BenchmarkDetect_N1 runs detection over many synthetic document roots
// with a realistic mix (mostly WordPress, some empty or static sites,
// the rest spread over the other applications) to estimate the cost of
// scanning a server with 10,000 sites (N-1). The page cache is warm, so
// this measures CPU and system call cost, not cold disk I/O.
func BenchmarkDetect_N1(b *testing.B) {
	const sites = 1000
	names := make([]string, 0, len(fixtures))
	for n := range fixtures {
		names = append(names, n)
	}
	sort.Strings(names)
	base := b.TempDir()
	roots := make([]string, sites)
	for i := range roots {
		name := "wordpress"
		if i%2 == 1 { // half WordPress, half the rest in turn
			name = names[(i/2)%len(names)]
		}
		roots[i] = filepath.Join(base, fmt.Sprintf("%04d-%s", i, name))
		if err := os.Mkdir(roots[i], 0o750); err != nil {
			b.Fatal(err)
		}
		build(b, roots[i], fixtures[name])
	}
	b.ResetTimer()
	for b.Loop() {
		for _, r := range roots {
			if _, err := Detect(r); err != nil {
				b.Fatal(err)
			}
		}
	}
	perSite := float64(b.Elapsed().Nanoseconds()) / float64(b.N) / sites
	b.ReportMetric(perSite, "ns/site")
	b.ReportMetric(perSite*10000/1e6, "ms/10k-sites")
}
