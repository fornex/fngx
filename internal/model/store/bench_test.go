// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/fornex/fngx/internal/model"
)

const (
	benchDomains = 10000 // N-1: upper bound named by the customer
	benchUsers   = 1000
)

func benchOwner(i int) model.User { return model.User(fmt.Sprintf("user%04d", i%benchUsers)) }

func benchDomain(i int) model.Domain { return model.Domain(fmt.Sprintf("site%05d.example.com", i)) }

// benchWrite writes a file without fsync to keep the setup fast; what
// is measured is reading, not writing.
func benchWrite(b *testing.B, p string, st model.Settings) {
	b.Helper()
	data, err := model.MarshalSettings(st)
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(p, data, filePerm); err != nil {
		b.Fatal(err)
	}
}

// setupBench writes a server file, benchUsers user files and benchDomains
// domain files with a realistic mix of overrides.
func setupBench(b *testing.B) (*Store, map[model.Domain]model.User) {
	b.Helper()
	s := newStore(b)
	srv := model.Server{
		Defaults: model.Settings{PHPVersion: ptr(model.PHPVersion("ea-php83"))},
		Access:   map[model.Field]model.Access{model.FieldCache: model.AccessClient},
	}
	if err := s.SaveServer(srv); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < benchUsers; i++ {
		st := model.Settings{}
		if i%3 == 0 {
			st.PHPVersion = ptr(model.PHPVersion("ea-php82"))
		}
		benchWrite(b, filepath.Join(s.users, string(benchOwner(i))), st)
	}
	modes := []model.Mode{model.ModeProxy, model.ModeHybrid, model.ModeNginx}
	owners := make(map[model.Domain]model.User, benchDomains)
	for i := 0; i < benchDomains; i++ {
		d := benchDomain(i)
		st := model.Settings{Mode: ptr(modes[i%3])}
		if i%2 == 0 {
			st.Cache = ptr(true)
		}
		if i%5 == 0 {
			st.AppTemplate = ptr(model.TemplateName("wordpress"))
		}
		benchWrite(b, filepath.Join(s.domains, string(d)), st)
		owners[d] = benchOwner(i)
	}
	return s, owners
}

// BenchmarkLoadResolve10k measures a full read of the settings of a
// 10,000-domain server and resolution of every domain (N-1). One
// iteration is the whole server, not one domain. Files are in the page
// cache after the first iteration.
func BenchmarkLoadResolve10k(b *testing.B) {
	s, owners := setupBench(b)
	b.ReportAllocs()
	for b.Loop() {
		srv, err := s.LoadServer()
		if err != nil {
			b.Fatal(err)
		}
		users, err := s.LoadAllUsers()
		if err != nil {
			b.Fatal(err)
		}
		domains, err := s.LoadAllDomains()
		if err != nil {
			b.Fatal(err)
		}
		if len(domains) != benchDomains {
			b.Fatalf("loaded %d domains", len(domains))
		}
		for d, st := range domains {
			_ = model.Resolve(srv, users[owners[d]], st)
		}
	}
}

// BenchmarkLoadResolveOne measures the single-domain path used when one
// domain changes.
func BenchmarkLoadResolveOne(b *testing.B) {
	s, owners := setupBench(b)
	d := benchDomain(4242)
	b.ReportAllocs()
	for b.Loop() {
		srv, err := s.LoadServer()
		if err != nil {
			b.Fatal(err)
		}
		u, err := s.LoadUser(owners[d])
		if err != nil {
			b.Fatal(err)
		}
		st, err := s.LoadDomain(d)
		if err != nil {
			b.Fatal(err)
		}
		_ = model.Resolve(srv, u, st)
	}
}

// BenchmarkInitExistingSites10k measures the M-5 first-install path on
// 10,000 domains: one fsynced atomic write per domain. Run it with
// -benchtime=1x; it is dominated by fsync latency of the disk.
func BenchmarkInitExistingSites10k(b *testing.B) {
	domains := make([]model.Domain, benchDomains)
	for i := range domains {
		domains[i] = benchDomain(i)
	}
	for b.Loop() {
		b.StopTimer()
		s := newStore(b)
		b.StartTimer()
		n, err := s.InitExistingSites(model.Server{}, domains)
		if err != nil || n != benchDomains {
			b.Fatalf("written %d: %v", n, err)
		}
	}
}
