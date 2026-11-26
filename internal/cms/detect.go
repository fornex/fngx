// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"fmt"
	"sort"

	"github.com/fornex/fngx/internal/model"
)

// Confidence grades how strongly the evidence points to an application.
type Confidence uint8

// Confidence levels, weakest first.
const (
	Low Confidence = iota + 1
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return fmt.Sprintf("confidence(%d)", uint8(c))
}

// MarshalText encodes the confidence as its name.
func (c Confidence) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Candidate is one application that may be installed in the document root.
type Candidate struct {
	App        App                `json:"app"`
	Variant    string             `json:"variant,omitempty"`
	Template   model.TemplateName `json:"template"`
	Confidence Confidence         `json:"confidence"`
	// Evidence lists the marker paths that were found, relative to the
	// document root. It never contains file contents.
	Evidence []string `json:"evidence"`
	// DocrootHint is set when the application expects a subdirectory of
	// the current document root to be the document root.
	DocrootHint string `json:"docroot_hint,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Result is the outcome of one detection. It is a suggestion only (T-10).
type Result struct {
	// Candidates are sorted by confidence, then by the amount of
	// evidence, best first. Empty when nothing was recognised.
	Candidates []Candidate `json:"candidates"`
	// Ignored lists marker paths that exist but were not used: symlinks,
	// special files, unreadable files. At most maxIgnored entries.
	Ignored []Ignored `json:"ignored,omitempty"`
}

// Suggestion returns the candidate to suggest: the best one, provided
// no other candidate for a different template has the same confidence.
// ok is false when nothing was found or the result is ambiguous; the
// caller then shows all candidates and suggests nothing.
func (r Result) Suggestion() (c Candidate, ok bool) {
	if len(r.Candidates) == 0 {
		return Candidate{}, false
	}
	best := r.Candidates[0]
	for _, o := range r.Candidates[1:] {
		if o.Confidence == best.Confidence && o.Template != best.Template {
			return Candidate{}, false
		}
	}
	return best, true
}

// Detect examines the document root and returns the applications found.
// It never modifies anything.
//
// docroot must be absolute. Its last component must be a directory, not
// a symlink. The components above it are resolved by the kernel and
// therefore must not be controlled by the site owner: for a document
// root inside a client's home directory use DetectUnder.
//
// The error is non-nil only when the document root cannot be opened.
func Detect(docroot string) (Result, error) {
	t, err := openTree(docroot)
	if err != nil {
		return Result{}, err
	}
	defer t.close()
	return t.detect(), nil
}

// DetectUnder is Detect for base/rel, where base is trusted (for example
// a home directory taken from the system user database) and rel is a
// relative path controlled by the site owner (for example
// "public_html/blog"). Every component of rel is opened without
// following symlinks, so a client cannot point the scan elsewhere.
func DetectUnder(base, rel string) (Result, error) {
	t, err := openTreeUnder(base, rel)
	if err != nil {
		return Result{}, err
	}
	defer t.close()
	return t.detect(), nil
}

func (t *tree) detect() Result {
	var found []Candidate
	high := false
	// Layout-only signatures first. Content checks read files, so they
	// run only when no layout signature gave a confident answer.
	for _, withContent := range []bool{false, true} {
		if withContent && high {
			break
		}
		for i := range signatures {
			s := &signatures[i]
			if (s.content != nil) != withContent {
				continue
			}
			if c, ok := t.match(s); ok {
				found = append(found, c)
				high = high || c.Confidence == High
			}
		}
	}
	return Result{Candidates: rank(found), Ignored: t.ignored}
}

func (t *tree) present(m marker) bool {
	e := t.stat(m.path)
	if m.kind == isDir {
		return e.k == kindDir
	}
	return e.k == kindFile
}

func (t *tree) match(s *signature) (Candidate, bool) {
	evidence := make([]string, 0, len(s.required)+len(s.supporting))
	for _, m := range s.required {
		if !t.present(m) {
			return Candidate{}, false
		}
		evidence = append(evidence, m.path)
	}
	if s.content != nil {
		if !s.content.match(t.readPrefix(s.content.path, s.content.limit)) {
			return Candidate{}, false
		}
	}
	hits := 0
	for _, m := range s.supporting {
		if t.present(m) {
			hits++
			evidence = append(evidence, m.path)
		}
	}
	conf := Medium
	if s.content == nil && hits >= s.highAt {
		conf = High
	}
	if conf > s.max {
		conf = s.max
	}
	return Candidate{
		App:         s.app,
		Variant:     s.variant,
		Template:    s.template,
		Confidence:  conf,
		Evidence:    evidence,
		DocrootHint: s.docrootHint,
		Note:        s.note,
	}, true
}

// rank keeps the best candidate per (app, variant-independent template)
// and sorts the result best first.
func rank(cs []Candidate) []Candidate {
	if len(cs) == 0 {
		return nil
	}
	sort.SliceStable(cs, func(i, j int) bool { return better(cs[i], cs[j]) })
	out := cs[:0]
	seen := map[model.TemplateName]bool{}
	for _, c := range cs {
		if seen[c.Template] {
			continue
		}
		seen[c.Template] = true
		out = append(out, c)
	}
	return out
}

func better(a, b Candidate) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return len(a.Evidence) > len(b.Evidence)
}
