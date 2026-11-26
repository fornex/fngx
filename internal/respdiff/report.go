// SPDX-License-Identifier: GPL-3.0-or-later

package respdiff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const maxShown = 200 // characters of a value shown in the text report

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable summary. Info-level differences are
// listed only when verbose is set. Values come from the probed servers,
// so control characters are escaped before they reach a terminal.
func (r *Report) WriteText(w io.Writer, verbose bool) {
	for _, s := range []struct {
		name string
		m    SnapshotMeta
	}{{"Before", r.Before}, {"After ", r.After}} {
		fmt.Fprintf(w, "%s: server %s, taken %s, %d results, %d errors, median %d ms, tls %s\n",
			s.name, clean(s.m.Server), s.m.Started, s.m.Results, s.m.Errors, s.m.MedianMS, clean(string(s.m.Options.TLSMode)))
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes:")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  - %s\n", clean(n))
		}
	}
	c := r.Counts
	fmt.Fprintf(w, "\nCompared %d results: %d identical, %d critical, %d warning, %d info; %d only before, %d only after.\n",
		c.Compared, c.Identical, c.Critical, c.Warning, c.Info, c.OnlyBefore, c.OnlyAfter)
	hidden := 0
	var section Severity = -1
	for i := range r.Diffs {
		d := &r.Diffs[i]
		if d.Severity < SevWarning && !verbose {
			hidden++
			continue
		}
		if d.Severity != section {
			section = d.Severity
			fmt.Fprintf(w, "\n%s:\n", strings.ToUpper(section.String()))
		}
		fmt.Fprintf(w, "  %s\n", clean(d.URL()))
		for _, ch := range d.Changes {
			if ch.Severity < SevWarning && !verbose {
				continue
			}
			fmt.Fprintf(w, "    [%s] %s: %s -> %s", ch.Severity, clean(ch.Field), shown(ch.Before), shown(ch.After))
			if ch.Note != "" {
				fmt.Fprintf(w, " (%s)", clean(ch.Note))
			}
			fmt.Fprintln(w)
		}
	}
	if hidden > 0 {
		fmt.Fprintf(w, "\n%d results with info-level differences only; use -v to list them.\n", hidden)
	}
}

func shown(s string) string {
	if s == "" {
		return "(none)"
	}
	if utf8.RuneCountInString(s) > maxShown {
		s = string([]rune(s)[:maxShown]) + "..."
	}
	return clean(s)
}

// clean escapes control characters and invalid UTF-8.
func clean(s string) string {
	var sb strings.Builder
	for i, r := range s {
		switch {
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "\uFFFD"):
			fmt.Fprintf(&sb, `\x%02x`, s[i])
		case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0, r == 0x2028, r == 0x2029,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
