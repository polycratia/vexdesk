package match

import (
	"sort"

	"github.com/polycratia/vexdesk/internal/kev"
)

// MarkExploited records, against every finding the catalog lists, that the
// vulnerability is known to have been exploited, and moves those findings to
// the front of the result: a date someone wrote down outranks the order the
// advisory set happened to arrive in.
//
// A finding the catalog does not list is left exactly as it was. The catalog
// says what has been seen exploited; it never says what has not.
func (r *Result) MarkExploited(cat *kev.Catalog) {
	if cat == nil {
		return
	}
	for i, f := range r.Findings {
		ids := make([]string, 0, len(f.Aliases)+1)
		ids = append(ids, f.Advisory)
		ids = append(ids, f.Aliases...)
		if e, ok := cat.Lookup(ids...); ok {
			r.Findings[i].Exploited = &e
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Exploited != nil && r.Findings[j].Exploited == nil
	})
}

// ExploitedFindings returns the findings a known-exploited catalog listed.
func (r Result) ExploitedFindings() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Exploited != nil {
			out = append(out, f)
		}
	}
	return out
}
