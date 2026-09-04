// Package vexdiff compares two OpenVEX documents and says what changed.
//
// The question a customer asks on receiving a new release is not "what does
// this document contain" but "what is different since the last one": what
// turned up, what went away, and which judgements were rewritten. A textual
// diff answers none of that — reordering statements changes every line while
// changing no claim, and an upgraded dependency reads as one finding vanishing
// and an unrelated one arriving. So the comparison is made claim by claim, one
// vulnerability against one product, and every difference is named.
package vexdiff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/polycratia/vexdesk/internal/inventory"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

// Kind is what happened to one claim between the two documents.
type Kind string

const (
	// NewFinding: the older document says nothing about this pair at all.
	NewFinding Kind = "new"
	// Restated: the same claim carries a different status.
	Restated Kind = "restated"
	// Rejustified: same status, different justification code — the conclusion
	// held but the reason for it did not, which is the change a reviewer of a
	// not_affected statement most needs to see.
	Rejustified Kind = "rejustified"
	// Amended: only the prose moved; status and code are unchanged.
	Amended Kind = "amended"
	// VersionBump: the same component is claimed at a different version,
	// reported as one move rather than a withdrawal and an arrival.
	VersionBump Kind = "version_bump"
	// Withdrawn: the older document made this claim and the newer one does not.
	Withdrawn Kind = "withdrawn"
)

var kindRank = map[Kind]int{
	NewFinding:  0,
	Restated:    1,
	Rejustified: 2,
	Amended:     3,
	VersionBump: 4,
	Withdrawn:   5,
}

// Claim is one statement flattened to a single product: the unit a reader
// actually compares.
type Claim struct {
	Vulnerability string                `json:"vulnerability"`
	Product       string                `json:"product"`
	Status        openvex.Status        `json:"status"`
	Justification openvex.Justification `json:"justification,omitempty"`
	Impact        string                `json:"impact_statement,omitempty"`
	Action        string                `json:"action_statement,omitempty"`
}

// Change is one difference between the documents. Before is nil for a new
// finding and After is nil for a withdrawal.
type Change struct {
	Kind   Kind   `json:"kind"`
	Before *Claim `json:"before,omitempty"`
	After  *Claim `json:"after,omitempty"`
	Detail string `json:"detail"`
}

// Vulnerability names the flaw this change is about.
func (c Change) Vulnerability() string {
	if c.After != nil {
		return c.After.Vulnerability
	}
	if c.Before != nil {
		return c.Before.Vulnerability
	}
	return ""
}

// Product is the product the change lands on: the current one where there is
// one, otherwise the product that was dropped.
func (c Change) Product() string {
	if c.After != nil {
		return c.After.Product
	}
	if c.Before != nil {
		return c.Before.Product
	}
	return ""
}

// Diff is the whole comparison.
type Diff struct {
	Changes []Change `json:"changes"`
	// Unchanged counts claims both documents make in the same words.
	Unchanged int `json:"unchanged"`
}

// NeedsAttention returns the changes that open work: a claim that is affected
// or under investigation now and was not before. The rest of the diff is worth
// reading, but only these are a reason to do something.
func (d Diff) NeedsAttention() []Change {
	var out []Change
	for _, c := range d.Changes {
		if c.After == nil || !isOpen(c.After.Status) {
			continue
		}
		if c.Before != nil && isOpen(c.Before.Status) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func isOpen(s openvex.Status) bool {
	return s == openvex.Affected || s == openvex.UnderInvestigation
}

type claimKey = [2]string

// Compare reads both documents as sets of claims and reports every difference.
// A nil document is read as one that makes no claims, so a first release diffs
// cleanly against nothing.
func Compare(before, after *openvex.Document) Diff {
	was := claims(before)
	now := claims(after)

	keys := make([]claimKey, 0, len(was)+len(now))
	for k := range was {
		keys = append(keys, k)
	}
	for k := range now {
		if _, ok := was[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})

	var d Diff
	var gone, arrived []Claim
	for _, k := range keys {
		b, existed := was[k]
		a, exists := now[k]
		switch {
		case !existed:
			arrived = append(arrived, a)
		case !exists:
			gone = append(gone, b)
		default:
			if c, changed := compareClaim(b, a); changed {
				d.Changes = append(d.Changes, c)
				continue
			}
			d.Unchanged++
		}
	}

	d.Changes = append(d.Changes, foldVersionBumps(gone, arrived)...)
	sortChanges(d.Changes)
	return d
}

func claims(doc *openvex.Document) map[claimKey]Claim {
	out := map[claimKey]Claim{}
	if doc == nil {
		return out
	}
	for _, s := range doc.Statements {
		for _, p := range s.Products {
			c := Claim{
				Vulnerability: s.Vulnerability.Name,
				Product:       p.ID,
				Status:        s.Status,
				Justification: s.Justification,
				Impact:        s.ImpactStatement,
				Action:        s.ActionStatement,
			}
			out[claimKey{c.Vulnerability, c.Product}] = c
		}
	}
	return out
}

func compareClaim(before, after Claim) (Change, bool) {
	c := Change{Before: &before, After: &after}
	switch {
	case before.Status != after.Status:
		c.Kind = Restated
		c.Detail = fmt.Sprintf("%s → %s", before.Status, after.Status)
	case before.Justification != after.Justification:
		c.Kind = Rejustified
		c.Detail = fmt.Sprintf("justification %s → %s",
			orNone(string(before.Justification)), orNone(string(after.Justification)))
	case before.Impact != after.Impact || before.Action != after.Action:
		c.Kind = Amended
		c.Detail = amendment(before, after)
	default:
		return Change{}, false
	}
	return c, true
}

func amendment(before, after Claim) string {
	var parts []string
	if before.Impact != after.Impact {
		parts = append(parts, prose("impact statement", before.Impact, after.Impact))
	}
	if before.Action != after.Action {
		parts = append(parts, prose("action statement", before.Action, after.Action))
	}
	return strings.Join(parts, "; ")
}

func prose(field, was, now string) string {
	switch {
	case strings.TrimSpace(was) == "":
		return field + " added"
	case strings.TrimSpace(now) == "":
		return field + " dropped"
	default:
		return field + " rewritten"
	}
}

// foldVersionBumps pairs a departure with an arrival when they are the same
// component at a different version, so an upgrade reads as one move.
func foldVersionBumps(gone, arrived []Claim) []Change {
	departures := indexByComponent(gone)
	arrivals := indexByComponent(arrived)

	foldedGone := map[int]bool{}
	foldedArrived := map[int]bool{}
	var out []Change

	for key, from := range departures {
		to, ok := arrivals[key]
		// With more than one candidate on either side the pairing is a guess,
		// and a wrong one invents a move nobody made. Both sides are reported
		// as they stand instead.
		if !ok || len(from) != 1 || len(to) != 1 {
			continue
		}
		b, a := gone[from[0]], arrived[to[0]]
		foldedGone[from[0]] = true
		foldedArrived[to[0]] = true

		detail := fmt.Sprintf("version %s → %s", version(b.Product), version(a.Product))
		if b.Status != a.Status {
			detail += fmt.Sprintf(", %s → %s", b.Status, a.Status)
		}
		out = append(out, Change{Kind: VersionBump, Before: &b, After: &a, Detail: detail})
	}

	for i := range gone {
		if foldedGone[i] {
			continue
		}
		b := gone[i]
		out = append(out, Change{Kind: Withdrawn, Before: &b,
			Detail: "no longer stated; was " + describe(b)})
	}
	for i := range arrived {
		if foldedArrived[i] {
			continue
		}
		a := arrived[i]
		out = append(out, Change{Kind: NewFinding, After: &a, Detail: describe(a)})
	}
	return out
}

func indexByComponent(cs []Claim) map[claimKey][]int {
	out := map[claimKey][]int{}
	for i, c := range cs {
		component, ok := componentOf(c.Product)
		if !ok {
			continue
		}
		key := claimKey{c.Vulnerability, component}
		out[key] = append(out[key], i)
	}
	return out
}

// componentOf strips the version from a package URL, leaving the identity of
// the component. A product identifier that is not a versioned package URL
// cannot be recognised across versions and is left out of the folding.
func componentOf(product string) (string, bool) {
	p, err := inventory.ParsePURL(product)
	if err != nil || p.Version == "" {
		return "", false
	}
	p.Version = ""
	return p.String(), true
}

func version(product string) string {
	p, err := inventory.ParsePURL(product)
	if err != nil || p.Version == "" {
		return product
	}
	return p.Version
}

func describe(c Claim) string {
	if c.Justification != "" {
		return fmt.Sprintf("%s (%s)", c.Status, c.Justification)
	}
	return string(c.Status)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func sortChanges(changes []Change) {
	sort.SliceStable(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if kindRank[a.Kind] != kindRank[b.Kind] {
			return kindRank[a.Kind] < kindRank[b.Kind]
		}
		if a.Vulnerability() != b.Vulnerability() {
			return a.Vulnerability() < b.Vulnerability()
		}
		return a.Product() < b.Product()
	})
}
