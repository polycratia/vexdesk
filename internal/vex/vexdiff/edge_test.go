package vexdiff

import (
	"strings"
	"testing"

	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

func kinds(d Diff) map[Kind]int {
	out := map[Kind]int{}
	for _, c := range d.Changes {
		out[c.Kind]++
	}
	return out
}

// A statement may name several products. The unit a reader compares is one
// vulnerability against one product, so such a statement is several claims.
func TestCompareReadsOneStatementAsOneClaimPerProduct(t *testing.T) {
	multi := openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "A-1"},
		Products:      []openvex.Product{{ID: "pkg:npm/cog@4.0.0"}, {ID: "pkg:npm/other@1.0.0"}},
		Status:        openvex.Fixed,
	}

	d := Compare(doc(), doc(multi))
	if got := kinds(d)[NewFinding]; got != 2 {
		t.Fatalf("changes = %+v, want one new claim per product", d.Changes)
	}
	named := map[string]bool{}
	for _, c := range d.Changes {
		named[c.Product()] = true
	}
	for _, want := range []string{"pkg:npm/cog@4.0.0", "pkg:npm/other@1.0.0"} {
		if !named[want] {
			t.Errorf("products = %v, want %q among them", named, want)
		}
	}
}

func TestCompareOfTwoDocumentsThatClaimNothing(t *testing.T) {
	d := Compare(nil, nil)
	if len(d.Changes) != 0 || d.Unchanged != 0 {
		t.Errorf("diff = %+v, want nothing reported", d)
	}
	if got := d.NeedsAttention(); len(got) != 0 {
		t.Errorf("attention = %+v, want nothing to do", got)
	}
}

// Folding a move needs the component's identity, and only a versioned package
// URL carries one. Anything else is reported as it stands rather than paired
// up on a guess about what the string means.
func TestCompareDoesNotFoldProductsThatAreNotVersionedPackageURLs(t *testing.T) {
	d := Compare(
		doc(stmt("A-1", "example-service", openvex.Affected)),
		doc(stmt("A-1", "example-service-next", openvex.Affected)),
	)
	got := kinds(d)
	if got[VersionBump] != 0 {
		t.Errorf("changes = %+v, want no move guessed from product strings", d.Changes)
	}
	if got[Withdrawn] != 1 || got[NewFinding] != 1 {
		t.Errorf("changes = %+v, want the departure and the arrival reported as they stand", d.Changes)
	}
}

// Ambiguity cuts both ways: two departures for one arrival is as much a guess
// as one departure for two arrivals.
func TestCompareDoesNotFoldTwoDeparturesIntoOneArrival(t *testing.T) {
	d := Compare(
		doc(
			stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected),
			stmt("A-1", "pkg:npm/cog@4.1.0", openvex.Affected),
		),
		doc(stmt("A-1", "pkg:npm/cog@4.2.0", openvex.Affected)),
	)
	got := kinds(d)
	if got[VersionBump] != 0 || got[Withdrawn] != 2 || got[NewFinding] != 1 {
		t.Errorf("changes = %+v, want both departures and the arrival reported as they stand", d.Changes)
	}
}

func TestCompareFoldsEachVulnerabilitySeparately(t *testing.T) {
	d := Compare(
		doc(
			stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected),
			stmt("A-2", "pkg:npm/cog@4.0.0", openvex.Affected),
		),
		doc(
			stmt("A-1", "pkg:npm/cog@4.1.0", openvex.Affected),
			stmt("A-2", "pkg:npm/cog@4.1.0", openvex.Affected),
		),
	)
	if got := kinds(d)[VersionBump]; got != 2 {
		t.Errorf("changes = %+v, want one move per vulnerability", d.Changes)
	}
}

func TestCompareNamesADroppedJustification(t *testing.T) {
	old := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.NotAffected)
	old.Justification = openvex.ComponentNotPresent
	now := old
	now.Justification = ""

	c := only(t, Compare(doc(old), doc(now)))
	if c.Kind != Rejustified {
		t.Fatalf("kind = %q, want rejustified", c.Kind)
	}
	for _, want := range []string{string(openvex.ComponentNotPresent), "none"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail = %q, want it to name %q", c.Detail, want)
		}
	}
}

func TestCompareNamesWhichProseMoved(t *testing.T) {
	base := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.NotAffected)
	base.Justification = openvex.ComponentNotPresent

	withImpact := base
	withImpact.ImpactStatement = "the admin importer is not built into this image"
	rewritten := base
	rewritten.ImpactStatement = "the affected module is vendored but never loaded"

	bothBefore := withImpact
	bothBefore.ActionStatement = "watch for a fix"
	bothAfter := rewritten
	bothAfter.ActionStatement = "no action: the module is unreachable"

	cases := []struct {
		name          string
		before, after openvex.Statement
		want          []string
	}{
		{"added", base, withImpact, []string{"impact statement added"}},
		{"dropped", withImpact, base, []string{"impact statement dropped"}},
		{"rewritten", withImpact, rewritten, []string{"impact statement rewritten"}},
		{"both", bothBefore, bothAfter,
			[]string{"impact statement rewritten", "action statement rewritten", "; "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := only(t, Compare(doc(tc.before), doc(tc.after)))
			if c.Kind != Amended {
				t.Fatalf("kind = %q, want amended: only the prose moved", c.Kind)
			}
			for _, want := range tc.want {
				if !strings.Contains(c.Detail, want) {
					t.Errorf("detail = %q, want it to contain %q", c.Detail, want)
				}
			}
		})
	}
}

// A folded move is still a claim, and an upgrade that reopens one is work.
func TestNeedsAttentionFollowsAClaimAcrossAVersionBump(t *testing.T) {
	reopened := stmt("A-1", "pkg:npm/cog@4.1.0", openvex.Affected)
	reopened.ActionStatement = "upgrade cog to 4.2.0"

	d := Compare(doc(stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Fixed)), doc(reopened))
	if c := only(t, d); c.Kind != VersionBump {
		t.Fatalf("kind = %q, want version_bump", c.Kind)
	}
	if got := d.NeedsAttention(); len(got) != 1 {
		t.Errorf("attention = %+v, want the upgrade that reopened the claim", got)
	}

	closing := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected)
	closing.ActionStatement = "upgrade cog to 4.1.0"
	closed := Compare(doc(closing), doc(stmt("A-1", "pkg:npm/cog@4.1.0", openvex.Fixed)))
	if got := closed.NeedsAttention(); len(got) != 0 {
		t.Errorf("attention = %+v, want an upgrade that closed the claim left out", got)
	}
}

func TestNeedsAttentionLeavesOutWithdrawnClaims(t *testing.T) {
	open := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected)
	open.ActionStatement = "upgrade cog to 4.1.0"

	d := Compare(doc(open), doc(stmt("A-2", "pkg:npm/other@1.0.0", openvex.Fixed)))
	if got := kinds(d); got[Withdrawn] != 1 || got[NewFinding] != 1 {
		t.Fatalf("changes = %+v, want a withdrawal and an arrival", d.Changes)
	}
	if got := d.NeedsAttention(); len(got) != 0 {
		t.Errorf("attention = %+v, want a claim that is gone and a closed arrival to ask nothing", got)
	}
}

// Arrivals first, departures last, alphabetical within a kind: two runs over
// the same documents read the same way.
func TestChangesAreOrderedByKindThenVulnerability(t *testing.T) {
	restatedBefore := stmt("B-1", "pkg:npm/cog@4.0.0", openvex.Affected)
	restatedBefore.ActionStatement = "upgrade cog to 4.1.0"

	d := Compare(
		doc(restatedBefore, stmt("C-1", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation)),
		doc(
			stmt("B-1", "pkg:npm/cog@4.0.0", openvex.Fixed),
			stmt("A-2", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation),
			stmt("A-1", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation),
		),
	)

	var got []string
	for _, c := range d.Changes {
		got = append(got, string(c.Kind)+" "+c.Vulnerability())
	}
	want := []string{"new A-1", "new A-2", "restated B-1", "withdrawn C-1"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("changes = %v, want %v", got, want)
	}
}
