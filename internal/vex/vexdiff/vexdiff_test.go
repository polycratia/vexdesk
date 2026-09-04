package vexdiff

import (
	"strings"
	"testing"

	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

func stmt(vuln, product string, status openvex.Status) openvex.Statement {
	return openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: vuln},
		Products:      []openvex.Product{{ID: product}},
		Status:        status,
	}
}

func doc(statements ...openvex.Statement) *openvex.Document {
	return &openvex.Document{Context: openvex.Context, Statements: statements}
}

func only(t *testing.T, d Diff) Change {
	t.Helper()
	if len(d.Changes) != 1 {
		t.Fatalf("got %d changes, want 1: %+v", len(d.Changes), d.Changes)
	}
	return d.Changes[0]
}

func TestCompareFindsNewAndWithdrawnClaims(t *testing.T) {
	before := doc(
		stmt("A-1", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation),
		stmt("A-2", "pkg:npm/cog@4.0.0", openvex.Affected),
	)
	after := doc(
		stmt("A-1", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation),
		stmt("A-3", "pkg:npm/cog@4.0.0", openvex.Affected),
	)

	d := Compare(before, after)
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	if len(d.Changes) != 2 {
		t.Fatalf("got %d changes, want a new finding and a withdrawal: %+v", len(d.Changes), d.Changes)
	}
	if d.Changes[0].Kind != NewFinding || d.Changes[0].Vulnerability() != "A-3" {
		t.Errorf("first change = %+v, want A-3 as a new finding", d.Changes[0])
	}
	if d.Changes[1].Kind != Withdrawn || d.Changes[1].Vulnerability() != "A-2" {
		t.Errorf("second change = %+v, want A-2 withdrawn", d.Changes[1])
	}
}

// Statement order is a serialisation detail. A diff that reports it reports
// noise, and the reader stops trusting the parts that matter.
func TestCompareIgnoresStatementOrder(t *testing.T) {
	a := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation)
	b := stmt("A-2", "pkg:npm/other@1.0.0", openvex.Fixed)

	d := Compare(doc(a, b), doc(b, a))
	if len(d.Changes) != 0 {
		t.Errorf("changes = %+v, want none: the same claims in another order", d.Changes)
	}
	if d.Unchanged != 2 {
		t.Errorf("unchanged = %d, want 2", d.Unchanged)
	}
}

func TestCompareReportsAChangedJustification(t *testing.T) {
	old := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.NotAffected)
	old.Justification = openvex.VulnerableCodeNotInExecutePath
	now := old
	now.Justification = openvex.ComponentNotPresent

	c := only(t, Compare(doc(old), doc(now)))
	if c.Kind != Rejustified {
		t.Fatalf("kind = %q, want rejustified", c.Kind)
	}
	for _, want := range []string{
		string(openvex.VulnerableCodeNotInExecutePath),
		string(openvex.ComponentNotPresent),
	} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail = %q, want it to name %q", c.Detail, want)
		}
	}
}

func TestCompareSeparatesStatusFromProse(t *testing.T) {
	old := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected)
	old.ActionStatement = "upgrade cog to 4.1.0"

	restated := old
	restated.Status = openvex.Fixed
	restated.ActionStatement = ""
	if c := only(t, Compare(doc(old), doc(restated))); c.Kind != Restated {
		t.Errorf("kind = %q, want restated when the status moves", c.Kind)
	}

	amended := old
	amended.ActionStatement = "upgrade cog to 4.2.0"
	c := only(t, Compare(doc(old), doc(amended)))
	if c.Kind != Amended {
		t.Fatalf("kind = %q, want amended when only the prose moves", c.Kind)
	}
	if !strings.Contains(c.Detail, "action statement") {
		t.Errorf("detail = %q, want it to say which prose changed", c.Detail)
	}
}

// An upgraded dependency must not read as one finding vanishing and an
// unrelated one arriving.
func TestCompareFoldsAVersionBump(t *testing.T) {
	c := only(t, Compare(
		doc(stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected)),
		doc(stmt("A-1", "pkg:npm/cog@4.1.0", openvex.Fixed)),
	))
	if c.Kind != VersionBump {
		t.Fatalf("kind = %q, want version_bump", c.Kind)
	}
	if c.Before == nil || c.After == nil {
		t.Fatalf("change = %+v, want both sides of the move", c)
	}
	for _, want := range []string{"4.0.0", "4.1.0", "fixed"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail = %q, want it to mention %q", c.Detail, want)
		}
	}
}

// Folding is only safe when the pairing is unambiguous: two arrivals for one
// departure would mean guessing which upgrade became which.
func TestCompareDoesNotGuessAmbiguousMoves(t *testing.T) {
	d := Compare(
		doc(stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected)),
		doc(
			stmt("A-1", "pkg:npm/cog@4.1.0", openvex.Affected),
			stmt("A-1", "pkg:npm/cog@4.2.0", openvex.Affected),
		),
	)
	counts := map[Kind]int{}
	for _, c := range d.Changes {
		counts[c.Kind]++
	}
	if counts[VersionBump] != 0 {
		t.Errorf("changes = %+v, want no guessed move", d.Changes)
	}
	if counts[NewFinding] != 2 || counts[Withdrawn] != 1 {
		t.Errorf("changes = %+v, want both arrivals and the departure reported as they stand", d.Changes)
	}
}

func TestNeedsAttentionIsWhatTheNewDocumentOpens(t *testing.T) {
	closed := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.NotAffected)
	closed.Justification = openvex.ComponentNotPresent
	reopened := stmt("A-1", "pkg:npm/cog@4.0.0", openvex.Affected)
	reopened.ActionStatement = "upgrade cog to 4.1.0"

	resolvedBefore := stmt("A-2", "pkg:npm/cog@4.0.0", openvex.Affected)
	resolvedBefore.ActionStatement = "upgrade cog to 4.1.0"
	resolvedAfter := stmt("A-2", "pkg:npm/cog@4.0.0", openvex.Fixed)

	d := Compare(
		doc(closed, resolvedBefore),
		doc(reopened, resolvedAfter,
			stmt("A-3", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation),
			stmt("A-4", "pkg:npm/cog@4.0.0", openvex.Fixed)),
	)

	got := map[string]bool{}
	for _, c := range d.NeedsAttention() {
		got[c.Vulnerability()] = true
	}
	if !got["A-1"] || !got["A-3"] {
		t.Errorf("attention = %v, want the reopened claim and the new open one", got)
	}
	if got["A-2"] || got["A-4"] {
		t.Errorf("attention = %v, want resolved and already-closed claims left out", got)
	}
}

func TestCompareAgainstNothing(t *testing.T) {
	d := Compare(nil, doc(stmt("A-1", "pkg:npm/cog@4.0.0", openvex.UnderInvestigation)))
	if c := only(t, d); c.Kind != NewFinding {
		t.Errorf("kind = %q, want every claim of a first document to be new", c.Kind)
	}
}
