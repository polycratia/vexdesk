package vex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polycratia/vexdesk/internal/match"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

func TestCarriedDecisionAnswersForEveryVersionInOneScan(t *testing.T) {
	findings := []match.Finding{
		finding("A-1", "pkg:npm/cog@4.1.0", match.Affected),
		finding("A-1", "pkg:npm/cog@4.2.0", match.Unknown),
	}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		AppliesTo:     ScopeComponent,
		Status:        openvex.NotAffected,
		Justification: openvex.VulnerableCodeNotPresent,
	}}

	got := Statements(findings, decisions)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want one per finding", len(got))
	}
	for i, product := range []string{"pkg:npm/cog@4.1.0", "pkg:npm/cog@4.2.0"} {
		if got[i].Status != openvex.NotAffected {
			t.Errorf("%s = %q, want the component-wide decision applied", product, got[i].Status)
		}
		if len(got[i].Products) != 1 || got[i].Products[0].ID != product {
			t.Errorf("products = %+v, want the version found in this scan, not the one the rule was written for",
				got[i].Products)
		}
	}
}

// Reversibility cannot depend on where in the file the two entries sit.
func TestAVersionDecisionWinsHoweverTheFileIsOrdered(t *testing.T) {
	findings := []match.Finding{finding("A-1", "pkg:npm/cog@4.1.0", match.Affected)}
	carried := Decision{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		AppliesTo:     ScopeComponent,
		Status:        openvex.NotAffected,
		Justification: openvex.VulnerableCodeNotInExecutePath,
	}
	exact := Decision{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.1.0",
		Status:        openvex.Affected,
		Action:        "upgrade cog to 4.2.0",
	}

	for _, order := range [][]Decision{{carried, exact}, {exact, carried}} {
		got := Statements(findings, order)
		if got[0].Status != openvex.Affected || got[0].ActionStatement == "" {
			t.Errorf("statement = %+v, want the decision written for this version to win", got[0])
		}
	}
}

func TestComponentScopeStillAnswersForItsOwnVersion(t *testing.T) {
	findings := []match.Finding{finding("A-1", "pkg:npm/cog@4.0.0", match.Affected)}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		AppliesTo:     ScopeComponent,
		Status:        openvex.NotAffected,
		Justification: openvex.ComponentNotPresent,
	}}
	if got := Statements(findings, decisions); got[0].Status != openvex.NotAffected {
		t.Errorf("status = %q, want a widened rule to keep answering for the version it was written for",
			got[0].Status)
	}
}

// Two ecosystems can spell a component the same way and mean different
// software, so the identity a rule travels on includes the ecosystem.
func TestCarriedRulesDoNotCrossEcosystems(t *testing.T) {
	findings := []match.Finding{finding("A-1", "pkg:golang/github.com/example/cog@4.1.0", match.Affected)}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		AppliesTo:     ScopeComponent,
		Status:        openvex.NotAffected,
		Justification: openvex.ComponentNotPresent,
	}}
	if got := Statements(findings, decisions); got[0].Status != openvex.UnderInvestigation {
		t.Errorf("status = %q, want a rule about an npm package to stay out of the Go one", got[0].Status)
	}
}

// The carry-over note lands in the impact statement, and the writer refuses a
// not_affected statement whose prose stands in for a justification. The two
// together must still produce a document.
func TestCarriedDecisionsProduceADocumentTheWriterAccepts(t *testing.T) {
	findings := []match.Finding{
		finding("A-1", "pkg:npm/cog@4.1.0", match.Affected),
		finding("A-2", "pkg:npm/cog@4.1.0", match.Unknown),
	}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		AppliesTo:     ScopeComponent,
		Status:        openvex.NotAffected,
		Justification: openvex.VulnerableCodeNotInExecutePath,
	}}

	doc, err := openvex.New("polycratia", time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		"vexdesk", Statements(findings, decisions))
	if err != nil {
		t.Fatalf("a carried decision produced a document the writer refuses: %v", err)
	}
	if len(doc.Statements) != 2 {
		t.Errorf("statements = %+v, want one per finding", doc.Statements)
	}
}

func TestADecisionThatSkipsItsJustificationNeverReachesADocument(t *testing.T) {
	findings := []match.Finding{finding("A-1", "pkg:npm/cog@4.0.0", match.Affected)}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		Status:        openvex.NotAffected,
	}}

	_, err := openvex.New("polycratia", time.Now(), "vexdesk", Statements(findings, decisions))
	if err == nil || !strings.Contains(err.Error(), "justification") {
		t.Errorf("err = %v, want a refusal that names the missing justification", err)
	}
}

// Writing the default out loud must behave exactly like leaving it off.
func TestLoadDecisionsReadsTheVersionScopeWrittenOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	const body = `{"decisions":[
	  {"vulnerability":"A-1","product":"pkg:npm/cog@4.0.0","applies_to":"version",
	   "status":"not_affected","justification":"component_not_present"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadDecisions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("decisions = %+v, want the one entry from the file", got)
	}
	findings := []match.Finding{finding("A-1", "pkg:npm/cog@4.1.0", match.Affected)}
	if st := Statements(findings, got); st[0].Status != openvex.UnderInvestigation {
		t.Errorf("status = %q, want no carry-over from a decision scoped to its version", st[0].Status)
	}
}

func TestLoadDecisionsRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadDecisions(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing decisions file was accepted as an empty one")
	}

	path := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(path, []byte(`<decisions/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecisions(path); err == nil {
		t.Error("a file that is not JSON was accepted")
	}
}
