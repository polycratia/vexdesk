package vex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/polycratia/vexdesk/internal/inventory"
	"github.com/polycratia/vexdesk/internal/match"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

func finding(advisory, purl string, status match.Status) match.Finding {
	return match.Finding{
		Component: inventory.Component{Name: "cog", Version: "4.0.0", PURL: purl},
		Advisory:  advisory,
		Status:    status,
	}
}

func TestStatementsDefaultToUnderInvestigation(t *testing.T) {
	got := Statements([]match.Finding{finding("A-1", "pkg:npm/cog@4.0.0", match.Affected)}, nil)
	if len(got) != 1 {
		t.Fatalf("got %d statements, want 1", len(got))
	}
	if got[0].Status != openvex.UnderInvestigation {
		t.Errorf("status = %q, want under_investigation: nobody has decided this yet", got[0].Status)
	}
}

func TestStatementsApplyDecisions(t *testing.T) {
	findings := []match.Finding{
		finding("A-1", "pkg:npm/cog@4.0.0", match.Affected),
		finding("A-2", "pkg:npm/cog@4.0.0", match.Unknown),
	}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/cog@4.0.0",
		Status:        openvex.NotAffected,
		Justification: openvex.VulnerableCodeNotInExecutePath,
	}}

	got := Statements(findings, decisions)
	if got[0].Status != openvex.NotAffected || got[0].Justification != openvex.VulnerableCodeNotInExecutePath {
		t.Errorf("A-1 = %+v, want the recorded decision", got[0])
	}
	if got[1].Status != openvex.UnderInvestigation {
		t.Errorf("A-2 = %q, want the undecided finding left under investigation", got[1].Status)
	}
}

func TestDecisionsAreMatchedPerProduct(t *testing.T) {
	findings := []match.Finding{finding("A-1", "pkg:npm/cog@4.0.0", match.Affected)}
	decisions := []Decision{{
		Vulnerability: "A-1",
		Product:       "pkg:npm/other@1.0.0",
		Status:        openvex.NotAffected,
		Justification: openvex.ComponentNotPresent,
	}}
	if got := Statements(findings, decisions); got[0].Status != openvex.UnderInvestigation {
		t.Errorf("status = %q, want a decision about another product to be ignored", got[0].Status)
	}
}

func TestLoadDecisions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.json")
	const body = `{"decisions":[
	  {"vulnerability":"A-1","product":"pkg:npm/cog@4.0.0",
	   "status":"not_affected","justification":"component_not_present"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadDecisions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Vulnerability != "A-1" || got[0].Status != openvex.NotAffected {
		t.Errorf("decisions = %+v, want the one entry from the file", got)
	}
}

func TestLoadDecisionsRejectsEntriesThatIdentifyNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(path, []byte(`{"decisions":[{"status":"not_affected"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecisions(path); err == nil {
		t.Error("a decision without a vulnerability or product was accepted")
	}
}
