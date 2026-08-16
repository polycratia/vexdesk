package openvex

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func statement(status Status) Statement {
	return Statement{
		Vulnerability: Vulnerability{Name: "FIXTURE-0001"},
		Products:      []Product{{ID: "pkg:npm/cog@4.0.0"}},
		Status:        status,
	}
}

func TestNewProducesAValidDocument(t *testing.T) {
	s := statement(NotAffected)
	s.Justification = VulnerableCodeNotInExecutePath

	doc, err := New("polycratia", time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), "vexdesk", []Statement{s})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Context != Context {
		t.Errorf("@context = %q, want %q", doc.Context, Context)
	}
	if doc.Timestamp != "2026-08-16T12:00:00Z" {
		t.Errorf("timestamp = %q, want RFC3339 in UTC", doc.Timestamp)
	}

	body, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("encoded document is not valid JSON: %v", err)
	}
	for _, key := range []string{"@context", "@id", "author", "timestamp", "version", "statements"} {
		if _, ok := round[key]; !ok {
			t.Errorf("encoded document is missing %q", key)
		}
	}
}

// The same decisions must produce the same document id, or every CI run looks
// like a freshly issued document.
func TestDocumentIDIsDerivedFromStatements(t *testing.T) {
	s := statement(NotAffected)
	s.Justification = ComponentNotPresent
	early := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	late := early.Add(72 * time.Hour)

	a, err := New("polycratia", early, "vexdesk", []Statement{s})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("polycratia", late, "vexdesk", []Statement{s})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Errorf("ids differ across runs: %q vs %q", a.ID, b.ID)
	}

	other := statement(UnderInvestigation)
	c, err := New("polycratia", early, "vexdesk", []Statement{other})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == c.ID {
		t.Error("different statements produced the same document id")
	}
}

func TestNotAffectedNeedsAReason(t *testing.T) {
	if _, err := New("polycratia", time.Now(), "", []Statement{statement(NotAffected)}); err == nil {
		t.Fatal("not_affected without justification or impact statement was accepted")
	}

	withImpact := statement(NotAffected)
	withImpact.ImpactStatement = "the parser is never fed untrusted input in this product"
	if _, err := New("polycratia", time.Now(), "", []Statement{withImpact}); err != nil {
		t.Errorf("not_affected with an impact statement was rejected: %v", err)
	}
}

func TestJustificationMustBeOneOfTheFiveCodes(t *testing.T) {
	s := statement(NotAffected)
	s.Justification = "we looked and it seemed fine"
	_, err := New("polycratia", time.Now(), "", []Statement{s})
	if err == nil {
		t.Fatal("free-form justification was accepted")
	}
	if !strings.Contains(err.Error(), string(VulnerableCodeNotPresent)) {
		t.Errorf("error should list the allowed codes, got: %v", err)
	}
}

func TestAffectedNeedsAnAction(t *testing.T) {
	if _, err := New("polycratia", time.Now(), "", []Statement{statement(Affected)}); err == nil {
		t.Fatal("affected without an action statement was accepted")
	}
	s := statement(Affected)
	s.ActionStatement = "upgrade to 4.1.0"
	if _, err := New("polycratia", time.Now(), "", []Statement{s}); err != nil {
		t.Errorf("affected with an action statement was rejected: %v", err)
	}
}

func TestDocumentRejectsIncompleteInput(t *testing.T) {
	valid := statement(UnderInvestigation)

	noProduct := valid
	noProduct.Products = nil
	noVuln := valid
	noVuln.Vulnerability = Vulnerability{}
	badStatus := valid
	badStatus.Status = "probably_fine"
	strayJustification := valid
	strayJustification.Justification = ComponentNotPresent

	cases := map[string]struct {
		author     string
		statements []Statement
	}{
		"no author":           {"", []Statement{valid}},
		"no statements":       {"polycratia", nil},
		"no product":          {"polycratia", []Statement{noProduct}},
		"no vulnerability":    {"polycratia", []Statement{noVuln}},
		"unknown status":      {"polycratia", []Statement{badStatus}},
		"stray justification": {"polycratia", []Statement{strayJustification}},
	}
	for name, c := range cases {
		if _, err := New(c.author, time.Now(), "", c.statements); err == nil {
			t.Errorf("%s: document was accepted, want an error", name)
		}
	}
}
