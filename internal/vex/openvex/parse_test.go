package openvex

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseRoundTripsAnIssuedDocument(t *testing.T) {
	s := statement(NotAffected)
	s.Justification = ComponentNotPresent
	doc, err := New("polycratia", time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), "vexdesk", []Statement{s})
	if err != nil {
		t.Fatal(err)
	}
	body, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}

	back, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != doc.ID || back.Author != doc.Author || back.Timestamp != doc.Timestamp {
		t.Errorf("header = %+v, want the one that was written", back)
	}
	if len(back.Statements) != 1 || back.Statements[0].Justification != ComponentNotPresent {
		t.Errorf("statements = %+v, want the statement that was written", back.Statements)
	}
}

// A document issued elsewhere may break the rules this package enforces on
// write. Reading it is how a person finds out; refusing hides the statements
// that need fixing.
func TestParseAcceptsADocumentThatWouldNotValidate(t *testing.T) {
	const body = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
	  {"vulnerability":{"name":"FIXTURE-0001"},"products":[{"@id":"pkg:npm/cog@4.0.0"}],
	   "status":"not_affected"}]}`
	doc, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("an already-issued document was refused: %v", err)
	}
	if doc.Validate() == nil {
		t.Error("Validate accepted a not_affected statement with no justification")
	}
}

func TestParseRejectsWhatIsNotADocument(t *testing.T) {
	for name, body := range map[string]string{
		"not json":     `<vex/>`,
		"empty object": `{}`,
		"an sbom":      `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: Parse succeeded, want an error", name)
		}
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vex.json")
	const body = `{"@context":"https://openvex.dev/ns/v0.2.0","author":"polycratia","statements":[
	  {"vulnerability":{"name":"FIXTURE-0001"},"products":[{"@id":"pkg:npm/cog@4.0.0"}],
	   "status":"under_investigation"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Status != UnderInvestigation {
		t.Errorf("statements = %+v, want the one from the file", doc.Statements)
	}
	if _, err := ParseFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file was accepted")
	}
}
