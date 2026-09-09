package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sbom       = "../../testdata/sbom.cyclonedx.json"
	advisories = "../../testdata/advisories"
)

func TestInventoryCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"inventory", sbom}, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"CycloneDX 1.6", "example-service 2.1.0", "widget", "direct", "transitive"} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "carry no package URL") {
		t.Errorf("the component without a purl should be called out:\n%s", got)
	}
}

// Go's flag package stops parsing at the first non-flag word, so a flag written
// after the path — the form everyone types — was being ignored.
func TestFlagsAreAcceptedAfterThePositionalArgument(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"inventory", sbom, "-json"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "{") {
		t.Errorf("-json after the path was ignored:\n%s", out.String())
	}
}

// The end-to-end shape of the tool: an SBOM and an advisory feed go in, and the
// findings that need a person come out — including the ones it cannot judge.
func TestMatchCommandReportsAffectedAndUnknown(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"match", "-sbom", sbom, "-advisories", advisories, "-json"}, &out)

	var code exitCode
	if !errors.As(err, &code) || int(code) != 1 {
		t.Fatalf("err = %v, want exit code 1 so a pipeline stops", err)
	}

	var res struct {
		Findings []struct {
			Advisory string `json:"advisory"`
			Status   string `json:"status"`
		} `json:"findings"`
		Skipped []struct {
			Reason string `json:"reason"`
		} `json:"skipped"`
		Checked int `json:"checked"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}

	want := map[string]string{
		"FIXTURE-0001": "affected",     // widget 1.2.3 is below the 1.3.0 fix
		"FIXTURE-0002": "not_affected", // sprocket 0.9.0 is past the 0.5.0 fix
		"FIXTURE-0003": "unknown",      // PyPI ECOSYSTEM range: ordering not implemented
		"FIXTURE-0004": "affected",     // cogwheel 4.0.0 is on the explicit list
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.Advisory] = f.Status
	}
	for id, status := range want {
		if got[id] != status {
			t.Errorf("%s = %q, want %q", id, got[id], status)
		}
	}
	if res.Checked != 4 {
		t.Errorf("checked = %d, want 4 identifiable components", res.Checked)
	}
	if len(res.Skipped) != 1 {
		t.Errorf("skipped = %d, want the vendored component with no purl", len(res.Skipped))
	}
}

func TestVexCommandWritesADocument(t *testing.T) {
	dir := t.TempDir()
	decisions := filepath.Join(dir, "decisions.json")
	body := `{"decisions":[{"vulnerability":"FIXTURE-0001",
	  "product":"pkg:golang/github.com/example/widget@v1.2.3",
	  "status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`
	if err := os.WriteFile(decisions, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "vex.json")

	var out bytes.Buffer
	err := run([]string{"vex", "-sbom", sbom, "-advisories", advisories,
		"-decisions", decisions, "-author", "polycratia", "-o", outPath}, &out)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Context    string `json:"@context"`
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}
	if doc.Author != "polycratia" || doc.ID == "" || !strings.HasPrefix(doc.Context, "https://openvex.dev/ns/") {
		t.Errorf("document header = %+v", doc)
	}
	if len(doc.Statements) != 3 {
		t.Fatalf("got %d statements, want 3 (two affected, one unknown)", len(doc.Statements))
	}

	byVuln := map[string]string{}
	for _, s := range doc.Statements {
		byVuln[s.Vulnerability.Name] = s.Status
	}
	if byVuln["FIXTURE-0001"] != "not_affected" {
		t.Errorf("FIXTURE-0001 = %q, want the recorded decision", byVuln["FIXTURE-0001"])
	}
	if byVuln["FIXTURE-0004"] != "under_investigation" {
		t.Errorf("FIXTURE-0004 = %q, want under_investigation for an undecided finding", byVuln["FIXTURE-0004"])
	}
}

func TestVexCommandRefusesAnAnonymousDocument(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"vex", "-sbom", sbom, "-advisories", advisories}, &out)
	if err == nil || !strings.Contains(err.Error(), "author") {
		t.Errorf("err = %v, want a refusal that names the missing author", err)
	}
}

func writeDoc(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const releasedDoc = `{"@context":"https://openvex.dev/ns/v0.2.0","author":"polycratia","statements":[
  {"vulnerability":{"name":"FIXTURE-0001"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"not_affected","justification":"vulnerable_code_not_in_execute_path"},
  {"vulnerability":{"name":"FIXTURE-0004"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"affected","action_statement":"upgrade cogwheel to 4.1.0"}]}`

// The question the customer asks about a new release: what turned up, what went
// away, and which judgement was rewritten.
func TestDiffCommandReportsWhatChanged(t *testing.T) {
	dir := t.TempDir()
	before := writeDoc(t, dir, "before.json", releasedDoc)
	after := writeDoc(t, dir, "after.json", `{"@context":"https://openvex.dev/ns/v0.2.0","author":"polycratia","statements":[
  {"vulnerability":{"name":"FIXTURE-0001"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"not_affected","justification":"component_not_present"},
  {"vulnerability":{"name":"FIXTURE-0004"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"fixed"},
  {"vulnerability":{"name":"FIXTURE-0005"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"under_investigation"}]}`)

	var out bytes.Buffer
	err := run([]string{"diff", before, after, "-json"}, &out)

	var code exitCode
	if !errors.As(err, &code) || int(code) != 1 {
		t.Fatalf("err = %v, want exit code 1: the current document opens a finding", err)
	}

	type claim struct {
		Vulnerability string `json:"vulnerability"`
		Product       string `json:"product"`
	}
	var d struct {
		Changes []struct {
			Kind   string `json:"kind"`
			Before *claim `json:"before"`
			After  *claim `json:"after"`
			Detail string `json:"detail"`
		} `json:"changes"`
		Unchanged int `json:"unchanged"`
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}

	got := map[string]string{}
	for _, c := range d.Changes {
		name := ""
		if c.After != nil {
			name = c.After.Vulnerability
		} else if c.Before != nil {
			name = c.Before.Vulnerability
		}
		got[name] = c.Kind
	}
	want := map[string]string{
		"FIXTURE-0005": "new",
		"FIXTURE-0004": "restated",
		"FIXTURE-0001": "rejustified",
	}
	for id, kind := range want {
		if got[id] != kind {
			t.Errorf("%s = %q, want %q", id, got[id], kind)
		}
	}
	if d.Unchanged != 0 {
		t.Errorf("unchanged = %d, want 0: every claim moved", d.Unchanged)
	}
}

// A release that changed nothing must not stop a pipeline, and must say so in
// words rather than printing an empty table.
func TestDiffCommandOfTwoIdenticalDocuments(t *testing.T) {
	dir := t.TempDir()
	before := writeDoc(t, dir, "before.json", releasedDoc)
	after := writeDoc(t, dir, "after.json", releasedDoc)

	var out bytes.Buffer
	if err := run([]string{"diff", before, after}, &out); err != nil {
		t.Fatalf("err = %v, want a clean exit", err)
	}
	if !strings.Contains(out.String(), "same claims") {
		t.Errorf("output = %q, want it to say the documents agree", out.String())
	}
}

func TestDiffCommandNeedsTwoDocuments(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"diff", "only-one.json"}, &out); err == nil {
		t.Error("diff with a single document was accepted")
	}
}

func TestUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"frobnicate"}, &out); err == nil {
		t.Error("unknown command was accepted")
	}
}
