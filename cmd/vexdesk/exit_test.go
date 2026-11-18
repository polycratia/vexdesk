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

// The released document plus one claim it never made: the case that stops a
// pipeline unless the caller says otherwise.
const opensWorkDoc = `{"@context":"https://openvex.dev/ns/v0.2.0","author":"polycratia","statements":[
  {"vulnerability":{"name":"FIXTURE-0001"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"not_affected","justification":"vulnerable_code_not_in_execute_path"},
  {"vulnerability":{"name":"FIXTURE-0004"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"affected","action_statement":"upgrade cogwheel to 4.1.0"},
  {"vulnerability":{"name":"FIXTURE-0005"},"products":[{"@id":"pkg:npm/cogwheel@4.0.0"}],
   "status":"under_investigation"}]}`

func TestMatchExitZeroReportsWithoutStoppingThePipeline(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"match", "-sbom", sbom, "-advisories", advisories, "-exit-zero"}, &out); err != nil {
		t.Fatalf("err = %v, want exit 0 when the caller asked for it", err)
	}
	got := out.String()
	for _, want := range []string{"FIXTURE-0001", "affected"} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q: the findings must still be reported:\n%s", want, got)
		}
	}
}

func TestDiffExitZeroDoesNotStopThePipeline(t *testing.T) {
	dir := t.TempDir()
	before := writeDoc(t, dir, "before.json", releasedDoc)
	after := writeDoc(t, dir, "after.json", opensWorkDoc)

	var out bytes.Buffer
	if err := run([]string{"diff", before, after, "-exit-zero"}, &out); err != nil {
		t.Fatalf("err = %v, want exit 0 when the caller asked for it", err)
	}
	if !strings.Contains(out.String(), "FIXTURE-0005") {
		t.Errorf("output = %q, want the opened finding still reported", out.String())
	}
}

func TestDiffAcceptsFlagsBeforeThePaths(t *testing.T) {
	dir := t.TempDir()
	before := writeDoc(t, dir, "before.json", releasedDoc)
	after := writeDoc(t, dir, "after.json", opensWorkDoc)

	var out bytes.Buffer
	err := run([]string{"diff", "-json", before, after}, &out)
	var code exitCode
	if !errors.As(err, &code) || int(code) != 1 {
		t.Fatalf("err = %v, want exit code 1: the current document opens a finding", err)
	}

	var d struct {
		Changes []struct {
			Kind string `json:"kind"`
		} `json:"changes"`
		Unchanged int `json:"unchanged"`
	}
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatalf("-json before the paths was ignored: %v\n%s", err, out.String())
	}
	if len(d.Changes) != 1 || d.Changes[0].Kind != "new" || d.Unchanged != 2 {
		t.Errorf("diff = %+v, want one new finding beside two unchanged claims", d)
	}
}

func TestDiffRefusesWhatIsNotAVexDocument(t *testing.T) {
	dir := t.TempDir()
	before := writeDoc(t, dir, "before.json", releasedDoc)
	notVex := writeDoc(t, dir, "sbom.json", `{"bomFormat":"CycloneDX","specVersion":"1.6"}`)

	var out bytes.Buffer
	if err := run([]string{"diff", before, notVex}, &out); err == nil {
		t.Error("an SBOM was accepted as a VEX document")
	}
	out.Reset()
	if err := run([]string{"diff", before, filepath.Join(dir, "missing.json")}, &out); err == nil {
		t.Error("a document that is not there was accepted")
	}
}

func TestMatchNeedsBothInputs(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"match", "-sbom", sbom}, &out)
	if err == nil || !strings.Contains(err.Error(), "-advisories") {
		t.Errorf("err = %v, want a refusal that names the missing input", err)
	}
}

func TestVexRefusesADecisionThatSkipsItsJustification(t *testing.T) {
	dir := t.TempDir()
	decisions := writeDoc(t, dir, "decisions.json", `{"decisions":[{"vulnerability":"FIXTURE-0001",
	  "product":"pkg:golang/github.com/example/widget@v1.2.3","status":"not_affected"}]}`)

	var out bytes.Buffer
	err := run([]string{"vex", "-sbom", sbom, "-advisories", advisories,
		"-decisions", decisions, "-author", "polycratia"}, &out)
	if err == nil || !strings.Contains(err.Error(), "justification") {
		t.Errorf("err = %v, want a refusal that names the missing justification", err)
	}
}

// The whole carry-over path: the fixture decision was written for
// Example_Fixture 3.0.9 and the SBOM ships 3.1.2.
func TestVexCarriesAComponentScopedDecisionEndToEnd(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "vex.json")
	var out bytes.Buffer
	err := run([]string{"vex", "-sbom", sbom, "-advisories", advisories,
		"-decisions", "../../testdata/scanners/decisions.json",
		"-author", "polycratia", "-o", outPath}, &out)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
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

	var found bool
	for _, s := range doc.Statements {
		if s.Vulnerability.Name != "FIXTURE-0003" {
			continue
		}
		found = true
		if s.Status != "not_affected" || s.Justification != "vulnerable_code_not_present" {
			t.Errorf("FIXTURE-0003 = %+v, want the decision carried to the version in this SBOM", s)
		}
	}
	if !found {
		t.Errorf("statements = %+v, want one about FIXTURE-0003", doc.Statements)
	}
}
