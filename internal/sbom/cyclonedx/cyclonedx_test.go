package cyclonedx

import (
	"strings"
	"testing"
)

const minimal = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "svc", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "a", "type": "library", "name": "a", "version": "1.0.0", "purl": "pkg:npm/a@1.0.0",
     "components": [{"bom-ref": "nested", "type": "library", "name": "nested", "version": "0.1.0"}]},
    {"bom-ref": "b", "type": "library", "name": "b", "version": "2.0.0"}
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}]
}`

func TestParse(t *testing.T) {
	inv, err := Parse(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != "CycloneDX" || inv.Spec != "1.6" {
		t.Errorf("format = %s %s, want CycloneDX 1.6", inv.Format, inv.Spec)
	}
	if inv.Root.Name != "svc" || inv.Root.Version != "1.0.0" {
		t.Errorf("root = %+v, want svc 1.0.0", inv.Root)
	}
	if len(inv.Components) != 3 {
		t.Fatalf("got %d components, want 3 (nested components must be flattened)", len(inv.Components))
	}
}

func TestParseMarksDirectDependenciesOnly(t *testing.T) {
	inv, err := Parse(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	direct := inv.Direct()
	if len(direct) != 1 || direct[0].Name != "a" {
		t.Errorf("direct = %+v, want only a: b is reached through a", direct)
	}
}

func TestParseWithoutDependencyGraphClaimsNothing(t *testing.T) {
	const noGraph = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "metadata":{"component":{"bom-ref":"root","name":"svc"}},
	  "components":[{"bom-ref":"a","name":"a","version":"1.0.0"}]}`
	inv, err := Parse(strings.NewReader(noGraph))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(inv.Direct()); got != 0 {
		t.Errorf("direct = %d, want 0: a document with no graph does not say anything is direct", got)
	}
}

func TestParseRejectsForeignAndUnsupportedDocuments(t *testing.T) {
	cases := map[string]string{
		"not cyclonedx":       `{"bomFormat":"SPDX","specVersion":"1.6"}`,
		"unsupported version": `{"bomFormat":"CycloneDX","specVersion":"1.2"}`,
		"not json":            `<bom/>`,
	}
	for name, doc := range cases {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: Parse succeeded, want an error", name)
		}
	}
}
