package kev

import (
	"path/filepath"
	"testing"
)

const fixture = "../../testdata/kev/catalog.json"

func TestLoadReadsTheFixtureCatalog(t *testing.T) {
	cat, err := Load(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if cat.Name == "" {
		t.Error("name is empty, want the title the catalog gives itself")
	}
	if cat.Len() != 3 {
		t.Errorf("entries = %d, want the three the fixture lists", cat.Len())
	}

	e, ok := cat.Lookup("CVE-FIXTURE-0001")
	if !ok {
		t.Fatal("CVE-FIXTURE-0001 is listed in the fixture and was not found")
	}
	if e.DateAdded != "2026-05-04" {
		t.Errorf("date_added = %q, want the date the catalog records", e.DateAdded)
	}
	if e.Catalog != cat.Name {
		t.Errorf("catalog = %q, want %q: an entry says which document listed it", e.Catalog, cat.Name)
	}
}

func TestLookup(t *testing.T) {
	cat, err := Load(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cat.Lookup("cve-fixture-0001"); !ok {
		t.Error("identifiers must match regardless of case")
	}
	if e, ok := cat.Lookup("FIXTURE-0004"); !ok || e.ID != "FIXTURE-0004" {
		t.Errorf("FIXTURE-0004 = %+v, %v; want the entry listed under that id", e, ok)
	}
	if _, ok := cat.Lookup("FIXTURE-0002", "CVE-FIXTURE-0002"); ok {
		t.Error("a vulnerability the catalog does not list was reported as exploited")
	}

	var none *Catalog
	if _, ok := none.Lookup("CVE-FIXTURE-0001"); ok || none.Len() != 0 {
		t.Error("a catalog that was never read must list nothing")
	}
}

func TestParseRefusesWhatItCannotRead(t *testing.T) {
	cases := map[string]string{
		"not json":           `<catalog/>`,
		"lists nothing":      `{"title":"empty","vulnerabilities":[]}`,
		"not a catalog":      `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"entry with no id":   `{"vulnerabilities":[{"dateAdded":"2026-05-04"}]}`,
		"entry with no date": `{"vulnerabilities":[{"cveID":"CVE-FIXTURE-0001"}]}`,
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: Parse succeeded, want an error rather than a catalog with nothing in it", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing catalog was accepted as an empty one")
	}
}
