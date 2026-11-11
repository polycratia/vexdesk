package main

// The catalog is the only way exploitation enters the tool, so the command has
// to carry it whole: the listed findings first, the date and the catalog name
// into -json, and a file that cannot be read refused rather than read as a
// catalog listing nothing.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	kevFixtureSBOM       = "../../testdata/sbom.cyclonedx.json"
	kevFixtureAdvisories = "../../testdata/advisories"
	kevFixtureCatalog    = "../../testdata/kev/catalog.json"
)

func matchWithCatalog(t *testing.T, catalog string, extra ...string) (string, error) {
	t.Helper()
	args := []string{"match", "-sbom", kevFixtureSBOM, "-advisories", kevFixtureAdvisories,
		"-kev", catalog, "-exit-zero"}
	var buf bytes.Buffer
	err := run(append(args, extra...), &buf)
	return buf.String(), err
}

func TestMatchReportsExploitedFindingsBeforeTheVerdicts(t *testing.T) {
	out, err := matchWithCatalog(t, kevFixtureCatalog)
	if err != nil {
		t.Fatal(err)
	}
	block := strings.Index(out, "Known exploited (2):")
	if block < 0 {
		t.Fatalf("no known-exploited block in the output:\n%s", out)
	}
	if table := strings.Index(out, "STATUS"); table >= 0 && table < block {
		t.Errorf("the exploited findings come after the table of verdicts:\n%s", out)
	}
	// FIXTURE-0001 is listed under the alias the catalog names, FIXTURE-0004
	// under the advisory's own id.
	for _, want := range []string{"added 2026-05-04", "added 2026-07-18"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not carry %q:\n%s", want, out)
		}
	}
}

func TestMatchCarriesTheCatalogIntoJSON(t *testing.T) {
	out, err := matchWithCatalog(t, kevFixtureCatalog, "-json")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			Advisory  string `json:"advisory"`
			Exploited *struct {
				Catalog   string `json:"catalog"`
				DateAdded string `json:"date_added"`
			} `json:"exploited"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(got.Findings) == 0 {
		t.Fatalf("no findings in the JSON output:\n%s", out)
	}
	if got.Findings[0].Exploited == nil {
		t.Errorf("findings[0] = %s, want a listed one first", got.Findings[0].Advisory)
	}

	listed := make(map[string]string)
	for _, f := range got.Findings {
		if f.Exploited == nil {
			continue
		}
		if f.Exploited.Catalog == "" {
			t.Errorf("%s: the entry names no catalog, so the date comes from nowhere", f.Advisory)
		}
		listed[f.Advisory] = f.Exploited.DateAdded
	}
	want := map[string]string{"FIXTURE-0001": "2026-05-04", "FIXTURE-0004": "2026-07-18"}
	if !reflect.DeepEqual(listed, want) {
		t.Errorf("exploited = %v, want %v", listed, want)
	}
}

func TestMatchRefusesACatalogItCannotRead(t *testing.T) {
	out, err := matchWithCatalog(t, filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("a catalog that cannot be read was accepted as one that lists nothing")
	}
	var code exitCode
	if errors.As(err, &code) {
		t.Errorf("err = %v, want a failure rather than a gate decision", err)
	}
	if strings.Contains(out, "compared against the advisory set") {
		t.Errorf("findings were printed despite the unreadable catalog:\n%s", out)
	}
}

func TestMatchRefusesACatalogThatListsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte(`{"title":"empty","vulnerabilities":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := matchWithCatalog(t, path); err == nil {
		t.Error("an empty catalog was accepted, clearing every finding at once")
	}
}

func TestMatchWithoutACatalogInfersNothing(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"match", "-sbom", kevFixtureSBOM, "-advisories", kevFixtureAdvisories,
		"-json", "-exit-zero"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "exploited") {
		t.Errorf("the output speaks of exploitation where no catalog was read:\n%s", buf.String())
	}
}
