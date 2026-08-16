package osv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	const body = `{
	  "id": "FIXTURE-0001",
	  "aliases": ["CVE-FIXTURE-0001"],
	  "summary": "fixture",
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "github.com/example/widget"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.3.0"}]}]
	  }]
	}`
	a, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "FIXTURE-0001" || len(a.Aliases) != 1 {
		t.Errorf("advisory = %+v, want id and aliases", a)
	}
	if len(a.Affected) != 1 || a.Affected[0].Package.Name != "github.com/example/widget" {
		t.Fatalf("affected = %+v", a.Affected)
	}
	events := a.Affected[0].Ranges[0].Events
	if len(events) != 2 || events[0].Introduced != "1.0.0" || events[1].Fixed != "1.3.0" {
		t.Errorf("events = %+v, want introduced 1.0.0 and fixed 1.3.0", events)
	}
}

func TestParseRequiresAnID(t *testing.T) {
	if _, err := Parse([]byte(`{"summary":"no id"}`)); err == nil {
		t.Error("record without an id was accepted")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Error("invalid JSON was accepted")
	}
}

func TestLoadDirWalksAndSorts(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "go")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, id string) {
		if err := os.WriteFile(path, []byte(`{"id":"`+id+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "b.json"), "B-2")
	write(filepath.Join(nested, "a.json"), "A-1")
	write(filepath.Join(dir, "notes.txt"), "ignored")

	got, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d advisories, want 2 (non-JSON files are skipped)", len(got))
	}
	if got[0].ID != "A-1" || got[1].ID != "B-2" {
		t.Errorf("order = %s, %s; want a stable sort by id", got[0].ID, got[1].ID)
	}
}

func TestLoadDirFailsLoudlyOnABrokenRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Error("a broken advisory file was skipped silently")
	}
}
