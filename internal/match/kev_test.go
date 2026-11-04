package match

import (
	"testing"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/inventory"
	"github.com/polycratia/vexdesk/internal/kev"
)

const kevFixturePath = "../../testdata/kev/catalog.json"

func kevInventory() *inventory.Inventory {
	return &inventory.Inventory{Components: []inventory.Component{
		{Name: "cogwheel", Version: "4.0.0", PURL: "pkg:npm/cogwheel@4.0.0"},
		{Name: "widget", Version: "1.2.3", PURL: "pkg:golang/github.com/example/widget@v1.2.3"},
	}}
}

func kevAdvisory(id, ecosystem, name string, aliases ...string) osv.Advisory {
	return osv.Advisory{ID: id, Aliases: aliases, Affected: []osv.Affected{{
		Package: osv.Package{Ecosystem: ecosystem, Name: name},
		Ranges:  []osv.Range{{Type: osv.RangeSemver, Events: []osv.Event{{Introduced: "0"}}}},
	}}}
}

func kevAdvisories() []osv.Advisory {
	return []osv.Advisory{
		kevAdvisory("NOT-LISTED-0001", "npm", "cogwheel"),
		kevAdvisory("FIXTURE-0004", "npm", "cogwheel"),
		kevAdvisory("FIXTURE-0001", "Go", "github.com/example/widget", "CVE-FIXTURE-0001"),
	}
}

func TestMarkExploitedUsesTheAdvisoryIDAndItsAliases(t *testing.T) {
	cat, err := kev.Load(kevFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	res := Run(kevInventory(), kevAdvisories())
	if len(res.Findings) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(res.Findings), res.Findings)
	}
	res.MarkExploited(cat)

	// The listed findings come first, and among equals the order the advisory
	// set gave is kept.
	for i, want := range []string{"FIXTURE-0004", "FIXTURE-0001", "NOT-LISTED-0001"} {
		if got := res.Findings[i].Advisory; got != want {
			t.Errorf("findings[%d] = %q, want %q", i, got, want)
		}
	}

	byID := make(map[string]Finding, len(res.Findings))
	for _, f := range res.Findings {
		byID[f.Advisory] = f
	}
	if e := byID["FIXTURE-0004"].Exploited; e == nil || e.DateAdded != "2026-07-18" {
		t.Errorf("FIXTURE-0004 exploited = %+v, want the date the catalog records", e)
	}
	if e := byID["FIXTURE-0001"].Exploited; e == nil || e.ID != "CVE-FIXTURE-0001" {
		t.Errorf("FIXTURE-0001 exploited = %+v, want it found through the alias the catalog lists", e)
	} else if e.Catalog != cat.Name {
		t.Errorf("catalog = %q, want %q", e.Catalog, cat.Name)
	}
	if e := byID["NOT-LISTED-0001"].Exploited; e != nil {
		t.Errorf("NOT-LISTED-0001 exploited = %+v, want nothing: the catalog does not list it", e)
	}
	if got := res.ExploitedFindings(); len(got) != 2 {
		t.Errorf("exploited = %d findings, want the two the catalog lists", len(got))
	}
}

func TestMarkExploitedWithoutACatalogClaimsNothing(t *testing.T) {
	res := Run(kevInventory(), kevAdvisories())
	res.MarkExploited(nil)
	for _, f := range res.Findings {
		if f.Exploited != nil {
			t.Errorf("%s = %+v, want nothing inferred where no catalog was read", f.Advisory, f.Exploited)
		}
	}
	if got := res.ExploitedFindings(); len(got) != 0 {
		t.Errorf("exploited = %d findings, want none", len(got))
	}
}
