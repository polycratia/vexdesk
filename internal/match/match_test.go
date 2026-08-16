package match

import (
	"strings"
	"testing"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/inventory"
)

func comp(name, version, purl string) inventory.Component {
	return inventory.Component{Name: name, Version: version, PURL: purl}
}

func advisory(id, ecosystem, pkg string, ranges []osv.Range, versions []string) osv.Advisory {
	return osv.Advisory{
		ID: id,
		Affected: []osv.Affected{{
			Package:  osv.Package{Ecosystem: ecosystem, Name: pkg},
			Ranges:   ranges,
			Versions: versions,
		}},
	}
}

func semverRange(events ...osv.Event) []osv.Range {
	return []osv.Range{{Type: osv.RangeSemver, Events: events}}
}

func TestRunStatuses(t *testing.T) {
	inv := &inventory.Inventory{Components: []inventory.Component{
		comp("widget", "v1.2.3", "pkg:golang/github.com/example/widget@v1.2.3"),
		comp("sprocket", "v0.9.0", "pkg:golang/github.com/example/sprocket@v0.9.0"),
	}}
	advisories := []osv.Advisory{
		advisory("A-1", "Go", "github.com/example/widget",
			semverRange(osv.Event{Introduced: "1.0.0"}, osv.Event{Fixed: "1.3.0"}), nil),
		advisory("A-2", "Go", "github.com/example/sprocket",
			semverRange(osv.Event{Introduced: "0.1.0"}, osv.Event{Fixed: "0.5.0"}), nil),
	}

	res := Run(inv, advisories)
	if res.Checked != 2 {
		t.Errorf("checked = %d, want 2", res.Checked)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(res.Findings))
	}
	if got := res.Findings[0]; got.Advisory != "A-1" || got.Status != Affected {
		t.Errorf("widget: %s %s, want A-1 affected", got.Advisory, got.Status)
	}
	if got := res.Findings[1]; got.Status != NotAffected {
		t.Errorf("sprocket: %s, want not_affected (0.9.0 is past the 0.5.0 fix)", got.Status)
	}
	if attention := res.Attention(); len(attention) != 1 {
		t.Errorf("attention = %d findings, want only the affected one", len(attention))
	}
}

func TestRunLastAffectedBoundary(t *testing.T) {
	advisories := []osv.Advisory{advisory("A-1", "npm", "cog",
		semverRange(osv.Event{Introduced: "1.0.0"}, osv.Event{LastAffected: "1.5.0"}), nil)}

	for version, want := range map[string]Status{
		"1.5.0": Affected,    // last_affected is inclusive
		"1.5.1": NotAffected, // one patch past it
		"0.9.0": NotAffected, // before it was introduced
	} {
		inv := &inventory.Inventory{Components: []inventory.Component{
			comp("cog", version, "pkg:npm/cog@"+version)}}
		res := Run(inv, advisories)
		if len(res.Findings) != 1 {
			t.Fatalf("%s: got %d findings, want 1", version, len(res.Findings))
		}
		if got := res.Findings[0].Status; got != want {
			t.Errorf("version %s: status = %s, want %s", version, got, want)
		}
	}
}

// The rule the whole package is built around: what cannot be compared is
// reported as unknown, never quietly cleared.
func TestRunSaysUnknownRatherThanGuessing(t *testing.T) {
	cases := []struct {
		name       string
		component  inventory.Component
		advisory   osv.Advisory
		wantReason string
	}{
		{
			name:      "ecosystem range with its own ordering rules",
			component: comp("fixture", "3.1.2", "pkg:pypi/Example_Fixture@3.1.2"),
			advisory: advisory("A-1", "PyPI", "example-fixture",
				[]osv.Range{{Type: osv.RangeEcosystem, Events: []osv.Event{
					{Introduced: "3.0"}, {Fixed: "3.2"}}}}, nil),
			wantReason: "own version ordering",
		},
		{
			name:      "git range",
			component: comp("widget", "v1.2.3", "pkg:golang/github.com/example/widget@v1.2.3"),
			advisory: advisory("A-2", "Go", "github.com/example/widget",
				[]osv.Range{{Type: osv.RangeGit, Events: []osv.Event{{Introduced: "abc123"}}}}, nil),
			wantReason: "GIT range",
		},
		{
			name:       "advisory names the package but bounds nothing",
			component:  comp("cog", "1.0.0", "pkg:npm/cog@1.0.0"),
			advisory:   advisory("A-3", "npm", "cog", nil, nil),
			wantReason: "neither ranges nor versions",
		},
		{
			name:      "version that is not semver",
			component: comp("cog", "2023-08-01", "pkg:npm/cog@2023-08-01"),
			advisory: advisory("A-4", "npm", "cog",
				semverRange(osv.Event{Introduced: "1.0.0"}, osv.Event{Fixed: "2.0.0"}), nil),
			wantReason: "expected major.minor.patch",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := &inventory.Inventory{Components: []inventory.Component{c.component}}
			res := Run(inv, []osv.Advisory{c.advisory})
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(res.Findings))
			}
			f := res.Findings[0]
			if f.Status != Unknown {
				t.Fatalf("status = %s, want unknown (reason was %q)", f.Status, f.Reason)
			}
			if !strings.Contains(f.Reason, c.wantReason) {
				t.Errorf("reason = %q, want it to mention %q", f.Reason, c.wantReason)
			}
		})
	}
}

func TestRunReportsWhatItCouldNotCheck(t *testing.T) {
	inv := &inventory.Inventory{Components: []inventory.Component{
		comp("vendored", "unknown", ""),
		comp("broken", "1.0.0", "not-a-purl"),
		comp("exotic", "1.0.0", "pkg:conan/exotic@1.0.0"),
		comp("versionless", "", "pkg:npm/versionless"),
	}}
	res := Run(inv, []osv.Advisory{advisory("A-1", "npm", "cog", nil, []string{"1.0.0"})})

	if res.Checked != 0 {
		t.Errorf("checked = %d, want 0: none of these can be compared", res.Checked)
	}
	if len(res.Skipped) != 4 {
		t.Fatalf("skipped = %d, want 4", len(res.Skipped))
	}
	wants := []string{"no package URL", "purl", "not mapped", "no version"}
	for i, want := range wants {
		if !strings.Contains(res.Skipped[i].Reason, want) {
			t.Errorf("skipped[%d].Reason = %q, want it to mention %q", i, res.Skipped[i].Reason, want)
		}
	}
}

func TestRunMatchesExplicitVersionLists(t *testing.T) {
	advisories := []osv.Advisory{advisory("A-1", "npm", "cog", nil, []string{"3.9.0", "4.0.0"})}

	inv := &inventory.Inventory{Components: []inventory.Component{comp("cog", "4.0.0", "pkg:npm/cog@4.0.0")}}
	if got := Run(inv, advisories).Findings[0].Status; got != Affected {
		t.Errorf("4.0.0: status = %s, want affected", got)
	}

	inv = &inventory.Inventory{Components: []inventory.Component{comp("cog", "4.1.0", "pkg:npm/cog@4.1.0")}}
	if got := Run(inv, advisories).Findings[0].Status; got != NotAffected {
		t.Errorf("4.1.0: status = %s, want not_affected", got)
	}
}

func TestRunNormalizesPyPINames(t *testing.T) {
	inv := &inventory.Inventory{Components: []inventory.Component{
		comp("Example_Fixture", "3.1.2", "pkg:pypi/Example_Fixture@3.1.2")}}
	res := Run(inv, []osv.Advisory{advisory("A-1", "PyPI", "example-fixture", nil, []string{"3.1.2"})})
	if len(res.Findings) != 1 || res.Findings[0].Status != Affected {
		t.Errorf("findings = %+v, want Example_Fixture to match example-fixture (PEP 503)", res.Findings)
	}
}

func TestRunIgnoresOtherPackages(t *testing.T) {
	inv := &inventory.Inventory{Components: []inventory.Component{
		comp("widget", "v1.2.3", "pkg:golang/github.com/example/widget@v1.2.3")}}
	res := Run(inv, []osv.Advisory{
		advisory("A-1", "npm", "widget", semverRange(osv.Event{Introduced: "0"}), nil),
		advisory("A-2", "Go", "github.com/other/widget", semverRange(osv.Event{Introduced: "0"}), nil),
	})
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none: same name, different package", res.Findings)
	}
}
