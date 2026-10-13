package match

import (
	"strings"
	"testing"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/inventory"
)

func foldInventory() *inventory.Inventory {
	return &inventory.Inventory{Components: []inventory.Component{{
		Name:    "cogwheel",
		Version: "4.0.0",
		PURL:    "pkg:npm/cogwheel@4.0.0",
	}}}
}

func foldEntry(name, rangeType string, events ...osv.Event) osv.Affected {
	return osv.Affected{
		Package: osv.Package{Ecosystem: "npm", Name: name},
		Ranges:  []osv.Range{{Type: rangeType, Events: events}},
	}
}

var (
	foldHit     = foldEntry("cogwheel", osv.RangeSemver, osv.Event{Introduced: "4.0.0"}, osv.Event{Fixed: "4.2.0"})
	foldMiss    = foldEntry("cogwheel", osv.RangeSemver, osv.Event{Introduced: "5.0.0"})
	foldGit     = foldEntry("cogwheel", osv.RangeGit, osv.Event{Introduced: "0"})
	foldUnknown = foldEntry("cogwheel", "HASH", osv.Event{Introduced: "0"})
)

// One advisory naming one component is one claim. Two affected entries for the
// same package used to produce two findings, hence two statements for one
// claim, which a claim-by-claim reader collapses without a word.
func TestRunFoldsAffectedEntriesIntoOneFinding(t *testing.T) {
	cases := []struct {
		name    string
		entries []osv.Affected
		want    Status
		reasons []string
	}{
		{
			name:    "affected wins over not_affected",
			entries: []osv.Affected{foldMiss, foldHit},
			want:    Affected,
			reasons: []string{"falls inside the advisory's affected range"},
		},
		{
			name:    "affected wins over unknown",
			entries: []osv.Affected{foldGit, foldHit},
			want:    Affected,
			reasons: []string{"falls inside the advisory's affected range"},
		},
		{
			name:    "unknown wins over not_affected",
			entries: []osv.Affected{foldMiss, foldGit},
			want:    Unknown,
			reasons: []string{"GIT range"},
		},
		{
			name:    "every reason behind the verdict survives",
			entries: []osv.Affected{foldGit, foldUnknown},
			want:    Unknown,
			reasons: []string{"GIT range", `range type "HASH"`},
		},
		{
			name:    "ruled out by every entry",
			entries: []osv.Affected{foldMiss, foldMiss},
			want:    NotAffected,
			reasons: []string{"outside every affected range"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			advisory := osv.Advisory{ID: "FOLD-0001", Affected: c.entries}
			res := Run(foldInventory(), []osv.Advisory{advisory})
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want one per (component, advisory) pair: %+v",
					len(res.Findings), res.Findings)
			}
			f := res.Findings[0]
			if f.Status != c.want {
				t.Errorf("status = %q, want %q (reason: %s)", f.Status, c.want, f.Reason)
			}
			for _, want := range c.reasons {
				if !strings.Contains(f.Reason, want) {
					t.Errorf("reason = %q, want it to mention %q", f.Reason, want)
				}
			}
		})
	}
}

// A verdict reached twice for the same reason is one reason, and a reason from
// an entry that lost reads as a contradiction beside the one that won.
func TestRunKeepsOnlyTheReasonsBehindTheVerdict(t *testing.T) {
	advisory := osv.Advisory{ID: "FOLD-0002", Affected: []osv.Affected{foldMiss, foldHit, foldMiss}}
	res := Run(foldInventory(), []osv.Advisory{advisory})
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].Reason; strings.Contains(got, "outside") || strings.Contains(got, ";") {
		t.Errorf("reason = %q, want the affected reason on its own", got)
	}
}

func TestRunIgnoresEntriesForOtherPackages(t *testing.T) {
	advisory := osv.Advisory{ID: "FOLD-0003", Affected: []osv.Affected{
		foldEntry("sprocket", osv.RangeSemver, osv.Event{Introduced: "0"}),
		foldHit,
	}}
	res := Run(foldInventory(), []osv.Advisory{advisory})
	if len(res.Findings) != 1 || res.Findings[0].Status != Affected {
		t.Fatalf("findings = %+v, want one affected finding for cogwheel", res.Findings)
	}
}

func TestRunStatesNothingWhenNoEntryNamesThePackage(t *testing.T) {
	advisory := osv.Advisory{ID: "FOLD-0004", Affected: []osv.Affected{
		foldEntry("sprocket", osv.RangeSemver, osv.Event{Introduced: "0"}),
	}}
	res := Run(foldInventory(), []osv.Advisory{advisory})
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none: the advisory says nothing about this package", res.Findings)
	}
	if res.Checked != 1 {
		t.Errorf("checked = %d, want the component counted as compared", res.Checked)
	}
}
