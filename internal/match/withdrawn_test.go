package match

import (
	"strings"
	"testing"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/inventory"
)

// An OSV record gets retracted — wrong package, duplicate, mistaken report —
// and the schema says so with a date in "withdrawn" while leaving the affected
// ranges where they were. The ranges still match, so the finding is still
// made; what it must not do is carry an affected claim.
const withdrawnRecord = `{
  "id": "FIXTURE-0005",
  "summary": "Fixture advisory: cogwheel, record retracted after publication",
  "modified": "2026-08-20T00:00:00Z",
  "withdrawn": "2026-08-15T00:00:00Z",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "cogwheel"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.2.0"}]}]
    }
  ]
}`

func withdrawnAdvisory(t *testing.T) osv.Advisory {
	t.Helper()
	a, err := osv.Parse([]byte(withdrawnRecord))
	if err != nil {
		t.Fatal(err)
	}
	if a.Withdrawn == "" {
		t.Fatal("the withdrawn date was not read from the record")
	}
	return a
}

func withdrawnInventory() *inventory.Inventory {
	return &inventory.Inventory{Components: []inventory.Component{{
		Name:    "cogwheel",
		Version: "4.0.0",
		PURL:    "pkg:npm/cogwheel@4.0.0",
	}}}
}

func TestRunReportsAWithdrawnAdvisoryAsWithdrawn(t *testing.T) {
	res := Run(withdrawnInventory(), []osv.Advisory{withdrawnAdvisory(t)})
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want the match still reported: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Status != Withdrawn {
		t.Errorf("status = %q, want %q: the version is in range but the record was taken back",
			f.Status, Withdrawn)
	}
	if !strings.Contains(f.Reason, "2026-08-15T00:00:00Z") {
		t.Errorf("reason = %q, want the date the advisory was withdrawn", f.Reason)
	}
	if got := res.Attention(); len(got) != 0 {
		t.Errorf("attention = %+v, want a retracted record left out of it, and so out of the document", got)
	}
	if got := res.WithdrawnFindings(); len(got) != 1 {
		t.Errorf("withdrawn = %+v, want the finding kept in its own block", got)
	}
}

// The same record without the retraction: affected is the verdict its ranges
// reach, and the withdrawn date is what holds that verdict back.
func TestRunWithoutTheWithdrawnDateSaysAffected(t *testing.T) {
	a := withdrawnAdvisory(t)
	a.Withdrawn = ""

	res := Run(withdrawnInventory(), []osv.Advisory{a})
	if len(res.Findings) != 1 || res.Findings[0].Status != Affected {
		t.Fatalf("findings = %+v, want one affected finding", res.Findings)
	}
	if len(res.Attention()) != 1 {
		t.Errorf("attention = %+v, want the affected finding in it", res.Attention())
	}
}
