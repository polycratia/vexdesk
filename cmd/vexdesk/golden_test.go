package main

// Golden documents over the shapes real scanners write.
//
// syft and trivy both emit CycloneDX and both emit it their own way: bom-refs
// carrying package-id qualifiers, operating-system components, purl types no
// advisory ecosystem covers. testdata/scanners holds those shapes and
// testdata/golden holds the documents they produce today, compared byte for
// byte — a renamed field, a shifted order or a justification that stops being
// written is format drift, and the reader who finds it should be this test
// rather than a customer's parser.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/match"
	"github.com/polycratia/vexdesk/internal/sbom/cyclonedx"
	"github.com/polycratia/vexdesk/internal/vex"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden VEX documents from the current output")

const (
	scannerDecisions = "../../testdata/scanners/decisions.json"
	goldenAuthor     = "Example Ltd"
)

// goldenIssued fixes the issuing time. The document id is derived from the
// statements and is stable on its own; the timestamp is not, and a clock in a
// golden file rewrites it on every run.
var goldenIssued = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

var scanners = []struct {
	name   string
	sbom   string
	golden string
}{
	{"syft", "../../testdata/scanners/syft.cyclonedx.json", "../../testdata/golden/syft.vex.json"},
	{"trivy", "../../testdata/scanners/trivy.cyclonedx.json", "../../testdata/golden/trivy.vex.json"},
}

func TestGoldenVEXDocuments(t *testing.T) {
	for _, s := range scanners {
		t.Run(s.name, func(t *testing.T) {
			got := buildVEX(t, s.sbom)
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(s.golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(s.golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("recorded %s (%d bytes)", s.golden, len(got))
				return
			}

			want, err := os.ReadFile(s.golden)
			if errors.Is(err, fs.ErrNotExist) {
				t.Skipf("%s has not been recorded yet: run `make golden` and commit the result", s.golden)
			}
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, want) {
				return
			}
			t.Errorf("%s no longer matches the document this input produces:\n%s\n\n"+
				"run `make golden` if the new bytes are the intended ones", s.golden, firstDifference(want, got))
		})
	}
}

// buildVEX walks the same path as the vex command. It does not call the command
// itself because that stamps time.Now() into the document, which no golden file
// can hold still.
func buildVEX(t *testing.T, sbomPath string) []byte {
	t.Helper()
	inv, err := cyclonedx.ParseFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	advs, err := osv.LoadDir(advisories)
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := vex.LoadDecisions(scannerDecisions)
	if err != nil {
		t.Fatal(err)
	}
	res := match.Run(inv, advs)
	doc, err := openvex.New(goldenAuthor, goldenIssued, "vexdesk", vex.Statements(res.Attention(), decisions))
	if err != nil {
		t.Fatal(err)
	}
	body, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// The fixtures earn their place only if they still read as the scanners write
// them: the counts and the reasons here fail before the golden does, and say
// which part of the input stopped being understood.
func TestScannerOutputIsReadWholeAndAdmitsWhatItCannotCheck(t *testing.T) {
	advs, err := osv.LoadDir(advisories)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name                        string
		sbom                        string
		components, direct, checked int
		statuses                    map[string]match.Status
		skipped                     []string
	}{
		{
			name:       "syft",
			sbom:       scanners[0].sbom,
			components: 6,
			direct:     3,
			checked:    4,
			statuses: map[string]match.Status{
				"FIXTURE-0001": match.Affected,
				"FIXTURE-0002": match.NotAffected,
				"FIXTURE-0003": match.Unknown,
				"FIXTURE-0004": match.Affected,
			},
			skipped: []string{"not mapped", "no package URL"},
		},
		{
			name:       "trivy",
			sbom:       scanners[1].sbom,
			components: 5,
			direct:     4,
			checked:    3,
			statuses: map[string]match.Status{
				"FIXTURE-0001": match.Affected,
				"FIXTURE-0004": match.Affected,
			},
			skipped: []string{"no package URL", "not mapped"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv, err := cyclonedx.ParseFile(c.sbom)
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Components) != c.components {
				t.Errorf("components = %d, want %d", len(inv.Components), c.components)
			}
			if got := len(inv.Direct()); got != c.direct {
				t.Errorf("direct = %d, want %d: the scanner's dependency graph was not read", got, c.direct)
			}

			res := match.Run(inv, advs)
			if res.Checked != c.checked {
				t.Errorf("checked = %d, want %d", res.Checked, c.checked)
			}
			if len(res.Findings) != len(c.statuses) {
				t.Fatalf("got %d findings, want %d: %+v", len(res.Findings), len(c.statuses), res.Findings)
			}
			for _, f := range res.Findings {
				if want := c.statuses[f.Advisory]; f.Status != want {
					t.Errorf("%s = %q, want %q (reason: %s)", f.Advisory, f.Status, want, f.Reason)
				}
			}
			if len(res.Skipped) != len(c.skipped) {
				t.Fatalf("skipped = %d, want %d: %+v", len(res.Skipped), len(c.skipped), res.Skipped)
			}
			for i, want := range c.skipped {
				if !strings.Contains(res.Skipped[i].Reason, want) {
					t.Errorf("skipped[%d] = %q, want it to mention %q", i, res.Skipped[i].Reason, want)
				}
			}
		})
	}
}

func firstDifference(want, got []byte) string {
	w := strings.Split(string(want), "\n")
	g := strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		a, b := lineAt(w, i), lineAt(g, i)
		if a == b {
			continue
		}
		return fmt.Sprintf("line %d:\n  recorded: %s\n  produced: %s", i+1, a, b)
	}
	return "the two differ in bytes that carry no line of their own"
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(end of document)"
}
