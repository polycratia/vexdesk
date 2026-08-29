package match

import (
	"testing"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
)

// Regression, 2026-08-29: events walked in file order flipped an affected
// version to not_affected when a multi-interval range arrived shuffled.
// OSV does not promise sorted events; the verdict must not depend on
// serialisation order.
func TestInSemverRangeUnsortedEvents(t *testing.T) {
	shuffled := osv.Range{Type: "SEMVER", Events: []osv.Event{
		{Introduced: "2.0.0"},
		{Fixed: "2.5.0"},
		{Introduced: "1.0.0"},
		{Fixed: "1.5.0"},
	}}
	cases := []struct {
		version string
		want    bool
	}{
		{"2.2.0", true},  // inside the second interval — the old walk said false
		{"1.2.0", true},  // inside the first interval
		{"1.7.0", false}, // between intervals
		{"2.5.0", false}, // fixed boundary is exclusive
		{"0.9.0", false}, // before everything
	}
	for _, c := range cases {
		got, err := inSemverRange(c.version, shuffled)
		if err != nil {
			t.Fatalf("%s: %v", c.version, err)
		}
		if got != c.want {
			t.Errorf("version %s: got %v, want %v", c.version, got, c.want)
		}
	}
}

// At equal versions a closing event must apply before the introduced that
// reopens the range: [1.0.0, 1.5.0) then [1.5.0, ...) leaves 1.5.0 affected
// by the second interval, regardless of file order.
func TestInSemverRangeTouchingIntervals(t *testing.T) {
	r := osv.Range{Type: "SEMVER", Events: []osv.Event{
		{Introduced: "1.5.0"},
		{Fixed: "1.5.0"},
		{Introduced: "1.0.0"},
	}}
	got, err := inSemverRange("1.5.0", r)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Errorf("1.5.0 must be affected by the reopened interval")
	}
}
