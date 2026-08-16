// Package match decides which advisories touch which components.
//
// The rule that shapes this package: when the tool cannot tell, it says so.
// A range type it cannot order, an ecosystem it cannot name, a component with
// no package URL — each of those becomes a visible "unknown", never a quiet
// "not affected". Someone has to look at those by hand, and they can only do
// that if the tool admits they exist.
package match

import (
	"fmt"
	"slices"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/inventory"
)

// Status is what the version comparison concluded.
type Status string

const (
	// Affected: the component's version falls inside the advisory's range.
	Affected Status = "affected"
	// NotAffected: the version is outside every range the advisory gives.
	// It says nothing about whether the vulnerable code is reachable.
	NotAffected Status = "not_affected"
	// Unknown: the comparison could not be made. Needs a human.
	Unknown Status = "unknown"
)

// Finding is one component measured against one advisory.
type Finding struct {
	Component inventory.Component `json:"component"`
	Advisory  string              `json:"advisory"`
	Aliases   []string            `json:"aliases,omitempty"`
	Summary   string              `json:"summary,omitempty"`
	Status    Status              `json:"status"`
	Reason    string              `json:"reason"`
}

// Skip is a component that could not be checked at all, with the reason why.
type Skip struct {
	Component inventory.Component `json:"component"`
	Reason    string              `json:"reason"`
}

// Result is the whole picture: what was compared, and what could not be.
type Result struct {
	Findings []Finding `json:"findings"`
	Skipped  []Skip    `json:"skipped,omitempty"`
	// Checked counts components that were compared against the advisory set.
	Checked int `json:"checked"`
}

// Attention returns the findings a person still has to deal with.
func (r Result) Attention() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status != NotAffected {
			out = append(out, f)
		}
	}
	return out
}

// Run compares every component in the inventory against every advisory.
func Run(inv *inventory.Inventory, advisories []osv.Advisory) Result {
	var res Result
	for _, c := range inv.Components {
		if c.PURL == "" {
			res.Skipped = append(res.Skipped, Skip{c, "no package URL: nothing to look up"})
			continue
		}
		purl, err := inventory.ParsePURL(c.PURL)
		if err != nil {
			res.Skipped = append(res.Skipped, Skip{c, err.Error()})
			continue
		}
		eco, name, ok := lookupEcosystem(purl)
		if !ok {
			res.Skipped = append(res.Skipped, Skip{c,
				fmt.Sprintf("purl type %q is not mapped to an advisory ecosystem", purl.Type)})
			continue
		}
		version := c.Version
		if version == "" {
			version = purl.Version
		}
		if version == "" {
			res.Skipped = append(res.Skipped, Skip{c, "no version: cannot compare against any range"})
			continue
		}

		res.Checked++
		for _, a := range advisories {
			for _, aff := range a.Affected {
				if !samePackage(aff.Package.Ecosystem, aff.Package.Name, eco, name) {
					continue
				}
				status, reason := evaluate(version, aff, eco)
				res.Findings = append(res.Findings, Finding{
					Component: c,
					Advisory:  a.ID,
					Aliases:   a.Aliases,
					Summary:   a.Summary,
					Status:    status,
					Reason:    reason,
				})
			}
		}
	}
	return res
}

// evaluate measures one version against one affected entry.
func evaluate(version string, aff osv.Affected, eco ecosystem) (Status, string) {
	// An explicit version list is exact: no ordering rules needed.
	if slices.Contains(aff.Versions, version) {
		return Affected, "version is in the advisory's affected version list"
	}

	var unknown []string
	for _, r := range aff.Ranges {
		switch r.Type {
		case osv.RangeSemver:
			// fall through to comparison
		case osv.RangeEcosystem:
			if !eco.semverOrdered {
				unknown = append(unknown, fmt.Sprintf(
					"ECOSYSTEM range for %s needs that ecosystem's own version ordering, which is not implemented",
					eco.name))
				continue
			}
		case osv.RangeGit:
			unknown = append(unknown, "GIT range: commit ranges cannot be compared against a version string")
			continue
		default:
			unknown = append(unknown, fmt.Sprintf("range type %q is not recognised", r.Type))
			continue
		}

		hit, err := inSemverRange(version, r)
		if err != nil {
			unknown = append(unknown, err.Error())
			continue
		}
		if hit {
			return Affected, "version falls inside the advisory's affected range"
		}
	}

	if len(unknown) > 0 {
		return Unknown, unknown[0]
	}
	if len(aff.Ranges) == 0 && len(aff.Versions) > 0 {
		return NotAffected, "version is not in the advisory's affected version list"
	}
	if len(aff.Ranges) == 0 {
		return Unknown, "advisory names this package but gives neither ranges nor versions"
	}
	return NotAffected, "version is outside every affected range"
}

// inSemverRange walks the range's events in order, per the OSV schema: an
// "introduced" event opens the interval, "fixed" and "last_affected" close it.
func inSemverRange(version string, r osv.Range) (bool, error) {
	affected := false
	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" {
				affected = true
				continue
			}
			c, err := compareSemver(version, e.Introduced)
			if err != nil {
				return false, err
			}
			if c >= 0 {
				affected = true
			}
		case e.Fixed != "":
			c, err := compareSemver(version, e.Fixed)
			if err != nil {
				return false, err
			}
			if c >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			c, err := compareSemver(version, e.LastAffected)
			if err != nil {
				return false, err
			}
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, nil
}
