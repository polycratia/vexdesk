// Package vex turns findings plus human decisions into VEX statements.
package vex

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/polycratia/vexdesk/internal/match"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

// Scope says how far one decision reaches.
type Scope string

const (
	// ScopeVersion keeps the decision on the exact product it names. It is the
	// default: a judgement made about one build does not travel unless asked.
	ScopeVersion Scope = "version"
	// ScopeComponent applies the decision to the same component at any version,
	// so a justification written once survives the next scan. A version-scoped
	// decision naming a particular version wins over it, which is how a rule is
	// taken back for that version.
	ScopeComponent Scope = "component"
)

var scopes = []Scope{ScopeVersion, ScopeComponent}

// Decision is what a person concluded about one finding. The tool never fills
// this in by itself: deciding that vulnerable code is unreachable is an
// engineering judgement, and a tool that guesses it produces documents that
// look authoritative and are not.
//
// AppliesTo decides whether the conclusion stays on the product it was written
// for or covers the component at every version. Carrying a decision forward is
// a written choice, and a statement that came from a carried rule says so.
type Decision struct {
	Vulnerability string                `json:"vulnerability"`
	Product       string                `json:"product"`
	AppliesTo     Scope                 `json:"applies_to,omitempty"`
	Status        openvex.Status        `json:"status"`
	Justification openvex.Justification `json:"justification,omitempty"`
	Impact        string                `json:"impact_statement,omitempty"`
	Action        string                `json:"action_statement,omitempty"`
}

type decisionFile struct {
	Decisions []Decision `json:"decisions"`
}

// LoadDecisions reads a decisions file.
func LoadDecisions(path string) ([]Decision, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f decisionFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decisions: %w", err)
	}
	for i, d := range f.Decisions {
		if d.Vulnerability == "" || d.Product == "" {
			return nil, fmt.Errorf("decisions: entry %d needs both vulnerability and product", i)
		}
		switch d.AppliesTo {
		case "", ScopeVersion, ScopeComponent:
		default:
			// An unreadable scope is refused rather than narrowed to the
			// default: a typo would otherwise drop a rule without a word.
			return nil, fmt.Errorf("decisions: entry %d has applies_to %q, want one of %v",
				i, d.AppliesTo, scopes)
		}
	}
	return f.Decisions, nil
}

// Statements turns findings into VEX statements, applying decisions where they
// exist. Anything undecided comes out as under_investigation — the honest
// status for "we have seen it and have not finished looking".
//
// A decision naming the exact product is used as written. Otherwise a
// component-scoped decision for the same component applies, and the statement
// records which product it was written for.
func Statements(findings []match.Finding, decisions []Decision) []openvex.Statement {
	exact := make(map[[2]string]Decision, len(decisions))
	componentWide := make(map[[2]string]Decision)
	for _, d := range decisions {
		exact[[2]string{d.Vulnerability, d.Product}] = d
		if scopeOf(d) == ScopeComponent {
			componentWide[[2]string{d.Vulnerability, componentKey(d.Product)}] = d
		}
	}

	out := make([]openvex.Statement, 0, len(findings))
	for _, f := range findings {
		s := openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: f.Advisory, Aliases: f.Aliases},
			Products:      []openvex.Product{{ID: f.Component.PURL}},
			Status:        openvex.UnderInvestigation,
		}
		if d, ok := exact[[2]string{f.Advisory, f.Component.PURL}]; ok {
			apply(&s, d, "")
		} else if d, ok := componentWide[[2]string{f.Advisory, componentKey(f.Component.PURL)}]; ok {
			apply(&s, d, d.Product)
		}
		out = append(out, s)
	}
	return out
}

func apply(s *openvex.Statement, d Decision, carriedFrom string) {
	s.Status = d.Status
	s.Justification = d.Justification
	s.ImpactStatement = d.Impact
	s.ActionStatement = d.Action
	if carriedFrom == "" {
		return
	}
	note := fmt.Sprintf("carried from the decision recorded for %s by an applies_to=%s rule",
		carriedFrom, ScopeComponent)
	if s.ImpactStatement == "" {
		s.ImpactStatement = note
		return
	}
	s.ImpactStatement += "; " + note
}

func scopeOf(d Decision) Scope {
	if d.AppliesTo == "" {
		return ScopeVersion
	}
	return d.AppliesTo
}

// componentKey drops the version from a package URL, leaving the identity of
// the component itself.
func componentKey(purl string) string {
	key := purl
	if i := strings.IndexAny(key, "?#"); i >= 0 {
		key = key[:i]
	}
	if i := strings.LastIndex(key, "@"); i >= 0 {
		key = key[:i]
	}
	return key
}
