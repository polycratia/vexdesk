// Package vex turns findings plus human decisions into VEX statements.
package vex

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/polycratia/vexdesk/internal/match"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
)

// Decision is what a person concluded about one finding. The tool never fills
// this in by itself: deciding that vulnerable code is unreachable is an
// engineering judgement, and a tool that guesses it produces documents that
// look authoritative and are not.
type Decision struct {
	Vulnerability string                `json:"vulnerability"`
	Product       string                `json:"product"`
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
	}
	return f.Decisions, nil
}

// Statements turns findings into VEX statements, applying decisions where they
// exist. Anything undecided comes out as under_investigation — the honest
// status for "we have seen it and have not finished looking".
func Statements(findings []match.Finding, decisions []Decision) []openvex.Statement {
	index := make(map[[2]string]Decision, len(decisions))
	for _, d := range decisions {
		index[[2]string{d.Vulnerability, d.Product}] = d
	}

	out := make([]openvex.Statement, 0, len(findings))
	for _, f := range findings {
		s := openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: f.Advisory, Aliases: f.Aliases},
			Products:      []openvex.Product{{ID: f.Component.PURL}},
			Status:        openvex.UnderInvestigation,
		}
		if d, ok := index[[2]string{f.Advisory, f.Component.PURL}]; ok {
			s.Status = d.Status
			s.Justification = d.Justification
			s.ImpactStatement = d.Impact
			s.ActionStatement = d.Action
		}
		out = append(out, s)
	}
	return out
}
