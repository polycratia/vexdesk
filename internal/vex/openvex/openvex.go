// Package openvex builds and validates OpenVEX documents.
//
// The validation is the point. A VEX statement that says "not_affected" without
// saying why is not a weaker statement — it is an unusable one, because the
// reader has no way to judge it. The spec makes the justification mandatory;
// this package refuses to emit a document that skips it.
package openvex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// Context is the OpenVEX specification this package writes.
const Context = "https://openvex.dev/ns/v0.2.0"

// Status values defined by OpenVEX.
type Status string

const (
	NotAffected        Status = "not_affected"
	Affected           Status = "affected"
	Fixed              Status = "fixed"
	UnderInvestigation Status = "under_investigation"
)

var statuses = []Status{NotAffected, Affected, Fixed, UnderInvestigation}

// Justification values allowed for not_affected. The list is closed by the
// spec: free-form reasons go in the impact statement instead.
type Justification string

const (
	ComponentNotPresent                         Justification = "component_not_present"
	VulnerableCodeNotPresent                    Justification = "vulnerable_code_not_present"
	VulnerableCodeNotInExecutePath              Justification = "vulnerable_code_not_in_execute_path"
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	InlineMitigationsAlreadyExist               Justification = "inline_mitigations_already_exist"
)

var justifications = []Justification{
	ComponentNotPresent,
	VulnerableCodeNotPresent,
	VulnerableCodeNotInExecutePath,
	VulnerableCodeCannotBeControlledByAdversary,
	InlineMitigationsAlreadyExist,
}

// Justifications lists the accepted justification codes, for help output and
// for error messages that have to tell the user what is allowed.
func Justifications() []Justification { return slices.Clone(justifications) }

// Vulnerability names the flaw a statement is about.
type Vulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Product is a thing the statement applies to, identified by package URL.
type Product struct {
	ID string `json:"@id"`
}

// Statement is one claim: this vulnerability, these products, this status.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products"`
	Status          Status        `json:"status"`
	Justification   Justification `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

// Document is an OpenVEX document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
	Statements []Statement `json:"statements"`
}

// New assembles a document and validates it. The identifier is derived from the
// statements, so the same decisions produce the same document id — a rebuild in
// CI does not look like a new document every time.
func New(author string, at time.Time, tooling string, statements []Statement) (*Document, error) {
	doc := &Document{
		Context:    Context,
		Author:     author,
		Timestamp:  at.UTC().Format(time.RFC3339),
		Version:    1,
		Tooling:    tooling,
		Statements: statements,
	}
	doc.ID = deriveID(statements)
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

// Parse reads a document that has already been issued. It does not validate: a
// document published last quarter is a fact, and refusing to read it would hide
// exactly the statements someone needs to see in order to fix them. Writing
// stays strict; reading does not.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("openvex: %w", err)
	}
	if doc.Context == "" && len(doc.Statements) == 0 {
		return nil, errors.New("openvex: not a VEX document: it has neither @context nor statements")
	}
	return &doc, nil
}

// ParseFile reads an OpenVEX document from disk.
func ParseFile(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// Validate checks the rules the spec puts on a document.
func (d *Document) Validate() error {
	var errs []error
	if strings.TrimSpace(d.Author) == "" {
		errs = append(errs, errors.New("document: author is required"))
	}
	if len(d.Statements) == 0 {
		errs = append(errs, errors.New("document: a document with no statements says nothing"))
	}
	for i, s := range d.Statements {
		if err := s.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("statement %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// Validate checks one statement.
func (s Statement) Validate() error {
	var errs []error
	if strings.TrimSpace(s.Vulnerability.Name) == "" {
		errs = append(errs, errors.New("vulnerability name is required"))
	}
	if len(s.Products) == 0 {
		errs = append(errs, errors.New("at least one product is required"))
	}
	for _, p := range s.Products {
		if strings.TrimSpace(p.ID) == "" {
			errs = append(errs, errors.New("product identifier cannot be empty"))
		}
	}
	if !slices.Contains(statuses, s.Status) {
		errs = append(errs, fmt.Errorf("status %q is not one of %v", s.Status, statuses))
		return errors.Join(errs...)
	}

	switch s.Status {
	case NotAffected:
		// One of the closed set of codes, always. Prose explains a decision to
		// the person reading this document; only the code lets a reviewer, a
		// diff or another tool compare it against every other not_affected.
		// An impact statement is welcome alongside it, never instead of it.
		switch {
		case s.Justification == "" && strings.TrimSpace(s.ImpactStatement) != "":
			errs = append(errs, fmt.Errorf(
				"not_affected has an impact_statement but no justification: prose does not stand in for one of %v",
				justifications))
		case s.Justification == "":
			errs = append(errs, fmt.Errorf("not_affected requires a justification, one of %v", justifications))
		case !slices.Contains(justifications, s.Justification):
			errs = append(errs, fmt.Errorf("justification %q is not one of %v", s.Justification, justifications))
		}
	case Affected:
		if strings.TrimSpace(s.ActionStatement) == "" {
			errs = append(errs, errors.New("affected requires an action_statement: what should the user do"))
		}
	default:
		if s.Justification != "" {
			errs = append(errs, fmt.Errorf("justification only applies to not_affected, not to %q", s.Status))
		}
	}
	return errors.Join(errs...)
}

// Encode writes the document as indented JSON.
func (d *Document) Encode() ([]byte, error) {
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func deriveID(statements []Statement) string {
	sum := sha256.New()
	// Errors from json.Marshal on this shape would mean a programming error,
	// and an id that ignores an unencodable statement is still deterministic.
	body, _ := json.Marshal(statements)
	sum.Write(body)
	return "https://openvex.dev/docs/public/vexdesk-" + hex.EncodeToString(sum.Sum(nil))[:16]
}
