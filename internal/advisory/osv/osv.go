// Package osv reads advisories in the OSV schema.
//
// Only the fields that decide "does this touch my product" are modelled. The
// rest of the schema is left alone on purpose: an unused field parsed today is
// a field to maintain forever.
package osv

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Range types defined by the OSV schema.
const (
	RangeSemver    = "SEMVER"
	RangeEcosystem = "ECOSYSTEM"
	RangeGit       = "GIT"
)

// Advisory is one OSV record.
type Advisory struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases,omitempty"`
	Summary  string     `json:"summary,omitempty"`
	Modified string     `json:"modified,omitempty"`
	Affected []Affected `json:"affected,omitempty"`
}

// Affected is one "this package, these versions" claim inside an advisory.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Package identifies what the claim is about.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range is a version interval expressed as a sequence of events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is one boundary of a range. Exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Parse reads a single OSV record.
func Parse(data []byte) (Advisory, error) {
	var a Advisory
	if err := json.Unmarshal(data, &a); err != nil {
		return Advisory{}, fmt.Errorf("osv: %w", err)
	}
	if a.ID == "" {
		return Advisory{}, fmt.Errorf("osv: record has no id")
	}
	return a, nil
}

// LoadDir reads every .json file under dir, recursively. Advisory feeds are
// distributed as directory trees of one record per file, so that is the shape
// this understands.
func LoadDir(dir string) ([]Advisory, error) {
	var out []Advisory
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		a, err := Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, a)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
