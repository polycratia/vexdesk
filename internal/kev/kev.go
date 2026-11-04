// Package kev reads a catalog of vulnerabilities known to be exploited.
//
// Exploitation is not a score to be inferred: it is something an authority
// recorded, on a date, in a document. So this package only reports what the
// catalog it was handed actually says. A catalog it cannot read is an error
// rather than a catalog with nothing in it, and an identifier the catalog does
// not list is not thereby known to be unexploited.
package kev

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Entry is one listing: the identifier the catalog names, the catalog that
// names it, and the date it was added.
type Entry struct {
	ID        string `json:"id"`
	Catalog   string `json:"catalog"`
	DateAdded string `json:"date_added"`
}

// Catalog is a set of known-exploited vulnerabilities, indexed by the
// identifiers it lists.
type Catalog struct {
	// Name is what the catalog calls itself, so a reader can tell which
	// authority the date came from.
	Name    string
	entries map[string]Entry
}

// catalogFile is the shape CISA publishes and other catalogs follow. Only the
// identifier and the date are modelled: those two are the fact.
type catalogFile struct {
	Title           string `json:"title"`
	Vulnerabilities []struct {
		CVEID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

const unnamed = "known-exploited catalog"

// Load reads a catalog from disk.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cat, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cat, nil
}

// Parse reads a catalog document.
func Parse(data []byte) (*Catalog, error) {
	var f catalogFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	name := strings.TrimSpace(f.Title)
	if name == "" {
		name = unnamed
	}

	cat := &Catalog{Name: name, entries: make(map[string]Entry, len(f.Vulnerabilities))}
	for i, v := range f.Vulnerabilities {
		id := strings.TrimSpace(v.CVEID)
		if id == "" {
			return nil, fmt.Errorf("kev: entry %d names no vulnerability", i)
		}
		if strings.TrimSpace(v.DateAdded) == "" {
			return nil, fmt.Errorf("kev: %s has no dateAdded: a listing without a date is not a fact with a date", id)
		}
		cat.entries[key(id)] = Entry{ID: id, Catalog: name, DateAdded: v.DateAdded}
	}
	if len(cat.entries) == 0 {
		// A document that parses but lists nothing would clear every finding,
		// which is the one answer a catalog must never be read into.
		return nil, fmt.Errorf("kev: catalog lists no vulnerabilities")
	}
	return cat, nil
}

// Lookup returns the catalog's entry for the first of ids it lists. A nil
// catalog — none was read — lists nothing and says so.
func (c *Catalog) Lookup(ids ...string) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	for _, id := range ids {
		if e, ok := c.entries[key(id)]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

// Len reports how many identifiers the catalog lists.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.entries)
}

func key(id string) string { return strings.ToUpper(strings.TrimSpace(id)) }
