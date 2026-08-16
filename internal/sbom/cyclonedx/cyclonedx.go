// Package cyclonedx reads a CycloneDX JSON bill of materials into an inventory.
//
// It reads; it does not write. Generating an SBOM is a solved problem with good
// tools behind it, and this project is about what happens to a bill of materials
// after it exists.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/polycratia/vexdesk/internal/inventory"
)

// Supported spec versions. Anything else is refused rather than parsed on the
// hope that the shape did not change.
var supported = []string{"1.4", "1.5", "1.6"}

type document struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Component *component `json:"component"`
	} `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type component struct {
	BOMRef     string      `json:"bom-ref"`
	Type       string      `json:"type"`
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	PURL       string      `json:"purl"`
	Components []component `json:"components"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// ParseFile reads a CycloneDX document from disk.
func ParseFile(path string) (*inventory.Inventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads a CycloneDX JSON document.
func Parse(r io.Reader) (*inventory.Inventory, error) {
	var doc document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("cyclonedx: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("cyclonedx: not a CycloneDX document (bomFormat=%q)", doc.BOMFormat)
	}
	if !slices.Contains(supported, doc.SpecVersion) {
		return nil, fmt.Errorf("cyclonedx: spec version %q is not supported (supported: %v)",
			doc.SpecVersion, supported)
	}

	inv := &inventory.Inventory{Format: "CycloneDX", Spec: doc.SpecVersion}
	if doc.Metadata.Component != nil {
		inv.Root = convert(*doc.Metadata.Component)
	}

	// Components may nest; a flat inventory is the whole point of this package.
	var flatten func(cs []component)
	flatten = func(cs []component) {
		for _, c := range cs {
			inv.Components = append(inv.Components, convert(c))
			flatten(c.Components)
		}
	}
	flatten(doc.Components)

	markDirect(inv, doc.Dependencies)
	return inv, nil
}

func convert(c component) inventory.Component {
	return inventory.Component{
		Ref:     c.BOMRef,
		Name:    c.Name,
		Version: c.Version,
		PURL:    c.PURL,
		Kind:    c.Type,
	}
}

// markDirect flags the components the root depends on without an intermediary.
// A document with no dependency graph leaves every component transitive: the
// honest reading of "the SBOM did not say" is not "everything is direct".
func markDirect(inv *inventory.Inventory, deps []dependency) {
	root := inv.Root.Ref
	if root == "" {
		return
	}
	var direct map[string]bool
	for _, d := range deps {
		if d.Ref != root {
			continue
		}
		direct = make(map[string]bool, len(d.DependsOn))
		for _, ref := range d.DependsOn {
			direct[ref] = true
		}
		break
	}
	for i := range inv.Components {
		inv.Components[i].Direct = direct[inv.Components[i].Ref]
	}
}
