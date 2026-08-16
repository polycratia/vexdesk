// Package inventory is the normalized view of what a product is made of.
//
// Every SBOM reader produces one of these, so the rest of the tool never has to
// know which format the bill of materials arrived in.
package inventory

// Component is one piece of software inside the product.
type Component struct {
	// Ref is the identifier the source document used for this component. It is
	// kept so that dependency edges can be resolved, not because it means
	// anything outside that document.
	Ref     string `json:"ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Kind    string `json:"kind,omitempty"`
	// Direct is true when the root component depends on this one without going
	// through another component. False also covers "the document did not say".
	Direct bool `json:"direct"`
}

// Inventory is a product and everything that ships inside it.
type Inventory struct {
	// Format and Spec record where this came from, e.g. "CycloneDX" and "1.6".
	Format     string      `json:"format"`
	Spec       string      `json:"spec"`
	Root       Component   `json:"root"`
	Components []Component `json:"components"`
}

// Direct returns the components the root depends on directly.
func (inv *Inventory) Direct() []Component {
	var out []Component
	for _, c := range inv.Components {
		if c.Direct {
			out = append(out, c)
		}
	}
	return out
}

// Identifiable returns the components carrying a package URL. Components
// without one cannot be looked up in any advisory database; callers are
// expected to report them rather than quietly drop them.
func (inv *Inventory) Identifiable() (with, without []Component) {
	for _, c := range inv.Components {
		if c.PURL == "" {
			without = append(without, c)
			continue
		}
		with = append(with, c)
	}
	return with, without
}
