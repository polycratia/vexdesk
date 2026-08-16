package match

import (
	"strings"

	"github.com/polycratia/vexdesk/internal/inventory"
)

// ecosystem describes how an OSV ecosystem names its packages and whether its
// versions can be ordered with semver rules.
type ecosystem struct {
	name string
	// semverOrdered marks ecosystems whose own version ordering is semver, so
	// an ECOSYSTEM range can be evaluated with semver comparison. Ecosystems
	// with their own ordering rules (PEP 440, Debian epochs, Maven) are left
	// out on purpose: guessing their order would produce confident wrong
	// answers, which is worse than saying "unknown".
	semverOrdered bool
	// pkgName builds the package name as the ecosystem's advisories spell it.
	pkgName func(p inventory.PURL) string
}

var byPURLType = map[string]ecosystem{
	"golang":   {name: "Go", semverOrdered: true, pkgName: joinSlash},
	"npm":      {name: "npm", semverOrdered: true, pkgName: joinSlash},
	"cargo":    {name: "crates.io", semverOrdered: true, pkgName: nameOnly},
	"pypi":     {name: "PyPI", pkgName: normalizedPyPI},
	"maven":    {name: "Maven", pkgName: joinColon},
	"gem":      {name: "RubyGems", pkgName: nameOnly},
	"nuget":    {name: "NuGet", pkgName: nameOnly},
	"composer": {name: "Packagist", pkgName: joinSlash},
	"hex":      {name: "Hex", pkgName: joinSlash},
	"pub":      {name: "Pub", pkgName: nameOnly},
}

// lookupEcosystem maps a package URL onto the OSV ecosystem and package name.
// An unmapped purl type is reported, not silently treated as "no advisories".
func lookupEcosystem(p inventory.PURL) (eco ecosystem, name string, ok bool) {
	e, ok := byPURLType[p.Type]
	if !ok {
		return ecosystem{}, "", false
	}
	return e, e.pkgName(p), true
}

func nameOnly(p inventory.PURL) string { return p.Name }

func joinSlash(p inventory.PURL) string {
	if p.Namespace == "" {
		return p.Name
	}
	return p.Namespace + "/" + p.Name
}

func joinColon(p inventory.PURL) string {
	if p.Namespace == "" {
		return p.Name
	}
	return p.Namespace + ":" + p.Name
}

// normalizedPyPI applies PEP 503 name normalization so that "Flask_Login" and
// "flask-login" are recognised as the same package.
func normalizedPyPI(p inventory.PURL) string {
	name := strings.ToLower(p.Name)
	var b strings.Builder
	var lastDash bool
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return b.String()
}

// samePackage compares an advisory's package against a component's, using the
// ecosystem's own naming. Ecosystem strings may carry a suffix
// ("Alpine:v3.19"), which the OSV schema treats as the same ecosystem family.
func samePackage(advisory string, advisoryName string, eco ecosystem, name string) bool {
	base, _, _ := strings.Cut(advisory, ":")
	if !strings.EqualFold(base, eco.name) {
		return false
	}
	if eco.name == "PyPI" {
		return normalizedPyPIString(advisoryName) == name
	}
	return advisoryName == name
}

func normalizedPyPIString(s string) string {
	return normalizedPyPI(inventory.PURL{Name: s})
}
