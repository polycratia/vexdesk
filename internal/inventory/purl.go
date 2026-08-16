package inventory

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PURL is the part of a package URL that identification actually needs:
// which ecosystem, which package, which version. Qualifiers and subpath are
// parsed off and discarded — nothing here depends on them yet, and pretending
// otherwise would be a promise the code does not keep.
type PURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
}

// String rebuilds the canonical form without qualifiers.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteString("/")
	if p.Namespace != "" {
		b.WriteString(p.Namespace)
		b.WriteString("/")
	}
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteString("@")
		b.WriteString(p.Version)
	}
	return b.String()
}

// ParsePURL reads pkg:type/namespace/name@version, per the package-url spec.
func ParsePURL(s string) (PURL, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return PURL{}, fmt.Errorf("purl %q: missing \"pkg:\" scheme", s)
	}
	rest, _, _ = strings.Cut(rest, "#") // subpath
	rest, _, _ = strings.Cut(rest, "?") // qualifiers

	var version string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest, version = rest[:i], rest[i+1:]
	}

	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		return PURL{}, fmt.Errorf("purl %q: expected type and name", s)
	}

	p := PURL{Type: strings.ToLower(parts[0])}
	var err error
	if p.Name, err = unescape(parts[len(parts)-1]); err != nil {
		return PURL{}, fmt.Errorf("purl %q: %w", s, err)
	}
	if len(parts) > 2 {
		if p.Namespace, err = unescape(strings.Join(parts[1:len(parts)-1], "/")); err != nil {
			return PURL{}, fmt.Errorf("purl %q: %w", s, err)
		}
	}
	if version != "" {
		if p.Version, err = unescape(version); err != nil {
			return PURL{}, fmt.Errorf("purl %q: %w", s, err)
		}
	}
	if p.Type == "" || p.Name == "" {
		return PURL{}, fmt.Errorf("purl %q: type and name cannot be empty", s)
	}
	return p, nil
}

var errEscape = errors.New("invalid percent-encoding")

func unescape(s string) (string, error) {
	out, err := url.PathUnescape(s)
	if err != nil {
		return "", errEscape
	}
	return out, nil
}
