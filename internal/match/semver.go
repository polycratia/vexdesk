package match

import (
	"fmt"
	"strconv"
	"strings"
)

// compareSemver orders two semantic versions per semver.org §11: numeric
// release parts first, then pre-release precedence, build metadata ignored.
// A leading "v" is tolerated because ecosystems disagree about it.
func compareSemver(a, b string) (int, error) {
	va, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := range 3 {
		if c := cmpInt(va.release[i], vb.release[i]); c != 0 {
			return c, nil
		}
	}
	return comparePre(va.pre, vb.pre), nil
}

type semver struct {
	release [3]uint64
	pre     []string
}

func parseSemver(s string) (semver, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(s), "v")
	if raw == "" {
		return semver{}, fmt.Errorf("version %q: empty", s)
	}
	raw, _, _ = strings.Cut(raw, "+") // build metadata carries no precedence
	core, pre, _ := strings.Cut(raw, "-")

	// Exactly three parts, no shortcuts. Accepting "1.2" would also accept
	// "2023-08-01" as major version 2023 with a pre-release of "08-01", and a
	// date silently outranking every real version is the kind of confident
	// wrong answer this tool exists to avoid.
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("version %q: expected major.minor.patch", s)
	}
	var v semver
	for i, p := range parts {
		if len(p) > 1 && p[0] == '0' {
			return semver{}, fmt.Errorf("version %q: %q has a leading zero", s, p)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return semver{}, fmt.Errorf("version %q: %q is not a number", s, p)
		}
		v.release[i] = n
	}
	if pre != "" {
		v.pre = strings.Split(pre, ".")
	}
	return v, nil
}

// comparePre implements pre-release precedence: a version with a pre-release
// sorts below the same version without one.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := comparePreID(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(uint64(len(a)), uint64(len(b)))
}

func comparePreID(a, b string) int {
	na, errA := strconv.ParseUint(a, 10, 64)
	nb, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		return cmpInt(na, nb)
	case errA == nil: // numeric identifiers sort below alphanumeric ones
		return -1
	case errB == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
