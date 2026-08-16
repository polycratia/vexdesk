package match

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.0.0", "1.0.0+build.5", 0},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
	}
	for _, c := range cases {
		got, err := compareSemver(c.a, c.b)
		if err != nil {
			t.Errorf("compareSemver(%q, %q) returned error: %v", c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareSemverRefusesWhatItCannotOrder(t *testing.T) {
	// A date is the trap: read loosely it becomes major version 2023 and
	// outranks every real version.
	for _, v := range []string{"", "1.0.0.1", "2023-08-01", "1.x", "latest", "1.2", "1.02.3"} {
		if _, err := compareSemver(v, "1.0.0"); err == nil {
			t.Errorf("compareSemver(%q, \"1.0.0\") succeeded, want an error rather than a guess", v)
		}
	}
}
