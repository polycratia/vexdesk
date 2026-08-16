package inventory

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in   string
		want PURL
	}{
		{"pkg:golang/github.com/example/widget@v1.2.3",
			PURL{Type: "golang", Namespace: "github.com/example", Name: "widget", Version: "v1.2.3"}},
		{"pkg:npm/cogwheel@4.0.0",
			PURL{Type: "npm", Name: "cogwheel", Version: "4.0.0"}},
		{"pkg:npm/%40scope/thing@1.0.0",
			PURL{Type: "npm", Namespace: "@scope", Name: "thing", Version: "1.0.0"}},
		{"pkg:maven/org.example/lib@2.0",
			PURL{Type: "maven", Namespace: "org.example", Name: "lib", Version: "2.0"}},
		{"pkg:deb/debian/curl@7.88.1?arch=amd64#subpath",
			PURL{Type: "deb", Namespace: "debian", Name: "curl", Version: "7.88.1"}},
		{"pkg:PyPI/Example@1.0",
			PURL{Type: "pypi", Namespace: "", Name: "Example", Version: "1.0"}},
		{"pkg:cargo/serde",
			PURL{Type: "cargo", Name: "serde"}},
	}
	for _, c := range cases {
		got, err := ParsePURL(c.in)
		if err != nil {
			t.Errorf("ParsePURL(%q) returned error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePURL(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParsePURLRejects(t *testing.T) {
	for _, in := range []string{"", "golang/widget", "pkg:golang", "pkg:/widget", "pkg:golang/"} {
		if got, err := ParsePURL(in); err == nil {
			t.Errorf("ParsePURL(%q) = %+v, want an error", in, got)
		}
	}
}

func TestPURLString(t *testing.T) {
	const in = "pkg:golang/github.com/example/widget@v1.2.3"
	p, err := ParsePURL(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != in {
		t.Errorf("String() = %q, want %q", got, in)
	}
}

func TestIdentifiableSplitsOnPURL(t *testing.T) {
	inv := &Inventory{Components: []Component{
		{Name: "with", PURL: "pkg:npm/with@1.0.0"},
		{Name: "without"},
	}}
	with, without := inv.Identifiable()
	if len(with) != 1 || with[0].Name != "with" {
		t.Errorf("with = %+v, want the component carrying a purl", with)
	}
	if len(without) != 1 || without[0].Name != "without" {
		t.Errorf("without = %+v, want the component with no purl", without)
	}
}
