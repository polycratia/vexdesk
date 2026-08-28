# vexdesk

From a bill of materials to a VEX document.

Scanners tell you that a component in your product has a known vulnerability.
They cannot tell you whether *your* product is affected by it, and from
11 September 2026 the EU Cyber Resilience Act expects manufacturers to answer
that question quickly, in writing, for every product they ship. vexdesk is the
bench between the two: it reads what your tools already produce, works out which
advisories could touch your components, and turns your decisions into a
machine-readable OpenVEX document.

## What it does not do

- **It does not generate SBOMs.** syft, trivy and cdxgen do that well. vexdesk
  reads what they write.
- **It does not scan for vulnerabilities** and ships no vulnerability database.
  It consumes OSV advisories you already have on disk.
- **It does not decide for you.** Whether vulnerable code is reachable in your
  product is an engineering judgement. Undecided findings come out as
  `under_investigation`, not as `not_affected`.
- **It is not compliance advice.** It prepares documents; a person signs them.

## Install

```bash
go install github.com/polycratia/vexdesk/cmd/vexdesk@latest
```

Go 1.24 or newer. No dependencies outside the standard library.

## Use

```console
$ vexdesk inventory sbom.cyclonedx.json
CycloneDX 1.6 — example-service 2.1.0
5 components, 3 direct, 4 identifiable by package URL

COMPONENT        VERSION  SCOPE       PURL
widget           1.2.3    direct      pkg:golang/github.com/example/widget@v1.2.3
sprocket         0.9.0    transitive  pkg:golang/github.com/example/sprocket@v0.9.0
cogwheel         4.0.0    direct      pkg:npm/cogwheel@4.0.0
Example_Fixture  3.1.2    transitive  pkg:pypi/Example_Fixture@3.1.2
vendored-blob    unknown  direct      -

1 component(s) carry no package URL and cannot be looked up.
```

```console
$ vexdesk match -sbom sbom.cyclonedx.json -advisories ./advisories
4 component(s) compared against the advisory set

STATUS    ADVISORY      COMPONENT        VERSION  REASON
affected  FIXTURE-0001  widget           1.2.3    version falls inside the advisory's affected range
affected  FIXTURE-0004  cogwheel         4.0.0    version is in the advisory's affected version list
unknown   FIXTURE-0003  Example_Fixture  3.1.2    ECOSYSTEM range for PyPI needs that ecosystem's own version ordering, which is not implemented

Not checked (1):
  vendored-blob  no package URL: nothing to look up
```

`match` exits 1 when anything needs attention, so it can gate a pipeline. Record
what you concluded in a decisions file:

```json
{
  "decisions": [
    {
      "vulnerability": "FIXTURE-0001",
      "product": "pkg:golang/github.com/example/widget@v1.2.3",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "the affected parser is only reached from the admin importer, which this build does not include"
    }
  ]
}
```

```bash
vexdesk vex -sbom sbom.cyclonedx.json -advisories ./advisories \
            -decisions decisions.json -author "Example Ltd" -o vex.json
```

## Saying "unknown" out loud

Every part of the tool is built around one rule: **what cannot be determined is
reported, never quietly cleared.**

A component with no package URL cannot be looked up in any advisory database.
A `GIT` range cannot be compared against a version string. A PyPI `ECOSYSTEM`
range needs PEP 440 ordering, which this tool does not implement. In each case
you get an `unknown` finding with the reason, or a line under "not checked" —
because those are exactly the items a person has to look at, and they can only
do that if the tool admits they exist.

The same rule shapes version parsing. `2023-08-01` is not read as "major version
2023"; it is refused, because a date that silently outranks every real version
produces a confident wrong answer.

## What the document says

vexdesk enforces the OpenVEX rules rather than emitting whatever it is given:

- `not_affected` requires one of the five justification codes
  (`component_not_present`, `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary`,
  `inline_mitigations_already_exist`). A written `impact_statement` is welcome
  alongside the code and the document refuses to build without one — a reviewer
  will ask why, and only the code answers that in a form they can compare
  against every other statement;
- `affected` requires an action statement: what should the user do;
- the document id is derived from the statements, so an unchanged set of
  decisions rebuilds to the same id instead of looking newly issued on every
  CI run.

## Status

Early. Working end to end on the path described above; the parts below are not
built yet, and the tool says so rather than pretending otherwise.

| | |
|---|---|
| SBOM formats | CycloneDX JSON 1.4–1.6 |
| Advisories | OSV records from a directory tree |
| Version ranges | `SEMVER`; `ECOSYSTEM` for Go, npm and crates.io; explicit version lists |
| Ecosystems | Go, npm, crates.io, PyPI, Maven, RubyGems, NuGet, Packagist, Hex, Pub |
| Output | OpenVEX v0.2.0 |
| Not yet | SPDX input, CSAF output, reachability analysis, KEV/EPSS feeds, the reporting clock |

## Development

```bash
make test   # go vet + go test ./...
make demo   # run the whole path over the fixtures in testdata/
```

## License

MIT

---

Maintained by [polycratia](https://polycratia.com).
