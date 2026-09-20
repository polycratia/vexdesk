# The CRA workflow, end to end

This is the whole path, from the bill of materials a scanner writes to a signed
document published beside a release: which steps belong to a tool, which belong
to a person, and where the result plugs into whatever script builds your
releases.

vexdesk prepares documents. It is not compliance advice, and nothing here is a
reading of the law. The Cyber Resilience Act's reporting obligations apply from
11 September 2026 and the remaining obligations from 11 December 2027; what your
product has to produce, and for whom, is a question for the regulation's text
and for whoever signs off on it in your organisation.

## The shape of it

```
  your build          third-party tools        vexdesk                 a person
  ----------          ----------------         -------                 --------
  artefact  ────────►  syft / trivy / cdxgen ──► inventory
                       OSV advisory tree ──────► match  ──► findings ──► decide
                                                                            │
                                                  vex  ◄───── decisions.json┘
                                                   │
                                                   ├──► vex.json
                                                   └──► diff vs last release ──► sign
```

Everything below follows that line, one stage at a time.

## Stage 0 — build the artefact and describe it

vexdesk does not generate SBOMs. Produce a CycloneDX JSON document with the tool
that already knows how your artefact is built — syft, trivy and cdxgen all write
a shape vexdesk reads — and produce it from the artefact you are about to ship,
not from a lockfile that may describe a different build.

```bash
syft dist/example-service-2.1.0 -o cyclonedx-json > dist/sbom-2.1.0.cyclonedx.json
```

CycloneDX JSON 1.4, 1.5 and 1.6 are read; anything else is refused rather than
parsed on the hope that the shape did not change.

## Stage 1 — have advisories on disk

vexdesk ships no vulnerability database and makes no network calls. It reads OSV
records from a directory tree, one record per `.json` file, nested however the
feed you use arranges them. Refresh that tree however you already do it; the
tree is an input to the run, so a document is reproducible only against the tree
it was built from.

## Stage 2 — see what the product is made of

```console
$ vexdesk inventory dist/sbom-2.1.0.cyclonedx.json
```

This stage decides nothing. It exists so that the count you reason about is the
count in the document: how many components, how many the root depends on
directly, and how many carry a package URL. A component without a package URL
cannot be looked up in any advisory database, and it is printed as its own line
rather than dropped.

## Stage 3 — match components against advisories

```console
$ vexdesk match -sbom dist/sbom-2.1.0.cyclonedx.json -advisories ./advisories
```

This is the stage where the tool does all the judging it is entitled to do. It
compares a component's version against the ranges an advisory gives, and each
comparison ends in one of three places:

| Status | Meaning |
|---|---|
| `affected` | the version falls inside an affected range, or is on an explicit affected version list |
| `not_affected` | the version is outside every range the advisory gives |
| `unknown` | the comparison could not be made, with the reason attached |

`not_affected` here is a statement about version arithmetic and nothing else. It
does not mean the vulnerable code is unreachable — only that this version is not
in the advisory's range.

`unknown` is the status that matters most, because it is the one a person has to
clear: a `GIT` range that cannot be compared against a version string, an
`ECOSYSTEM` range for an ecosystem whose ordering is not implemented, a version
string that is not a version. Components that could not be checked at all — no
package URL, no version, a package URL type that maps to no advisory ecosystem —
are listed separately under "not checked".

`match` exits 1 when anything needs attention, so it can gate a pipeline; pass
`-exit-zero` to print the report without stopping, and `-json` to hand the same
result to another tool.

## Stage 4 — decide (this stage is yours)

Nothing automates this one. Whether vulnerable code is reachable in your product
is an engineering judgement, and a tool that guesses it produces documents that
look authoritative and are not. Record what you concluded in a decisions file,
kept in version control next to the product it describes:

```json
{
  "decisions": [
    {
      "vulnerability": "FIXTURE-0001",
      "product": "pkg:golang/github.com/example/widget@v1.2.3",
      "applies_to": "version",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "the affected parser is only reached from the admin importer, which this build does not include"
    },
    {
      "vulnerability": "FIXTURE-0004",
      "product": "pkg:npm/cogwheel@4.0.0",
      "status": "affected",
      "action_statement": "upgrade cogwheel to 4.1.0"
    }
  ]
}
```

- `vulnerability` and `product` are both required: a decision that does not say
  what it is about cannot be applied to anything.
- `status` is one of `not_affected`, `affected`, `fixed`, `under_investigation`.
- `not_affected` requires one of five justification codes:
  `component_not_present`, `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary`,
  `inline_mitigations_already_exist`. Prose in `impact_statement` is welcome
  alongside the code and never instead of it — a reviewer can compare a code
  against every other `not_affected` and cannot compare a paragraph.
- `affected` requires an `action_statement`: what should the user of your
  product do.
- `applies_to` says how far the decision reaches. `version`, the default, keeps
  it on the exact product it names. `component` applies it to the same component
  at any version, so a justification written once survives the next scan; the
  statement it produces records which product the decision was written for, so
  nothing carries forward silently. Naming the exact version in a second,
  version-scoped decision takes the rule back for that version.

Anything you have not decided is not a gap in the document — it comes out as
`under_investigation`, which is the honest status for "we have seen it and have
not finished looking".

## Stage 5 — build the document

```bash
vexdesk vex -sbom dist/sbom-2.1.0.cyclonedx.json -advisories ./advisories \
            -decisions decisions.json -author "Example Ltd" \
            -o dist/vex-2.1.0.json
```

What goes in:

- one statement per finding that needs attention — `affected` and `unknown`.
  Findings ruled out by version arithmetic alone are not stated;
- your decisions, where one names the finding;
- `under_investigation` for everything else.

What does not go in: components that could not be checked at all. They have no
package URL to state a claim about, so they never reach the document. They are
in the `match` report, and clearing them is hand work.

Writing is strict. The document refuses to build if the author is missing, if a
`not_affected` statement has no justification code, if an `affected` statement
has no action statement, or if a justification appears on a status other than
`not_affected`. A product where every advisory was ruled out by version has
nothing to state at all, and `vex` says so rather than writing an empty
document — a script that always expects a file needs to handle that case.

The document `@id` is derived from the statements. Rebuilding from unchanged
decisions produces the same id, so a rebuild does not look like a newly issued
document. The timestamp does move, so compare documents by their id or with
`diff`, not byte for byte.

## Stage 6 — say what changed since the last release

```console
$ vexdesk diff released/vex-2.0.0.json dist/vex-2.1.0.json
```

The question a customer asks on receiving a new document is not what it contains
but what is different from the one before. The comparison is made claim by claim
— one vulnerability against one product — so reordered statements report
nothing, a changed justification on a conclusion that held is reported on its
own, and an upgraded dependency reads as one move rather than a finding
vanishing and an unrelated one arriving.

`diff` exits 1 when the current document opens work: a claim that is `affected`
or `under_investigation` now and was not before. That is the gate worth putting
in front of a release — it fires on new exposure, not on every edit.

Already-issued documents are read leniently, including ones that break the rules
vexdesk enforces on write, because refusing them would hide the statements
someone needs to fix.

## Stage 7 — sign and publish

vexdesk does not sign. The document is a plain JSON file, so sign it the way you
sign your other release artefacts — the point of the signature is that a reader
can tell the document came from you and has not been edited since:

```bash
cosign sign-blob --yes --bundle dist/vex-2.1.0.json.sigbundle dist/vex-2.1.0.json
```

Publish the document, its signature and the SBOM beside the artefact, at a
stable location, and keep the document you published: it is the `previous`
argument for the next release's diff, and the record of what you claimed at the
time you claimed it.

## Who decides what

| Decided by the tool | Decided by a person |
|---|---|
| which components are in the product, and which carry a package URL | whether a component with no package URL matters |
| which advisories name those packages | whether an advisory that names the package describes your build |
| whether a version falls inside an affected range | whether vulnerable code is reachable, and which justification code says so |
| that a comparison could not be made, and why | how to resolve an `unknown` — read the advisory, pin a version, or state the judgement |
| that an undecided finding is `under_investigation` | when investigation ends, and what it concluded |
| that a document breaks the OpenVEX rules | what the document claims |
| what changed since the last released document | whether that change blocks the release |
| — | signing, publishing and standing behind the result |

## In a release script

Order matters more than tooling. Build, describe, match, decide, state, compare,
sign:

```sh
#!/bin/sh
set -eu

version="$1"
sbom="dist/sbom-$version.cyclonedx.json"
doc="dist/vex-$version.json"
previous="released/vex-$(cat released/LATEST).json"

# Describe the artefact that was just built.
syft "dist/example-service-$version" -o cyclonedx-json > "$sbom"

# Report what matched and what could not be checked. Read, do not gate:
# the gate that matters is the diff below.
vexdesk match -sbom "$sbom" -advisories ./advisories -exit-zero

# State the decisions recorded in the repository.
vexdesk vex -sbom "$sbom" -advisories ./advisories \
            -decisions decisions.json -author "Example Ltd" -o "$doc"

# Stop here if this release opens work the last one did not.
vexdesk diff "$previous" "$doc"

# Sign and publish beside the artefact.
cosign sign-blob --yes --bundle "$doc.sigbundle" "$doc"
```

With `set -e`, the `diff` call is the gate: a release that introduces an
`affected` or `under_investigation` claim stops until someone records a decision
for it. Gating on `match` instead is the stricter choice — it stops on every
finding, decided or not — and it is the wrong stricter choice for most teams,
because a finding you decided about last month would block every release after
it.

For a report-only run, add `-exit-zero` to `diff` as well and read the output.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the command ran and nothing is blocking |
| 1 | `match`: a finding needs attention. `diff`: the current document opens work the previous one did not. Suppress with `-exit-zero` |
| 2 | the command could not run: a file is missing, a document is malformed, a required flag is absent, or the document would break the OpenVEX rules |

Code 1 is an answer, not a failure. Code 2 means nothing was produced.

## What this path does not cover

Being explicit about the edges is the point of the tool, so the same applies to
the workflow:

- **The reporting clock.** The CRA's reporting duties for actively exploited
  vulnerabilities run on deadlines measured in hours. vexdesk tracks no clock
  and notifies nobody; that process is yours.
- **Reachability analysis.** `vulnerable_code_not_in_execute_path` is your
  claim, supported by whatever evidence you gathered. The tool records it.
- **Ecosystems it cannot order.** A PyPI `ECOSYSTEM` range needs PEP 440
  ordering, which is not implemented, and a `GIT` range cannot be compared
  against a version string at all. Both surface as `unknown` with the reason.
- **Input and output formats.** CycloneDX JSON in, OpenVEX out. SPDX input and
  CSAF output are not built.
- **Exploitability feeds.** No KEV, no EPSS, no severity ranking. Every finding
  arrives with the same weight and you prioritise it.

## Keeping the record

Three things are worth keeping under version control next to the product:
`decisions.json`, because it is the reasoning behind every claim and its history
is the history of what you knew; the issued documents, because each one is the
previous side of the next diff; and the SBOM for each release, because a
document is only checkable against the bill of materials it was built from.
