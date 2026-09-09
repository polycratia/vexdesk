// Command vexdesk takes a bill of materials and an advisory feed and carries
// them to the document a maintainer actually has to hand over: a VEX file
// saying, per vulnerability, whether the product is affected and why.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/polycratia/vexdesk/internal/advisory/osv"
	"github.com/polycratia/vexdesk/internal/inventory"
	"github.com/polycratia/vexdesk/internal/match"
	"github.com/polycratia/vexdesk/internal/sbom/cyclonedx"
	"github.com/polycratia/vexdesk/internal/vex"
	"github.com/polycratia/vexdesk/internal/vex/openvex"
	"github.com/polycratia/vexdesk/internal/vex/vexdiff"
)

const usage = `vexdesk — from a bill of materials to a VEX document.

Usage:
  vexdesk inventory <sbom.json> [-json]
        Read a CycloneDX SBOM and show what the product is made of.

  vexdesk match -sbom <sbom.json> -advisories <dir> [-all] [-json]
        Compare the inventory against OSV advisories. Exits 1 when anything
        needs attention, so it can gate a pipeline.

  vexdesk vex -sbom <sbom.json> -advisories <dir> -author <name>
             [-decisions <file>] [-o <file>]
        Build an OpenVEX document from the findings and recorded decisions.
        Findings without a decision come out as under_investigation.

  vexdesk diff <previous.json> <current.json> [-json]
        Compare two OpenVEX documents claim by claim: what turned up, what
        went away, and which judgements were rewritten. Exits 1 when the
        current document opens work that was not open before.

vexdesk does not generate SBOMs and does not scan for vulnerabilities; it reads
what those tools produce.
`

func main() {
	err := run(os.Args[1:], os.Stdout)
	var code exitCode
	switch {
	case errors.As(err, &code):
		os.Exit(int(code))
	case err != nil:
		fmt.Fprintln(os.Stderr, "vexdesk:", err)
		os.Exit(2)
	}
}

// exitCode carries a non-error, non-zero outcome: the command worked and the
// answer is "this pipeline should stop".
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}
	switch args[0] {
	case "inventory":
		return cmdInventory(args[1:], out)
	case "match":
		return cmdMatch(args[1:], out)
	case "vex":
		return cmdVex(args[1:], out)
	case "diff":
		return cmdDiff(args[1:], out)
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

// parseArgs parses flags that appear before, after or between the positional
// arguments. Go's flag package stops at the first non-flag word, which would
// silently ignore "vexdesk inventory sbom.json -json".
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func cmdInventory(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the inventory as JSON")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("inventory needs exactly one SBOM path")
	}

	inv, err := cyclonedx.ParseFile(positional[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(out, inv)
	}

	with, without := inv.Identifiable()
	fmt.Fprintf(out, "%s %s — %s\n", inv.Format, inv.Spec, describe(inv.Root))
	fmt.Fprintf(out, "%d components, %d direct, %d identifiable by package URL\n\n",
		len(inv.Components), len(inv.Direct()), len(with))

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "COMPONENT\tVERSION\tSCOPE\tPURL")
	for _, c := range inv.Components {
		scope := "transitive"
		if c.Direct {
			scope = "direct"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Name, orDash(c.Version), scope, orDash(c.PURL))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(without) > 0 {
		fmt.Fprintf(out, "\n%d component(s) carry no package URL and cannot be looked up.\n", len(without))
	}
	return nil
}

func cmdMatch(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	sbomPath := fs.String("sbom", "", "path to a CycloneDX SBOM")
	advDir := fs.String("advisories", "", "directory of OSV advisories")
	all := fs.Bool("all", false, "also show findings ruled out by version")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	exitZero := fs.Bool("exit-zero", false, "always exit 0, even when findings need attention")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := analyse(*sbomPath, *advDir)
	if err != nil {
		return err
	}

	shown := res.Attention()
	if *all {
		shown = res.Findings
	}
	if *asJSON {
		if err := writeJSON(out, res); err != nil {
			return err
		}
	} else {
		printFindings(out, res, shown)
	}
	if len(res.Attention()) > 0 && !*exitZero {
		return exitCode(1)
	}
	return nil
}

func printFindings(out io.Writer, res match.Result, shown []match.Finding) {
	fmt.Fprintf(out, "%d component(s) compared against the advisory set\n\n", res.Checked)
	if len(shown) == 0 {
		fmt.Fprintln(out, "Nothing needs attention.")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "STATUS\tADVISORY\tCOMPONENT\tVERSION\tREASON")
		for _, f := range shown {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				f.Status, f.Advisory, f.Component.Name, orDash(f.Component.Version), f.Reason)
		}
		tw.Flush()
	}
	if len(res.Skipped) > 0 {
		fmt.Fprintf(out, "\nNot checked (%d):\n", len(res.Skipped))
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, s := range res.Skipped {
			fmt.Fprintf(tw, "  %s\t%s\n", s.Component.Name, s.Reason)
		}
		tw.Flush()
	}
}

func cmdVex(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vex", flag.ContinueOnError)
	sbomPath := fs.String("sbom", "", "path to a CycloneDX SBOM")
	advDir := fs.String("advisories", "", "directory of OSV advisories")
	decisionsPath := fs.String("decisions", "", "path to a decisions file")
	author := fs.String("author", "", "who is issuing this document")
	outPath := fs.String("o", "", "write the document here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *author == "" {
		return fmt.Errorf("vex needs -author: a VEX document without an issuer cannot be trusted by its reader")
	}
	res, err := analyse(*sbomPath, *advDir)
	if err != nil {
		return err
	}

	var decisions []vex.Decision
	if *decisionsPath != "" {
		if decisions, err = vex.LoadDecisions(*decisionsPath); err != nil {
			return err
		}
	}

	statements := vex.Statements(res.Attention(), decisions)
	if len(statements) == 0 {
		return fmt.Errorf("nothing to state: no finding needs a VEX statement")
	}
	doc, err := openvex.New(*author, time.Now(), "vexdesk", statements)
	if err != nil {
		return err
	}
	body, err := doc.Encode()
	if err != nil {
		return err
	}
	if *outPath == "" {
		_, err = out.Write(body)
		return err
	}
	return os.WriteFile(*outPath, body, 0o644)
}

func cmdDiff(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the comparison as JSON")
	exitZero := fs.Bool("exit-zero", false, "always exit 0, even when the current document opens work")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		return fmt.Errorf("diff needs two VEX documents: the previous one and the current one")
	}

	before, err := openvex.ParseFile(positional[0])
	if err != nil {
		return err
	}
	after, err := openvex.ParseFile(positional[1])
	if err != nil {
		return err
	}

	d := vexdiff.Compare(before, after)
	if *asJSON {
		if err := writeJSON(out, d); err != nil {
			return err
		}
	} else {
		printDiff(out, d)
	}
	if len(d.NeedsAttention()) > 0 && !*exitZero {
		return exitCode(1)
	}
	return nil
}

func printDiff(out io.Writer, d vexdiff.Diff) {
	fmt.Fprintf(out, "%d change(s), %d claim(s) unchanged\n\n", len(d.Changes), d.Unchanged)
	if len(d.Changes) == 0 {
		fmt.Fprintln(out, "Both documents make the same claims.")
		return
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHANGE\tADVISORY\tPRODUCT\tDETAIL")
	for _, c := range d.Changes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Kind, c.Vulnerability(), c.Product(), c.Detail)
	}
	tw.Flush()

	attention := d.NeedsAttention()
	if len(attention) == 0 {
		return
	}
	fmt.Fprintf(out, "\nNeeds attention (%d):\n", len(attention))
	twa := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, c := range attention {
		fmt.Fprintf(twa, "  %s\t%s\t%s\n", c.Vulnerability(), c.Product(), c.Detail)
	}
	twa.Flush()
}

func analyse(sbomPath, advDir string) (match.Result, error) {
	if sbomPath == "" || advDir == "" {
		return match.Result{}, fmt.Errorf("both -sbom and -advisories are required")
	}
	inv, err := cyclonedx.ParseFile(sbomPath)
	if err != nil {
		return match.Result{}, err
	}
	advisories, err := osv.LoadDir(advDir)
	if err != nil {
		return match.Result{}, err
	}
	if len(advisories) == 0 {
		return match.Result{}, fmt.Errorf("no advisories found in %s", advDir)
	}
	return match.Run(inv, advisories), nil
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func describe(root inventory.Component) string {
	if root.Name == "" {
		return "product not named in the document"
	}
	if root.Version == "" {
		return root.Name
	}
	return root.Name + " " + root.Version
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
