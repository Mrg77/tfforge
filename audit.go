package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/Mrg77/tfforge/internal/repo"
	"github.com/Mrg77/tfforge/internal/tools"
)

// colorStdout reports whether to colorize stdout (a TTY and NO_COLOR unset).
func colorStdout() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// runAudit is the "adopt an existing repo" command:
//
//	tfforge audit <repo> [--json] [--html [--out f]] [--explain] [--top N] [--fail-on <sev>]
//
// It walks a WHOLE Terraform repository (modules, environments), runs the
// deterministic analysis on every directory, and produces a PRIORITIZED health
// report — where to start, not a flat dump. No LLM, no tokens, so it gates CI.
//
// Output modes:
//   - default: a colored text report on stdout.
//   - --json:  machine-readable, for CI.
//   - --html:  a self-contained, shareable HTML report (written to --out, or
//     printed to stdout). This is the deliverable you attach or open in a browser.
//
// --explain adds the OPTIONAL AI layer: if ANTHROPIC_API_KEY is set, each finding
// gets a concrete modern-fix explanation from the model. Everything above works
// with zero tokens; --explain is the "peaufinage IA" on top of the deterministic
// core — exactly "the deterministic detects, the AI explains".
func runAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON (for CI)")
	asHTML := fs.Bool("html", false, "emit a self-contained, shareable HTML report")
	asMarkdown := fs.Bool("markdown", false, "emit a GitHub-flavored Markdown report (for a CI job summary)")
	out := fs.String("out", "", "write the report to this file instead of stdout (great with --html)")
	explain := fs.Bool("explain", false, "enrich each finding with an AI-written fix (needs ANTHROPIC_API_KEY; costs tokens)")
	top := fs.Int("top", 10, "how many top findings to show (text report only; HTML/JSON list all)")
	failOn := fs.String("fail-on", "none", "exit non-zero at/above this severity: info|low|medium|high|critical|none")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tfforge audit <repo> [--json] [--html] [--out FILE] [--explain] [--top N] [--fail-on <sev>]")
	}

	dir, rest := splitDirAndFlags(args)
	if dir == "" {
		fs.Usage()
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "tfforge audit: %q is not a directory\n", dir)
		return 2
	}

	// Confine the analysis under the current working directory (reuses the tools
	// boundary used by the agent).
	if abs, err := os.Getwd(); err == nil {
		tools.SetProjectRoot(abs)
	}

	rep, err := repo.Audit(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfforge audit:", err)
		return 1
	}

	// Optional AI layer: explain the findings. Deterministic report is already
	// built above, so if this fails we still have the full report. cost carries
	// the FinOps summary of the call, shown in the HTML footer.
	var enrich map[string]repo.Enrichment
	var cost *repo.ExplainCost
	if *explain {
		var stats *explainStats
		enrich, stats = explainFindings(rep)
		if stats != nil {
			cost = &repo.ExplainCost{Model: stats.Model, InTok: stats.InTok, OutTok: stats.OutTok, USD: stats.Cost}
		}
	}

	// Render.
	var content string
	switch {
	case *asHTML:
		content = rep.HTML(enrich, cost)
	case *asMarkdown:
		content = rep.Markdown(enrich, cost)
	case *asJSON:
		content = rep.JSON()
	default:
		// Text to a file shouldn't carry ANSI codes; only colorize a TTY stdout.
		content = rep.Text(*top, *out == "" && colorStdout())
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "tfforge audit:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "tfforge audit: wrote %s (%d findings) → %s\n", reportKind(*asHTML, *asJSON), len(rep.Findings), *out)
	} else {
		fmt.Println(content)
	}

	// Gate for CI: --fail-on=none is report-only (the default for an audit — you
	// want to SEE the health, not fail the build, unless you ask for it).
	threshold, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "tfforge audit: invalid --fail-on %q\n", *failOn)
		return 2
	}
	if *failOn != "none" && rep.MaxSeverity() >= threshold && len(rep.Findings) > 0 {
		return 1
	}
	return 0
}

func reportKind(html, json bool) string {
	switch {
	case html:
		return "HTML report"
	case json:
		return "JSON report"
	default:
		return "text report"
	}
}
