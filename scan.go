package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Mrg77/tfforge/internal/tools"
)

// runScan is the CI mode: `tfforge scan <dir> [--json] [--fail-on <sev>]`.
//
// It runs the DETERMINISTIC security analysis only — NO LLM, no API key, no
// tokens — and exits non-zero when findings at or above the threshold exist, so
// it can gate a pipeline. This is the "I think in integration, not just an
// interactive demo" piece: the same security brain the agent uses, callable
// straight from CI.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit findings as JSON (for CI parsing)")
	failOn := fs.String("fail-on", "high", "exit non-zero at or above this severity: info|low|medium|high|critical|none")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tfforge scan <dir> [--json] [--fail-on info|low|medium|high|critical|none]")
	}
	// Accept flags in any position (before or after the dir) — friendlier than
	// Go's default "flags must come first". We pull the single positional dir out
	// and let flag parse the rest.
	dir, rest := splitDirAndFlags(args)
	if dir == "" {
		fs.Usage()
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "tfforge scan: %q is not a directory\n", dir)
		return 2
	}

	threshold, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "tfforge scan: invalid --fail-on %q\n", *failOn)
		return 2
	}

	findings := tools.AnalyzeDir(dir)
	max := tools.MaxSeverity(findings)

	if *asJSON {
		emitJSON(dir, findings, max)
	} else {
		emitText(dir, findings)
	}

	// Gate: exit non-zero if the worst finding is at/above the threshold.
	// --fail-on=none never fails (report-only).
	if *failOn != "none" && len(findings) > 0 && max >= threshold {
		return 1
	}
	return 0
}

func emitText(dir string, findings []tools.Finding) {
	if len(findings) == 0 {
		fmt.Printf("tfforge scan: %s — no findings from the provider-aware analysis.\n", dir)
		return
	}
	fmt.Printf("tfforge scan: %s — %d finding(s)\n", dir, len(findings))
	fmt.Println(tools.RenderFindings(findings))
}

// scanReport is the JSON shape emitted for CI.
type scanReport struct {
	Dir         string          `json:"dir"`
	Findings    []tools.Finding `json:"findings"`
	Count       int             `json:"count"`
	MaxSeverity string          `json:"max_severity"`
}

func emitJSON(dir string, findings []tools.Finding, max tools.Severity) {
	if findings == nil {
		findings = []tools.Finding{}
	}
	out, _ := json.MarshalIndent(scanReport{
		Dir:         dir,
		Findings:    findings,
		Count:       len(findings),
		MaxSeverity: max.String(),
	}, "", "  ")
	fmt.Println(string(out))
}

// valueFlags are the flags across scan/audit that take a SEPARATE value token
// (`--flag value`). splitDirAndFlags must keep that value with the flags so it
// isn't captured as the positional <dir>. The `--flag=value` form is a single
// token and never needs listing here.
var valueFlags = map[string]bool{
	"--fail-on": true, "-fail-on": true,
	"--top": true, "-top": true,
	"--out": true, "-out": true,
}

// splitDirAndFlags separates the single positional <dir> argument from the
// flags, so they can appear in any order (`scan dir --json` or `scan --json dir`).
// Returns the dir and the remaining flag args. A flag that takes a value
// (see valueFlags) is handled by leaving both tokens in rest for flag to parse.
func splitDirAndFlags(args []string) (dir string, rest []string) {
	skipNext := false
	for i, a := range args {
		if skipNext {
			rest = append(rest, a)
			skipNext = false
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			rest = append(rest, a)
			// Flags that take a SEPARATE value token (e.g. `--fail-on high`,
			// `--top 20`, `--out f.html`): keep the next token with the flags so
			// it isn't mistaken for the positional <dir>. `--flag=value` is one
			// token and doesn't need this.
			if valueFlags[a] {
				skipNext = true
			}
			continue
		}
		if dir == "" {
			dir = a // the first non-flag token is the dir
		} else {
			rest = append(rest, args[i:]...) // extra positional → let flag error
			break
		}
	}
	return dir, rest
}

// parseSeverity maps a flag string to a Severity (plus a "none" sentinel that
// callers handle separately).
func parseSeverity(s string) (tools.Severity, bool) {
	switch s {
	case "info":
		return tools.SevInfo, true
	case "low":
		return tools.SevLow, true
	case "medium":
		return tools.SevMedium, true
	case "high":
		return tools.SevHigh, true
	case "critical":
		return tools.SevCritical, true
	case "none":
		return tools.SevCritical, true // threshold unused; --fail-on=none checked separately
	default:
		return tools.SevInfo, false
	}
}
