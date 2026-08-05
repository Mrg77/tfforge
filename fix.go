package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Mrg77/tfforge/internal/agent"
	"github.com/Mrg77/tfforge/internal/anthropic"
	"github.com/Mrg77/tfforge/internal/guard"
	"github.com/Mrg77/tfforge/internal/tools"
	"github.com/Mrg77/tfforge/internal/trace"
)

// fixSystemPrompt drives the autonomous remediation loop. It is deliberately
// narrower than the interactive agent: FIX findings, nothing else. No planning,
// no applying — those tools aren't even in the toolset.
const fixSystemPrompt = `You are tfforge in AUTONOMOUS FIX mode, running in CI with NO human present.
Your only job: make the Terraform in the given directory pass the security scan.

Loop until clean or no further progress:
  1. SCAN — run security_scan to see the findings.
  2. FIX — for each finding, edit the code to resolve it. Prefer edit_file for a
     small change; use write_file to create a file or rewrite a large part.
     Apply the security defaults: private S3 + public-access block + encryption,
     least-privilege IAM (never Action "*"), encryption at rest, no hard-coded
     secrets (move them to variables), modern syntax (S3-native use_lockfile for
     backends, never a DynamoDB lock table).
  3. RE-SCAN. Repeat until the scan is clean, or until a finding genuinely can't
     be auto-fixed (e.g. "rotate this leaked credential" — a human action).

Rules:
  - You CANNOT plan, apply, or destroy — those tools are not available to you, by
    design. You only edit files and scan. Never claim you applied anything.
  - Change the SMALLEST thing that fixes each finding. Don't reformat or rewrite
    working code.
  - Be terse: you're writing to a CI log, not a person. When done, state which
    findings you fixed and which (if any) remain and why.
  - Stop as soon as the scan is clean or you can make no more progress. Do not
    loop pointlessly — you cost tokens.`

// runFix is the CI/autonomous remediation command:
//
//	tfforge fix <dir> [--fail-on <sev>] [--diff]
//
// The agent scans, fixes findings, and re-scans until clean — HEADLESS (no TTY),
// under a guard, with apply/plan/destroy REMOVED from its tools so it can never
// touch real infrastructure. Meant for a GitHub Action / pre-commit: it edits
// files in place; committing the result (or opening a PR) is the pipeline's job.
//
// Exit: 0 if the repo is clean at/above the --fail-on threshold after the run,
// 1 if findings remain (the fix was partial). Needs ANTHROPIC_API_KEY.
func runFix(args []string) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	failOn := fs.String("fail-on", "high", "exit non-zero if findings at/above this severity remain: info|low|medium|high|critical|none")
	showDiff := fs.Bool("diff", false, "print a unified diff of what changed (git diff if available)")
	maxTurns := fs.Int("max-turns", 40, "hard cap on agent turns (runaway guard)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tfforge fix <dir> [--fail-on <sev>] [--diff] [--max-turns N]")
	}

	dir, rest := splitDirAndFlags(args)
	if dir == "" {
		fs.Usage()
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "tfforge fix: %q is not a directory\n", dir)
		return 2
	}
	threshold, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "tfforge fix: invalid --fail-on %q\n", *failOn)
		return 2
	}

	// Snapshot the tree before the run, so --diff can show exactly what changed.
	before := snapshotTree(dir)

	client, err := anthropic.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfforge fix:", err)
		return 1
	}

	// Confine every file path under the target directory — the agent can't escape
	// to /etc or a sibling repo.
	abs, _ := absDir(dir)
	tools.SetProjectRoot(abs)

	// THE KEY SAFETY PROPERTY: the fix toolset has NO apply/plan/destroy. The
	// agent can read, edit, validate, and scan — and nothing that touches real
	// infrastructure or cloud credentials. This is what makes it safe to run
	// unattended in CI.
	toolset := []tools.Tool{
		tools.WriteFileTool{},
		tools.EditFileTool{},
		tools.ValidateTool{},
		tools.SecurityScanTool{},
	}

	// The guard still runs, and denies anything mutating by default — belt and
	// suspenders on top of the trimmed toolset. No TTY confirm: in CI there's no
	// human, so a "confirm" fails closed (deny).
	g := guard.New(guard.Default(), denyConfirm)

	tr, err := trace.New(client.Model(), auditLogPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfforge fix: could not open audit log:", err)
		return 1
	}
	defer tr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ag := agent.New(client, fixSystemPrompt, toolset, g, tr, os.Stderr)
	if v := os.Getenv("TFFORGE_MAX_COST"); v != "" {
		if usd, err := strconv.ParseFloat(v, 64); err == nil && usd > 0 {
			ag.SetBudget(usd)
		}
	}

	fmt.Fprintf(os.Stderr, "tfforge fix · model %s · %s\n\n", client.Model(), dir)
	task := fmt.Sprintf("Fix every security finding in the Terraform directory %q. Scan, edit, re-scan until clean or no more progress.", dir)
	runErr := ag.Run(ctx, task, *maxTurns)
	fmt.Fprintln(os.Stderr, "\n"+tr.Summary())
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "tfforge fix:", runErr)
		// fall through — still report the final scan state below
	}

	// Show what changed, if asked.
	if *showDiff {
		printDiff(dir, before)
	}

	// Final verdict from the DETERMINISTIC scan (not the model's word): re-scan and
	// gate on what actually remains.
	remaining := tools.AnalyzeDir(abs)
	max := tools.MaxSeverity(remaining)
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "tfforge fix: ✓ clean — no findings remain.")
		return 0
	}
	fmt.Fprintf(os.Stderr, "tfforge fix: %d finding(s) remain after auto-fix:\n", len(remaining))
	fmt.Fprintln(os.Stderr, tools.RenderFindings(remaining))
	if *failOn != "none" && max >= threshold {
		return 1 // partial fix — CI fails on what's left, a human decides
	}
	return 0
}

// denyConfirm is the CI confirmation handler: there is no human, so every
// action that would need confirmation is denied (fail-closed).
func denyConfirm(action, ctx, message string) bool { return false }

// absDir returns the absolute path of dir.
func absDir(dir string) (string, error) {
	if strings.HasPrefix(dir, "/") {
		return dir, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return dir, err
	}
	return wd + "/" + dir, nil
}
