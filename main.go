// Command tfforge is an AI agent that BUILDS, validates, and secures Terraform —
// with a safety layer it can't bypass. It can generate infrastructure code
// itself, validate it, scan it for security issues (checkov/trivy/tfsec plus
// provider-aware checks), and auto-correct until it's clean — while every
// destructive action passes through policy-as-code guards, so the agent can help
// without being able to wreck production.
//
// Usage:
//
//	export ANTHROPIC_API_KEY=...   # from console.anthropic.com (billed per token)
//	tfforge "build a private, encrypted S3 bucket in ./examples/demo, scan it, and fix any findings"
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Mrg77/tfforge/internal/agent"
	"github.com/Mrg77/tfforge/internal/anthropic"
	"github.com/Mrg77/tfforge/internal/guard"
	"github.com/Mrg77/tfforge/internal/tools"
	"github.com/Mrg77/tfforge/internal/trace"
)

const systemPrompt = `You are tfforge, an AI agent that BUILDS, validates, and secures
Terraform infrastructure for a DevOps engineer — and does so safely.

You can write Terraform code yourself and iterate on it. When asked to build or fix
infrastructure, follow this loop until the result is clean:

  1. GENERATE — write the Terraform to write_file (idiomatic HCL, sensible defaults,
     security-first: private by default, encryption on, least-privilege IAM).
  2. VALIDATE — run terraform_validate. If it fails, fix the code and re-validate.
  3. SECURE — run security_scan (checkov/trivy/tfsec + provider-aware checks).
  4. AUTO-CORRECT — if the scan reports findings, REWRITE the code to fix them
     (write_file again) and scan AGAIN. Repeat until the scan is clean or only
     acceptable, explicitly-justified findings remain.
  5. PLAN — run terraform_plan to show what would be created/changed.
  6. Only apply/destroy if explicitly asked; those pass through the safety policy.

Security defaults you always apply when generating code:
  - S3: private ACL + public-access block + server-side encryption.
  - IAM: never Action "*" or Resource "*" — scope to what's needed.
  - Databases/volumes: encryption at rest on.
  - Never hard-code secrets in .tf — use variables.

Principles:
  - Understand before acting; be precise and concise; lead with the verdict.
  - You operate under a safety guard: destructive actions may be blocked by policy.
    If a tool is BLOCKED, do not retry it — explain and propose a safer path.
  - Never invent tool output — only report what the tools actually return. When you
    fix a finding, say which finding and how you fixed it.`

func main() {
	if len(os.Args) < 2 || strings.TrimSpace(strings.Join(os.Args[1:], " ")) == "" {
		fmt.Fprintln(os.Stderr, "usage: tfforge \"<task>\"")
		fmt.Fprintln(os.Stderr, "example: tfforge \"run the plan in ./examples/staging and explain what would change\"")
		os.Exit(2)
	}
	task := strings.Join(os.Args[1:], " ")

	client, err := anthropic.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfforge:", err)
		os.Exit(1)
	}

	// Confine every tool-provided path under the current working directory, so
	// a model can't point terraform at an unrelated directory (e.g. /etc) or
	// escape via `..`. This holds even for read-only tools (which bypass the guard).
	if wd, err := os.Getwd(); err == nil {
		tools.SetProjectRoot(wd)
	}
	// Render the plan table for the human on stdout (the agent gets only a
	// compact digest, so a huge plan doesn't blow the context or the token bill).
	tools.SetPlanOutput(os.Stdout)

	// The tool set: generate + validate + scan (the build/secure loop), plus
	// read-only analysis and guarded mutating/destructive actions.
	toolset := []tools.Tool{
		tools.WriteFileTool{},    // generate & auto-correct code
		tools.ValidateTool{},     // syntax gate
		tools.SecurityScanTool{}, // checkov/trivy/tfsec + provider-aware
		tools.PlanTool{},         // impact preview
		tools.ApplyTool{},        // guarded
		tools.DestroyTool{},      // guarded (deny on prod)
	}

	// The guard: policy-as-code (the same idea as opsforge's shell guards). The
	// default policy denies destroy on prod and confirms apply on prod. A
	// "confirm" prompts the human on the TTY; with no TTY it fails safe (deny).
	g := guard.New(guard.Default(), ttyConfirm)

	// The tracer: an audit log (every turn + tool + guard decision, JSONL) and
	// run cost accounting. This is the LLMOps layer — reviewability + spend
	// visibility. Set TFFORGE_AUDIT=off to skip the file (summary still prints).
	tr, err := trace.New(client.Model(), auditLogPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfforge: could not open audit log:", err)
		os.Exit(1)
	}
	defer tr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ag := agent.New(client, systemPrompt, toolset, g, tr, os.Stdout)

	fmt.Printf("tfforge · model %s\n\n", client.Model())
	// A build+validate+scan+autocorrect cycle can take several tool round-trips;
	// give the loop room while still bounding it against runaway.
	runErr := ag.Run(ctx, task, 30)

	// Always print the run summary (turns, tokens, guard actions, cost) — even
	// on error, so a failed run's spend is still visible.
	fmt.Fprintln(os.Stderr, "\n"+tr.Summary())
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "tfforge:", runErr)
		os.Exit(1)
	}
}

// auditLogPath returns the audit-log destination, or "" when disabled via
// TFFORGE_AUDIT=off (or an explicit path via TFFORGE_AUDIT=/some/file).
func auditLogPath() string {
	switch v := os.Getenv("TFFORGE_AUDIT"); v {
	case "off", "0", "false":
		return ""
	case "":
		return trace.DefaultLogPath()
	default:
		return v
	}
}

// ttyConfirm asks the human to approve a guarded action. If stdin isn't a
// terminal (CI, a pipe), it returns false — fail-safe: never auto-approve a
// mutating/destructive action without a human.
func ttyConfirm(action, ctx, message string) bool {
	fmt.Fprintf(os.Stderr, "\n⚠  The agent wants to run: %s", action)
	if ctx != "" {
		fmt.Fprintf(os.Stderr, "  (context: %s)", ctx)
	}
	fmt.Fprintf(os.Stderr, "\n   %s\n   Proceed? [y/N] ", message)

	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(sc.Text()))
	return answer == "y" || answer == "yes"
}
