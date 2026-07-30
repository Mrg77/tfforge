// Command tfforge is an AI agent that builds and analyzes Terraform — with a
// safety layer. It reasons over your infrastructure (plan, analyze, and soon
// build), but every destructive action passes through policy-as-code guards and
// is traced, so the agent can help without being able to wreck production.
//
// This first cut is the bare agentic loop with a single read-only tool
// (terraform_plan), so you can watch an agent reason end-to-end. The guard,
// security scanning (tfsec/checkov), and build tools land in the next steps.
//
// Usage:
//
//	export ANTHROPIC_API_KEY=...      # from console.anthropic.com (billed per token)
//	tfforge "analyze the plan in ./examples/staging and explain the impact"
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"bufio"

	"github.com/Mrg77/tfforge/internal/agent"
	"github.com/Mrg77/tfforge/internal/anthropic"
	"github.com/Mrg77/tfforge/internal/guard"
	"github.com/Mrg77/tfforge/internal/tools"
)

const systemPrompt = `You are tfforge, an AI agent for Terraform infrastructure.
You help a DevOps engineer understand, analyze, and safely change Terraform.

Principles:
- Understand before acting: run terraform_plan to see real impact before proposing anything.
- Be precise and concise. Lead with the verdict, then the reasoning.
- You operate under a safety guard: destructive actions may be blocked by policy.
  If a tool is BLOCKED, do not retry it — explain the situation and propose a safer path.
- Never invent resource names, values, or plan output — only report what the tools return.`

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

	// The tool set: read-only analysis + guarded mutating/destructive actions.
	toolset := []tools.Tool{
		tools.PlanTool{},
		tools.ApplyTool{},
		tools.DestroyTool{},
	}

	// The guard: policy-as-code (the same idea as opsforge's shell guards). The
	// default policy denies destroy on prod and confirms apply on prod. A
	// "confirm" prompts the human on the TTY; with no TTY it fails safe (deny).
	g := guard.New(guard.Default(), ttyConfirm)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ag := agent.New(client, systemPrompt, toolset, g, nil, os.Stdout)

	fmt.Printf("tfforge · model %s\n\n", client.Model())
	if err := ag.Run(ctx, task, 12); err != nil {
		fmt.Fprintln(os.Stderr, "\ntfforge:", err)
		os.Exit(1)
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
