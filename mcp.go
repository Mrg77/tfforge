package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mrg77/tfforge/internal/mcp"
	"github.com/Mrg77/tfforge/internal/repo"
	"github.com/Mrg77/tfforge/internal/tools"
)

// runMCP serves the deterministic checks over the Model Context Protocol, so an
// assistant can call them directly instead of shelling out and parsing text.
//
// Only what reads is exposed. An MCP server is driven by a model, usually
// without a human approving each call, so `fix`, `apply` and `destroy` stay
// behind the CLI where the policy guard actually runs. Exposing them here would
// leave the guard in place and simply never consult it.
//
// `drift` is the one that deserves a word: it runs `tofu plan`, so it needs
// cloud credentials and touches the real infrastructure — read-only, but not
// free and not offline. Its description says so, because a model choosing
// between tools should know which one costs an API round-trip to AWS.
func runMCP(args []string) int {
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	tools.SetProjectRoot(root)

	dirSchema := func(desc string) map[string]any {
		return map[string]any{
			"type": "object",
			"properties": map[string]any{
				"dir": map[string]any{"type": "string", "description": desc},
			},
			"additionalProperties": false,
		}
	}

	// findingsJSON gives the model the same shape the other *forge tools emit,
	// so one assistant can reason across all three without special-casing.
	findingsJSON := func(fs []tools.Finding) any {
		type out struct {
			Severity string `json:"severity"`
			Category string `json:"category"`
			File     string `json:"file"`
			Message  string `json:"message"`
		}
		list := make([]out, 0, len(fs))
		worst := ""
		rank := map[string]int{"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
		for _, f := range fs {
			sev := strings.ToLower(f.Severity)
			list = append(list, out{sev, string(f.Category), f.File, f.Message})
			if rank[strings.ToUpper(f.Severity)] > rank[strings.ToUpper(worst)] {
				worst = sev
			}
		}
		if worst == "" {
			worst = "none"
		}
		var v any
		b, _ := json.Marshal(map[string]any{
			"count": len(fs), "max_severity": worst, "findings": list,
		})
		_ = json.Unmarshal(b, &v)
		return v
	}

	scan := func(args map[string]any) (string, any, error) {
		dir, _ := args["dir"].(string)
		if dir == "" {
			dir = "."
		}
		abs := dir
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, dir)
		}
		findings := tools.AnalyzeDir(abs)
		var b strings.Builder
		if len(findings) == 0 {
			b.WriteString("no findings in " + dir + " (deterministic checks only — not a proof of safety)")
		} else {
			fmt.Fprintf(&b, "%d finding(s) in %s:\n", len(findings), dir)
			for _, f := range findings {
				fmt.Fprintf(&b, "  [%s·%s] %s — %s\n", f.Severity, f.Category, f.File, f.Message)
			}
		}
		return b.String(), findingsJSON(findings), nil
	}

	audit := func(args map[string]any) (string, any, error) {
		dir, _ := args["dir"].(string)
		if dir == "" {
			dir = root
		} else if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, dir)
		}
		r, err := repo.Audit(dir)
		if err != nil {
			return "", nil, err
		}
		// No colour: the text goes into a model's context, not a terminal.
		return r.Text(0, false), findingsJSON(r.Findings), nil
	}

	srv := &mcp.Server{
		Name:    "tfforge",
		Version: version,
		Tools: []mcp.Tool{
			{
				Name: "terraform_scan",
				Description: "Scan one Terraform/OpenTofu directory for security and best-practice issues: secrets " +
					"hard-coded in .tf, IAM policies granting Resource \"*\" or service-wide wildcards, encryption " +
					"left off, missing provider pins. Deterministic, offline, read-only — it changes nothing and " +
					"needs no cloud credentials.",
				InputSchema: dirSchema("Directory to scan, relative to the project root. Defaults to the root."),
				Run:         scan,
			},
			{
				Name: "terraform_audit",
				Description: "Walk a whole Terraform tree and return a prioritised report across security, " +
					"best-practice and structure. Use this to answer \"what is wrong with this repository\"; use " +
					"terraform_scan when one directory is in question. Deterministic, offline, read-only.",
				InputSchema: dirSchema("Repository root to audit. Defaults to the project root."),
				Run:         audit,
			},
		},
	}

	fmt.Fprintf(os.Stderr, "tfforge mcp · serving %d read-only tool(s) on stdio · root %s\n", len(srv.Tools), root)
	return srv.Run()
}
