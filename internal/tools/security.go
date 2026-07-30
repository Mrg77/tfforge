package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// --- terraform_validate: read-only. Is the configuration syntactically valid? -

// ValidateTool runs `terraform validate` (after an init if needed). Read-only:
// it checks the configuration is internally consistent, without touching infra.
// It's the first gate in the build loop — no point scanning code that won't parse.
type ValidateTool struct{}

func (ValidateTool) Name() string   { return "terraform_validate" }
func (ValidateTool) Danger() Danger { return ReadOnly }
func (ValidateTool) Description() string {
	return "Run `terraform validate` in a working directory to check the configuration is " +
		"syntactically valid and internally consistent. Read-only. Run this after writing or " +
		"editing .tf files, before scanning or planning."
}
func (ValidateTool) Schema() map[string]any {
	return dirSchema("Validate the Terraform configuration in a working directory.")
}
func (ValidateTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in dirInput
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	dir, err := confine(in.Dir)
	if err != nil {
		return "", err
	}
	// Validate needs the providers initialized. Init is safe (no apply) and
	// idempotent; -backend=false keeps it offline/local.
	if out, err := runTerraform(ctx, dir, "init", "-input=false", "-no-color", "-backend=false"); err != nil {
		return out, fmt.Errorf("terraform init (for validate) failed: %w", err)
	}
	return runTerraform(ctx, dir, "validate", "-no-color")
}

// --- security_scan: read-only. Static security analysis of the Terraform code. -

// SecurityScanTool runs a static IaC security scanner over the Terraform code
// and returns its findings. It is the heart of the build loop's "secure" step:
// the agent writes code, scans it, and — if findings appear — rewrites and
// re-scans until clean.
//
// It is TOOL-TOLERANT: it uses the best scanner installed (checkov preferred,
// then trivy, then tfsec), so tfforge works with whatever the machine has, and
// says so clearly when none is present. On top of the scanner it adds a small
// provider-aware IAM/exposure heuristic pass (see analyzeIAM) for the classics
// scanners sometimes phrase obscurely: wildcard IAM, public S3, missing encryption.
type SecurityScanTool struct{}

func (SecurityScanTool) Name() string   { return "security_scan" }
func (SecurityScanTool) Danger() Danger { return ReadOnly }
func (SecurityScanTool) Description() string {
	return "Statically scan the Terraform code in a working directory for security issues " +
		"(uses checkov, trivy, or tfsec — whichever is installed) and add a provider-aware " +
		"check for classic risks (wildcard IAM permissions, public S3 buckets, missing " +
		"encryption). Read-only. Use this after validate; if it reports issues, FIX the code " +
		"and scan again until it is clean."
}
func (SecurityScanTool) Schema() map[string]any {
	return dirSchema("Run a static security scan over the Terraform code in a working directory.")
}
func (SecurityScanTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in dirInput
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	dir, err := confine(in.Dir)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	scanner, out := runBestScanner(ctx, dir)
	if scanner == "" {
		fmt.Fprintln(&b, "No IaC security scanner found (install one of: checkov, trivy, tfsec).")
		fmt.Fprintln(&b, "Tip: `opsforge install checkov` — running the provider-aware heuristics only.")
	} else {
		fmt.Fprintf(&b, "=== %s ===\n%s\n", scanner, strings.TrimSpace(out))
	}

	// Always run the lightweight provider-aware pass on top.
	if iam := analyzeTerraformDir(dir); iam != "" {
		fmt.Fprintf(&b, "\n=== provider-aware checks (tfforge) ===\n%s\n", iam)
	}
	return b.String(), nil
}

// runBestScanner tries the installed scanners in order of preference and returns
// the scanner name used + its output. Empty name = none installed.
func runBestScanner(ctx context.Context, dir string) (string, string) {
	// checkov: the Terraform-focused reference. -q quiets the banner; --compact
	// keeps output small for the model; exit code is non-zero on findings, which
	// we IGNORE (findings are the signal, not an error).
	if _, err := exec.LookPath("checkov"); err == nil {
		out, _ := exec.CommandContext(ctx, "checkov", "-d", dir, "--quiet", "--compact").CombinedOutput()
		return "checkov", string(out)
	}
	// trivy: the successor to tfsec, scans IaC via `trivy config`.
	if _, err := exec.LookPath("trivy"); err == nil {
		out, _ := exec.CommandContext(ctx, "trivy", "config", "--no-progress", dir).CombinedOutput()
		return "trivy", string(out)
	}
	// tfsec: deprecated but still works.
	if _, err := exec.LookPath("tfsec"); err == nil {
		out, _ := exec.CommandContext(ctx, "tfsec", dir, "--no-color", "--concise-output").CombinedOutput()
		return "tfsec", string(out)
	}
	return "", ""
}
