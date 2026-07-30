package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// projectRoot is the directory tfforge is allowed to operate within. All
// tool-provided `dir` paths are confined under it, so a model (or a
// prompt-injected .tf file) can't point terraform at, say, /etc or an unrelated
// state file via `..` escape. Set at startup to the process working dir.
var projectRoot string

// SetProjectRoot fixes the confinement boundary. main() calls this once with the
// current working directory.
func SetProjectRoot(abs string) { projectRoot = abs }

// confine resolves dir to an absolute path and verifies it stays under
// projectRoot. Returns the safe absolute path, or an error if it escapes.
func confine(dir string) (string, error) {
	root := projectRoot
	if root == "" {
		root, _ = filepath.Abs(".")
	}
	abs := dir
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, dir)
	}
	abs = filepath.Clean(abs)
	rootClean := filepath.Clean(root)
	// abs must be root itself or a descendant of it.
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("directory %q is outside the allowed project root %q — tfforge won't operate there", dir, rootClean)
	}
	return abs, nil
}

// runTerraform executes a terraform (or tofu) subcommand in workdir and returns
// combined output. It never runs an interactive command — tfforge always drives
// terraform non-interactively (-input=false, -no-color) so output is clean and
// deterministic for the model to read.
func runTerraform(ctx context.Context, workdir string, args ...string) (string, error) {
	bin := "terraform"
	if _, err := exec.LookPath(bin); err != nil {
		if _, err2 := exec.LookPath("tofu"); err2 == nil {
			bin = "tofu"
		} else {
			return "", fmt.Errorf("neither terraform nor tofu found on PATH")
		}
	}
	full := append([]string{"-chdir=" + workdir}, args...)
	cmd := exec.CommandContext(ctx, bin, full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Terraform writes the useful diagnostic to output, so return it with the error.
		return string(out), fmt.Errorf("%s %s failed: %w", bin, strings.Join(args, " "), err)
	}
	return string(out), nil
}

// dirArg is the shared input schema fragment for tools that operate on a
// Terraform working directory.
func dirSchema(desc string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"dir": map[string]any{
				"type":        "string",
				"description": "Path to the Terraform working directory (contains .tf files).",
			},
		},
		"required":             []string{"dir"},
		"additionalProperties": false,
		"description":          desc,
	}
}

type dirInput struct {
	Dir string `json:"dir"`
}

// --- terraform_plan: the first tool. Read-only: shows what WOULD change. ------

// PlanTool runs `terraform plan`. It is read-only — it never touches real
// infrastructure — so the guard lets it run freely. It's the agent's primary
// way to understand the impact of a change before proposing anything.
type PlanTool struct{}

func (PlanTool) Name() string   { return "terraform_plan" }
func (PlanTool) Danger() Danger { return ReadOnly }
func (PlanTool) Description() string {
	return "Run `terraform plan` in a working directory and return the plan output. " +
		"Read-only: shows what would be created/changed/destroyed without applying anything. " +
		"Use this to understand the impact of the current configuration before proposing any change."
}
func (PlanTool) Schema() map[string]any {
	return dirSchema("Show the execution plan for a Terraform working directory.")
}
func (PlanTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in dirInput
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	dir, err := confine(in.Dir) // reject paths outside the project root
	if err != nil {
		return "", err
	}
	// -input=false so it never blocks on a prompt; -no-color for clean text.
	return runTerraform(ctx, dir, "plan", "-input=false", "-no-color")
}

// --- terraform_apply: MUTATING. Creates/updates real resources. Guarded. ------

// ApplyTool runs `terraform apply -auto-approve`. It is mutating, so it goes
// through the guard (which confirms on prod). The agent never bypasses that —
// the loop routes every tool through the guard before Run is called.
type ApplyTool struct{}

func (ApplyTool) Name() string   { return "terraform_apply" }
func (ApplyTool) Danger() Danger { return Mutating }
func (ApplyTool) Description() string {
	return "Run `terraform apply` in a working directory to create or update real infrastructure. " +
		"MUTATING: this changes real resources. It is subject to the safety policy and may require approval."
}
func (ApplyTool) Schema() map[string]any {
	return dirSchema("Apply the Terraform configuration in a working directory.")
}
func (ApplyTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in dirInput
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	dir, err := confine(in.Dir)
	if err != nil {
		return "", err
	}
	return runTerraform(ctx, dir, "apply", "-input=false", "-no-color", "-auto-approve")
}

// --- terraform_destroy: DESTRUCTIVE. Tears infra down. Guarded (deny on prod). -

// DestroyTool runs `terraform destroy -auto-approve`. Destructive: the default
// policy DENIES it on a production context and confirms it elsewhere.
type DestroyTool struct{}

func (DestroyTool) Name() string   { return "terraform_destroy" }
func (DestroyTool) Danger() Danger { return Destructive }
func (DestroyTool) Description() string {
	return "Run `terraform destroy` in a working directory to tear down infrastructure. " +
		"DESTRUCTIVE: this deletes real resources. It is blocked on production contexts by the safety policy."
}
func (DestroyTool) Schema() map[string]any {
	return dirSchema("Destroy the infrastructure managed in a working directory.")
}
func (DestroyTool) Run(ctx context.Context, input json.RawMessage) (string, error) {
	var in dirInput
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	dir, err := confine(in.Dir)
	if err != nil {
		return "", err
	}
	return runTerraform(ctx, dir, "destroy", "-input=false", "-no-color", "-auto-approve")
}
