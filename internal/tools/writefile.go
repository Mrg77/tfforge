package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileTool lets the agent create or overwrite a file — this is how tfforge
// GENERATES and, crucially, AUTO-CORRECTS Terraform code: it writes .tf, scans
// it, and when the scan flags something, it writes an improved version and
// scans again. That rewrite loop is the "build" capability.
//
// It is classified Mutating (it changes the filesystem) but writes are confined
// under the project root and restricted to text config files, so the agent
// can't drop a file outside the project or overwrite arbitrary system paths.
// The guard still sees it as Mutating; on a prod-named dir the policy applies.
type WriteFileTool struct{}

func (WriteFileTool) Name() string   { return "write_file" }
func (WriteFileTool) Danger() Danger { return Mutating }
func (WriteFileTool) Description() string {
	return "Create or overwrite a text file (typically a Terraform .tf file) with the given " +
		"content. Use this to generate infrastructure code and to APPLY FIXES after a security " +
		"scan: write the corrected code, then scan again. Paths are confined to the project."
}
func (WriteFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "File path (relative to the project), e.g. \"examples/demo/main.tf\".",
			},
			"content": map[string]any{
				"type":        "string",
				"description": "The full file content to write.",
			},
		},
		"required":             []string{"path", "content"},
		"additionalProperties": false,
	}
}

// allowedExt is the set of file types the agent may write — config/text only,
// never executables or dotfiles that could alter behavior outside Terraform.
var allowedExt = map[string]bool{
	".tf": true, ".tfvars": true, ".hcl": true, ".json": true,
	".yaml": true, ".yml": true, ".md": true, ".txt": true,
}

func (WriteFileTool) Run(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	// Confine the containing directory under the project root (reuses the same
	// boundary as the terraform tools), then re-join the base name.
	dir, err := confine(filepath.Dir(in.Path))
	if err != nil {
		return "", err
	}
	base := filepath.Base(in.Path)
	if base == "" || strings.HasPrefix(base, ".") {
		return "", fmt.Errorf("refusing to write %q (no dotfiles / empty name)", base)
	}
	if ext := strings.ToLower(filepath.Ext(base)); !allowedExt[ext] {
		return "", fmt.Errorf("refusing to write %q: only config/text files are allowed (.tf, .tfvars, .hcl, .json, .yaml, .md, .txt)", base)
	}

	full := filepath.Join(dir, base)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(full, []byte(in.Content), 0o644); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d bytes to %s", len(in.Content), filepath.Join(filepath.Base(dir), base)), nil
}
