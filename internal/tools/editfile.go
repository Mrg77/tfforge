package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EditFileTool does a surgical search/replace in an existing file, so the agent
// can fix ONE line without regenerating the whole file. This is a big
// token-saver: a small fix costs a small edit, not a full rewrite of a
// 100-line .tf. Prefer this over write_file when only a part changes.
//
// Mutating (it changes the filesystem), path-confined like the other tools.
type EditFileTool struct{}

func (EditFileTool) Name() string   { return "edit_file" }
func (EditFileTool) Danger() Danger { return Mutating }
func (EditFileTool) Description() string {
	return "Replace an exact snippet in an existing file (surgical fix). Prefer this over " +
		"write_file when only part of a file changes — it's far cheaper than rewriting the whole " +
		"file. `old` must appear EXACTLY once in the file; the tool errors otherwise so a fix is " +
		"never applied to the wrong place."
}
func (EditFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "File path (relative to the project)."},
			"old":  map[string]any{"type": "string", "description": "The exact text to replace (must occur exactly once)."},
			"new":  map[string]any{"type": "string", "description": "The replacement text."},
		},
		"required":             []string{"path", "old", "new"},
		"additionalProperties": false,
	}
}

func (EditFileTool) Run(_ context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Path string `json:"path"`
		Old  string `json:"old"`
		New  string `json:"new"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}
	if in.Path == "" || in.Old == "" {
		return "", fmt.Errorf("path and old are required")
	}
	dir, err := confine(filepath.Dir(in.Path))
	if err != nil {
		return "", err
	}
	base := filepath.Base(in.Path)
	if ext := strings.ToLower(filepath.Ext(base)); !allowedExt[ext] {
		return "", fmt.Errorf("refusing to edit %q: only config/text files are allowed", base)
	}
	full := filepath.Join(dir, base)

	data, err := os.ReadFile(full)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", base, err)
	}
	content := string(data)

	// old must match exactly once — otherwise the fix is ambiguous and we refuse
	// rather than edit the wrong occurrence.
	n := strings.Count(content, in.Old)
	switch {
	case n == 0:
		return "", fmt.Errorf("the `old` snippet was not found in %s — read the file and copy it exactly", base)
	case n > 1:
		return "", fmt.Errorf("the `old` snippet appears %d times in %s — include more surrounding context so it's unique", n, base)
	}

	updated := strings.Replace(content, in.Old, in.New, 1)
	if err := os.WriteFile(full, []byte(updated), 0o644); err != nil {
		return "", err
	}
	return fmt.Sprintf("edited %s (1 replacement)", base), nil
}
