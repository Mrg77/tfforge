package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// treeSnapshot maps a .tf file path to its content, taken before the fix run so
// we can show exactly what the agent changed (for the --diff flag and CI logs).
type treeSnapshot map[string]string

// snapshotTree records the current content of every .tf file under dir.
func snapshotTree(dir string) treeSnapshot {
	snap := treeSnapshot{}
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".tf") {
			return nil
		}
		if data, err := os.ReadFile(path); err == nil {
			snap[path] = string(data)
		}
		return nil
	})
	return snap
}

// printDiff shows what changed since the snapshot. It prefers `git diff` (clean,
// familiar unified format) when the directory is inside a git repo; otherwise it
// falls back to a simple per-file added/modified summary from the snapshot.
func printDiff(dir string, before treeSnapshot) {
	if gitDiff(dir) {
		return
	}
	// Fallback: compare current tree to the snapshot.
	after := snapshotTree(dir)
	var changed, added []string
	for path, now := range after {
		old, existed := before[path]
		switch {
		case !existed:
			added = append(added, path)
		case old != now:
			changed = append(changed, path)
		}
	}
	if len(changed) == 0 && len(added) == 0 {
		fmt.Fprintln(os.Stderr, "tfforge fix: no files changed.")
		return
	}
	fmt.Fprintln(os.Stderr, "\ntfforge fix: changes")
	for _, p := range added {
		fmt.Fprintf(os.Stderr, "  + %s (new)\n", p)
	}
	for _, p := range changed {
		fmt.Fprintf(os.Stderr, "  ~ %s (modified)\n", p)
	}
}

// gitDiff runs `git diff -- <dir>` and prints it, returning true if git was
// available and the directory is tracked. Returns false to trigger the fallback.
func gitDiff(dir string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Is this inside a git work tree?
	check := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	if out, err := check.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "true" {
		return false
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "diff", "--", ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		fmt.Fprintln(os.Stderr, "tfforge fix: no files changed.")
		return true
	}
	fmt.Fprintln(os.Stderr, "\ntfforge fix: diff")
	fmt.Fprint(os.Stderr, string(out))
	return true
}
