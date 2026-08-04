// Package repo audits an EXISTING Terraform repository — the killer feature that
// turns tfforge from a code generator into a daily tool. Real DevOps work is
// almost never a blank file: it's inheriting a repo with modules, multiple
// environments, and years of drift, and asking "where do I even start?".
//
// audit walks the whole tree, runs the deterministic analysis on every directory
// that holds .tf files (per module / per environment), aggregates the findings,
// and produces a PRIORITIZED health report — the top things to fix first, in
// order, with counts by category — rather than a flat dump of 50 issues.
//
// Deterministic by design: no LLM, no tokens, so it can gate CI. The agent's
// optional --fix/--explain layer sits on top of this report.
package repo

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mrg77/tfforge/internal/tools"
)

// dirReport is the analysis of one directory (a module or an environment).
type dirReport struct {
	Dir      string // repo-relative, e.g. "modules/s3" or "."
	Findings []tools.Finding
}

// Report is the whole-repo prioritized health report.
type Report struct {
	Root        string
	DirsScanned int
	TFFiles     int
	Findings    []tools.Finding // all findings, sorted worst-first
	byDir       []dirReport
}

// skipDir is a directory we never descend into.
func skipDir(name string) bool {
	switch name {
	case ".terraform", ".git", ".github", "node_modules", "vendor", ".idea", ".vscode":
		return true
	}
	return false
}

// Audit walks root, analyzes every directory that contains .tf files, and
// returns a prioritized report. The analysis per directory is the existing
// deterministic pass (security + version + best-practice), so a whole repo gets
// the same rules a single dir does — but aggregated and ranked.
func Audit(root string) (*Report, error) {
	rep := &Report{Root: root}

	// Collect the set of directories that contain .tf files (analysis is
	// per-directory because Terraform resolves resources within a dir).
	tfDirs := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip, don't abort the whole audit
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".tf") {
			rep.TFFiles++
			tfDirs[filepath.Dir(path)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	dirs := make([]string, 0, len(tfDirs))
	for d := range tfDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, d := range dirs {
		findings := tools.AnalyzeDir(d)
		rel, _ := filepath.Rel(root, d)
		if rel == "" {
			rel = "."
		}
		// Tag each finding's file with its directory so the report is navigable.
		for i := range findings {
			if rel != "." {
				findings[i].File = filepath.Join(rel, findings[i].File)
			}
		}
		rep.byDir = append(rep.byDir, dirReport{Dir: rel, Findings: findings})
		rep.Findings = append(rep.Findings, findings...)
	}
	rep.DirsScanned = len(dirs)

	// Rank worst-first: higher severity first, then security before version
	// before best-practice, then by file for stable output.
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Sev() != b.Sev() {
			return a.Sev() > b.Sev()
		}
		if catRank(a.Category) != catRank(b.Category) {
			return catRank(a.Category) < catRank(b.Category)
		}
		return a.File < b.File
	})
	return rep, nil
}

// catRank orders categories so security outranks version outranks best-practice
// at equal severity.
func catRank(c tools.Category) int {
	switch c {
	case tools.CatSecurity:
		return 0
	case tools.CatVersion:
		return 1
	default:
		return 2
	}
}

// Counts returns the number of findings per severity string.
func (r *Report) Counts() map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// CategoryCounts returns the number of findings per category.
func (r *Report) CategoryCounts() map[tools.Category]int {
	m := map[tools.Category]int{}
	for _, f := range r.Findings {
		m[f.Category]++
	}
	return m
}

// Top returns the n worst findings (already sorted worst-first).
func (r *Report) Top(n int) []tools.Finding {
	if n > len(r.Findings) {
		n = len(r.Findings)
	}
	return r.Findings[:n]
}

// MaxSeverity of the whole repo (for CI gating).
func (r *Report) MaxSeverity() tools.Severity {
	return tools.MaxSeverity(r.Findings)
}
