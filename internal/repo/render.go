package repo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Mrg77/tfforge/internal/tools"
)

const (
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	reset  = "\033[0m"
)

// Text renders the prioritized health report a human reads: a headline verdict,
// counts by category, then the TOP findings to fix first (worst-first) — so an
// engineer inheriting the repo knows exactly where to start, not just that "there
// are 50 issues".
func (r *Report) Text(topN int, color bool) string {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", c(bold, "Terraform repo health — "+r.Root))
	fmt.Fprintf(&b, "  %s\n", c(dim, fmt.Sprintf("scanned %d directory(ies), %d .tf file(s)", r.DirsScanned, r.TFFiles)))

	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "\n  %s\n", c(green, "✓ no findings — the repo looks healthy."))
		return b.String()
	}

	// Verdict line: counts by severity + by category.
	cat := r.CategoryCounts()
	fmt.Fprintf(&b, "\n  %s  %s  %s\n",
		c(red, fmt.Sprintf("%d security", cat[tools.CatSecurity])),
		c(yellow, fmt.Sprintf("%d version/deprecation", cat[tools.CatVersion])),
		c(dim, fmt.Sprintf("%d best-practice", cat[tools.CatBestPractice])),
	)

	// The prioritized "start here" list.
	fmt.Fprintf(&b, "\n  %s\n", c(bold, fmt.Sprintf("Fix these first (top %d of %d):", min(topN, len(r.Findings)), len(r.Findings))))
	for i, f := range r.Top(topN) {
		sevColor := dim
		switch f.Severity {
		case "CRITICAL", "HIGH":
			sevColor = red
		case "MEDIUM":
			sevColor = yellow
		}
		fmt.Fprintf(&b, "  %2d. %s  %s\n", i+1,
			c(sevColor, fmt.Sprintf("[%s·%s]", f.Severity, f.Category)),
			f.File)
		fmt.Fprintf(&b, "      %s\n", c(dim, f.Message))
	}

	// A per-directory rollup so the engineer sees where the debt concentrates.
	fmt.Fprintf(&b, "\n  %s\n", c(bold, "By directory:"))
	type kv struct {
		dir string
		n   int
	}
	rows := make([]kv, 0, len(r.byDir))
	for _, d := range r.byDir {
		if len(d.Findings) > 0 {
			rows = append(rows, kv{d.Dir, len(d.Findings)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	for _, row := range rows {
		fmt.Fprintf(&b, "    %s  %s\n", c(dim, fmt.Sprintf("%2d", row.n)), row.dir)
	}
	return b.String()
}

// jsonReport is the machine-readable shape for CI.
type jsonReport struct {
	Root        string          `json:"root"`
	DirsScanned int             `json:"dirs_scanned"`
	TFFiles     int             `json:"tf_files"`
	Count       int             `json:"count"`
	MaxSeverity string          `json:"max_severity"`
	Findings    []tools.Finding `json:"findings"`
}

// JSON renders the whole report for CI parsing.
func (r *Report) JSON() string {
	fs := r.Findings
	if fs == nil {
		fs = []tools.Finding{}
	}
	out, _ := json.MarshalIndent(jsonReport{
		Root:        r.Root,
		DirsScanned: r.DirsScanned,
		TFFiles:     r.TFFiles,
		Count:       len(fs),
		MaxSeverity: r.MaxSeverity().String(),
		Findings:    fs,
	}, "", "  ")
	return string(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
