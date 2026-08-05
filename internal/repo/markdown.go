package repo

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Mrg77/tfforge/internal/tools"
)

// Markdown renders the audit as GitHub-flavored Markdown, for a CI job summary
// ($GITHUB_STEP_SUMMARY). It leads with a verdict and a counts table, then the
// prioritized findings — each with its before/after diff in a collapsible block
// so a long report stays scannable. enrich/cost are the optional --explain layer,
// same as HTML.
func (r *Report) Markdown(enrich map[string]Enrichment, cost *ExplainCost) string {
	var b strings.Builder
	cat := r.CategoryCounts()
	total := len(r.Findings)

	// Header: title + a shields.io verdict badge, then the scan metadata line.
	b.WriteString("# 🛠️ tfforge — Terraform health\n\n")
	b.WriteString(verdictBadge(total, r.MaxSeverity()) + "\n\n")
	fmt.Fprintf(&b, "**`%s`** — scanned %d director%s, %d `.tf` file%s",
		r.Root, r.DirsScanned, plural(r.DirsScanned, "y", "ies"),
		r.TFFiles, plural(r.TFFiles, "", "s"))
	if len(r.Providers) > 0 {
		fmt.Fprintf(&b, "  ·  providers %s", providerBadges(r.Providers))
	}
	b.WriteString("\n\n")

	if total == 0 {
		b.WriteString("> ✅ **No findings — this repo looks healthy.**\n")
		return b.String()
	}

	fmt.Fprintf(&b, "> %s\n\n", verdictLine(total, r.MaxSeverity()))

	// Counts as shields badges (colored, scannable at a glance).
	b.WriteString(countBadges(total, cat) + "\n\n")

	// Findings — a table row per finding, worst-first.
	b.WriteString("### 🎯 Fix these first\n\n")
	b.WriteString("| # | Severity | Category | File | Issue |\n")
	b.WriteString("|:-:|:--|:--|:--|:--|\n")
	shown := r.Findings
	const capN = 40
	truncated := false
	if len(shown) > capN {
		shown = shown[:capN]
		truncated = true
	}
	for i, f := range shown {
		fmt.Fprintf(&b, "| %d | %s | %s | `%s` | %s |\n",
			i+1, sevBadge(f.Severity), f.Category, f.File, mdEscape(f.Message))
	}
	if truncated {
		fmt.Fprintf(&b, "\n_Showing the top %d of %d — run `tfforge audit --json` for the full list._\n", capN, total)
	}
	b.WriteString("\n")

	// Detailed fixes with before/after diffs (only when --explain enriched them).
	if len(enrich) > 0 {
		b.WriteString("### 🔧 Suggested fixes\n\n")
		for i, f := range shown {
			e, ok := enrich[EnrichKey(f)]
			if !ok || strings.TrimSpace(e.Prose) == "" {
				continue
			}
			fmt.Fprintf(&b, "<details><summary>%s <b>%d.</b> %s — <code>%s</code></summary>\n\n",
				sevDot(f.Severity), i+1, mdEscape(f.Message), f.File)
			fmt.Fprintf(&b, "> **Fix ·** %s\n\n", e.Prose)
			// Show before (removed) and after (added) as one combined diff block,
			// which reads as a real patch in GitHub's rendered Markdown.
			if strings.TrimSpace(e.Before) != "" || strings.TrimSpace(e.After) != "" {
				b.WriteString("```diff\n")
				if strings.TrimSpace(e.Before) != "" {
					b.WriteString(diffLines(e.Before, "-") + "\n")
				}
				if strings.TrimSpace(e.After) != "" {
					b.WriteString(diffLines(e.After, "+") + "\n")
				}
				b.WriteString("```\n\n")
			}
			b.WriteString("</details>\n\n")
		}
	}

	// Per-FILE rollup — more actionable than per-directory ("which file exactly?").
	b.WriteString("### 📂 Where the debt concentrates\n\n")
	b.WriteString("| File | Findings |\n|:--|:-:|\n")
	for _, row := range fileCounts(r.Findings) {
		fmt.Fprintf(&b, "| `%s` | %d |\n", row.name, row.n)
	}
	b.WriteString("\n")

	// Footer + cost.
	if cost != nil {
		fmt.Fprintf(&b, "<sub>tfforge · deterministic audit · AI explain via %s · %d in / %d out tokens · ~$%.4f</sub>\n",
			cost.Model, cost.InTok, cost.OutTok, cost.USD)
	} else {
		b.WriteString("<sub>tfforge · deterministic audit, no LLM tokens</sub>\n")
	}
	return b.String()
}

// sevBadge is a shields.io badge for a severity — colored, so the table scans at
// a glance. GitHub renders these inline images in Markdown summaries.
func sevBadge(s string) string {
	color := map[string]string{
		"CRITICAL": "b31d28", "HIGH": "d15b2b", "MEDIUM": "dbab09",
		"LOW": "1f6feb", "INFO": "8b949e",
	}[s]
	if color == "" {
		color = "8b949e"
	}
	return fmt.Sprintf("![%s](https://img.shields.io/badge/%s-%s)", s, s, color)
}

// sevDot is a plain emoji dot for use inside <summary> (badges don't render there).
func sevDot(s string) string {
	switch s {
	case "CRITICAL", "HIGH":
		return "🔴"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🔵"
	default:
		return "⚪"
	}
}

// verdictBadge is the big shields badge at the top: overall posture in one glance.
func verdictBadge(total int, max tools.Severity) string {
	label, color := "healthy", "2ea043"
	switch {
	case total == 0:
		label, color = "healthy", "2ea043"
	case max >= tools.SevHigh:
		label, color = "urgent", "b31d28"
	case max >= tools.SevMedium:
		label, color = "needs%20attention", "dbab09"
	default:
		label, color = "minor%20polish", "1f6feb"
	}
	return fmt.Sprintf("![status](https://img.shields.io/badge/status-%s-%s?style=for-the-badge)", label, color)
}

// countBadges renders one shields badge per non-zero category.
func countBadges(total int, cat map[tools.Category]int) string {
	badge := func(label string, n int, color string) string {
		return fmt.Sprintf("![%s](https://img.shields.io/badge/%s-%d-%s)", label, label, n, color)
	}
	parts := []string{badge("total", total, "24292f")}
	if n := cat[tools.CatSecurity]; n > 0 {
		parts = append(parts, badge("security", n, "b31d28"))
	}
	if n := cat[tools.CatVersion]; n > 0 {
		parts = append(parts, badge("version", n, "dbab09"))
	}
	if n := cat[tools.CatBestPractice]; n > 0 {
		parts = append(parts, badge("best--practice", n, "1f6feb"))
	}
	if n := cat[tools.CatStructure]; n > 0 {
		parts = append(parts, badge("structure", n, "8250df"))
	}
	if n := cat[tools.CatVariables]; n > 0 {
		parts = append(parts, badge("variables", n, "6e7781"))
	}
	return strings.Join(parts, " ")
}

// providerBadges renders each detected provider as a small badge.
func providerBadges(providers []string) string {
	parts := make([]string, 0, len(providers))
	for _, p := range providers {
		parts = append(parts, fmt.Sprintf("![%s](https://img.shields.io/badge/%s-30363d)", p, p))
	}
	return strings.Join(parts, " ")
}

func verdictLine(total int, max tools.Severity) string {
	switch {
	case total == 0:
		return "**No findings** — this repo looks healthy."
	case max >= tools.SevHigh:
		return "**Urgent** — fix the security items at the top before anything else."
	case max >= tools.SevMedium:
		return "**Needs attention** — deprecations and gaps to clean up, nothing on fire."
	default:
		return "**Mostly healthy** — only low-severity polish left."
	}
}

// diffLines prefixes each line with a diff marker (+/-) for the ```diff fence.
func diffLines(s, marker string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = marker + " " + ln
	}
	return strings.Join(lines, "\n")
}

// mdEscape escapes the Markdown table delimiter so a message with "|" doesn't
// break the table.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// fileCount is one row of the per-file rollup.
type fileCount struct {
	name string
	n    int
}

// fileCounts groups findings by their File and returns rows sorted most-first
// (then by name). More precise than a per-directory rollup — it points at the
// exact file to open.
func fileCounts(findings []tools.Finding) []fileCount {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.File]++
	}
	rows := make([]fileCount, 0, len(counts))
	for name, n := range counts {
		rows = append(rows, fileCount{name, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].name < rows[j].name
	})
	return rows
}
