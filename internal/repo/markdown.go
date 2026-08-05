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

	// Header + verdict.
	fmt.Fprintf(&b, "## tfforge — Terraform health report\n\n")
	fmt.Fprintf(&b, "`%s` · %d director%s · %d `.tf` file%s",
		r.Root, r.DirsScanned, plural(r.DirsScanned, "y", "ies"),
		r.TFFiles, plural(r.TFFiles, "", "s"))
	if len(r.Providers) > 0 {
		fmt.Fprintf(&b, " · providers: %s", "`"+strings.Join(r.Providers, "`, `")+"`")
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "> %s %s\n\n", verdictEmoji(r.MaxSeverity()), verdictLine(total, r.MaxSeverity()))

	if total == 0 {
		b.WriteString("✅ **No findings — this repo looks healthy.**\n")
		return b.String()
	}

	// Counts table.
	b.WriteString("| Total | 🔴 Security | 🟡 Version | 🔵 Best-practice | 🟣 Structure | ⚪ Variables |\n")
	b.WriteString("|:-:|:-:|:-:|:-:|:-:|:-:|\n")
	fmt.Fprintf(&b, "| **%d** | %d | %d | %d | %d | %d |\n\n",
		total, cat[tools.CatSecurity], cat[tools.CatVersion],
		cat[tools.CatBestPractice], cat[tools.CatStructure], cat[tools.CatVariables])

	// Findings — a table row per finding, worst-first, with an expandable diff.
	b.WriteString("### Fix these first\n\n")
	b.WriteString("| # | Severity | Category | File | Issue |\n")
	b.WriteString("|:-:|:-:|:-:|:--|:--|\n")
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
		b.WriteString("### Suggested fixes\n\n")
		for i, f := range shown {
			e, ok := enrich[EnrichKey(f)]
			if !ok || strings.TrimSpace(e.Prose) == "" {
				continue
			}
			fmt.Fprintf(&b, "<details><summary><b>%d. %s</b> — <code>%s</code></summary>\n\n",
				i+1, mdEscape(f.Message), f.File)
			fmt.Fprintf(&b, "**Fix ·** %s\n\n", e.Prose)
			if strings.TrimSpace(e.Before) != "" {
				fmt.Fprintf(&b, "```diff\n%s\n```\n\n", diffLines(e.Before, "-"))
			}
			if strings.TrimSpace(e.After) != "" {
				fmt.Fprintf(&b, "```diff\n%s\n```\n\n", diffLines(e.After, "+"))
			}
			b.WriteString("</details>\n\n")
		}
	}

	// Per-directory rollup.
	b.WriteString("### Where the debt concentrates\n\n")
	type kv struct {
		dir string
		n   int
	}
	rows := []kv{}
	for _, d := range r.byDir {
		if len(d.Findings) > 0 {
			rows = append(rows, kv{d.Dir, len(d.Findings)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].dir < rows[j].dir
	})
	b.WriteString("| Directory | Findings |\n|:--|:-:|\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "| `%s` | %d |\n", row.dir, row.n)
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

func sevBadge(s string) string {
	switch s {
	case "CRITICAL":
		return "🔴 **CRITICAL**"
	case "HIGH":
		return "🔴 HIGH"
	case "MEDIUM":
		return "🟡 MEDIUM"
	case "LOW":
		return "🔵 LOW"
	default:
		return "⚪ INFO"
	}
}

func verdictEmoji(s tools.Severity) string {
	switch {
	case s >= tools.SevHigh:
		return "🔴"
	case s >= tools.SevMedium:
		return "🟡"
	default:
		return "🟢"
	}
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
