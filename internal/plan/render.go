package plan

import (
	"fmt"
	"sort"
	"strings"
)

// glyphs and (optional) colors per action. Colors use ANSI; callers on a
// non-TTY can use RenderPlain.
var glyph = map[Action]string{
	Create: "+", Update: "~", Delete: "-", Replace: "±",
}

const (
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	reset  = "\033[0m"
)

func color(a Action) string {
	switch a {
	case Create:
		return green
	case Update:
		return yellow
	case Delete, Replace:
		return red
	default:
		return ""
	}
}

// Table renders a colored, human-facing summary for the terminal. maxRows caps
// the per-resource list so a huge plan stays readable; the rest is summarized by
// type. Pass colorize=false for a no-color / piped context.
func (s *Summary) Table(maxRows int, colorize bool) string {
	c := func(code, txt string) string {
		if !colorize {
			return txt
		}
		return code + txt + reset
	}

	var b strings.Builder
	// Header tally.
	fmt.Fprintf(&b, "%s\n", c(bold, "Plan summary"))
	fmt.Fprintf(&b, "  %s  %s  %s  %s\n",
		c(green, fmt.Sprintf("+%d create", s.Create)),
		c(yellow, fmt.Sprintf("~%d update", s.Update)),
		c(red, fmt.Sprintf("-%d destroy", s.Delete)),
		c(red, fmt.Sprintf("±%d replace", s.Replace)),
	)
	if s.Total() == 0 {
		fmt.Fprintf(&b, "  %s\n", c(dim, "no changes — infrastructure matches the configuration"))
		return b.String()
	}

	fmt.Fprintln(&b)
	// Per-resource lines (destroys/replaces first — already sorted). Cap at maxRows.
	shown := s.Changes
	truncated := 0
	if maxRows > 0 && len(shown) > maxRows {
		truncated = len(shown) - maxRows
		shown = shown[:maxRows]
	}
	for _, ch := range shown {
		line := fmt.Sprintf("  %s %s", glyph[ch.Action], ch.Address)
		if ch.Action == Replace {
			line += c(dim, "  (replace: destroy then create)")
		} else if ch.Action == Delete {
			line += c(dim, "  (destroy)")
		}
		fmt.Fprintln(&b, c(color(ch.Action), line))
	}
	if truncated > 0 {
		fmt.Fprintf(&b, "  %s\n", c(dim, fmt.Sprintf("… and %d more — grouped by type below", truncated)))
		fmt.Fprint(&b, s.byType(colorize))
	}
	// A clear warning line when anything is destroyed/replaced.
	if s.HasDestructive() {
		fmt.Fprintf(&b, "\n  %s\n", c(red+bold, fmt.Sprintf("⚠ %d resource(s) will be destroyed or replaced — review before applying.", s.Delete+s.Replace)))
	}
	return b.String()
}

// byType summarizes changes grouped by resource type, for the long tail of a big
// plan. Sorted by count descending.
func (s *Summary) byType(colorize bool) string {
	counts := map[string]int{}
	for _, ch := range s.Changes {
		counts[ch.Type]++
	}
	type kv struct {
		t string
		n int
	}
	rows := make([]kv, 0, len(counts))
	for t, n := range counts {
		rows = append(rows, kv{t, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].t < rows[j].t
	})
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "    %s × %d\n", r.t, r.n)
	}
	return b.String()
}

// Digest is a compact, plain-text summary for the LLM — counts + up to a few
// destructive changes by name — so the agent can explain the plan without
// ingesting the full (possibly huge) output.
func (s *Summary) Digest() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan: %d to create, %d to update, %d to destroy, %d to replace.\n",
		s.Create, s.Update, s.Delete, s.Replace)
	if s.HasDestructive() {
		fmt.Fprintln(&b, "Destroyed/replaced resources:")
		n := 0
		for _, ch := range s.Changes {
			if ch.Action == Delete || ch.Action == Replace {
				fmt.Fprintf(&b, "  %s %s (%s)\n", glyph[ch.Action], ch.Address, ch.Action)
				if n++; n >= 20 {
					fmt.Fprintln(&b, "  … (more)")
					break
				}
			}
		}
	}
	return b.String()
}
