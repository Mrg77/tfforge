package tools

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file adds DETERMINISTIC structure & variable-hygiene checks — the "is this
// well-built Terraform, not just secure?" layer. Like the backend check, these
// need WHOLE-DIRECTORY context (a module is resolved as a unit), so they run in
// checkDirStructure, called once per directory from AnalyzeDir. No LLM, no tokens.
//
// The bar is the same as everywhere in tfforge: only OBJECTIVE, low-false-positive
// signals. We flag repetition that clearly wants a loop/module, and variables
// missing a type or a description — never taste-based style.

var (
	// Matches the opening of a real resource BLOCK: `resource "TYPE" "NAME" {`
	// anchored at line start. We capture the type and the position, then slice the
	// block body ourselves (to the matching close brace) — more robust than a
	// single non-greedy regex, which mis-handles nested/one-line braces.
	reResourceOpen   = regexp.MustCompile(`(?m)^[ \t]*resource\s+"([A-Za-z0-9_]+)"\s+"[A-Za-z0-9_-]+"\s*\{`)
	reCountOrForEach = regexp.MustCompile(`(?m)^\s*(count|for_each)\s*=`)
	reDynamicBlock   = regexp.MustCompile(`(?m)^\s*dynamic\s+"`)
	// `variable "NAME" {  ...body...  }` — non-greedy body, allows uppercase names.
	reVariableBlock = regexp.MustCompile(`(?s)variable\s+"([A-Za-z0-9_-]+)"\s*\{(.*?)\n\}`)
	reHasType       = regexp.MustCompile(`(?m)^\s*type\s*=`)
	reHasDesc       = regexp.MustCompile(`(?m)^\s*description\s*=`)
)

// checkDirStructure runs the structure (DRY) and variable-hygiene checks over a
// whole directory's concatenated source. dir is the label used on the findings.
func checkDirStructure(dir, dirSrc string) []Finding {
	var out []Finding
	out = append(out, checkRepetition(dir, dirSrc)...)
	out = append(out, checkVariableHygiene(dir, dirSrc)...)
	return out
}

// checkRepetition flags the same resource TYPE declared many times in one module
// without a loop or dynamic block — the classic copy-paste that wants a for_each
// or an extracted module. Conservative threshold (>=4) to avoid nagging.
//
// The count and the "already loops?" decision are BOTH per-type, over real
// resource BLOCKS (not a bare line match): a `for_each` on an unrelated resource
// must not silence repetition of a different type, and a `resource "..."` written
// inside a heredoc/template (no real block body) doesn't inflate the count.
func checkRepetition(dir, dirSrc string) []Finding {
	counts := map[string]int{} // type → number of real blocks
	loops := map[string]bool{} // type → at least one block uses count/for_each/dynamic
	for _, loc := range reResourceOpen.FindAllStringSubmatchIndex(dirSrc, -1) {
		typ := dirSrc[loc[2]:loc[3]]
		// loc[1] is just past the opening "{"; slice the balanced block body.
		body := blockBody(dirSrc, loc[1]-1)
		counts[typ]++
		if reCountOrForEach.MatchString(body) || reDynamicBlock.MatchString(body) {
			loops[typ] = true
		}
	}
	// Deterministic order for stable output.
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)

	var out []Finding
	for _, t := range types {
		// Already using a loop/dynamic for THIS type → the author knows the idiom.
		if loops[t] {
			continue
		}
		if counts[t] >= 4 {
			out = append(out, findingCat(dir, CatStructure, SevLow, fmt.Sprintf(
				`%d separate "%s" resources with no count/for_each — this repetition usually wants a for_each (or an extracted module) to stay DRY.`,
				counts[t], t)))
		}
	}
	return out
}

// checkVariableHygiene flags declared variables missing a type or a description —
// both are cheap, objective quality signals (a typed, documented variable is
// self-checking and self-documenting).
func checkVariableHygiene(dir, dirSrc string) []Finding {
	var untyped, undescribed []string
	for _, m := range reVariableBlock.FindAllStringSubmatch(dirSrc, -1) {
		name, body := m[1], m[2]
		if !reHasType.MatchString(body) {
			untyped = append(untyped, name)
		}
		if !reHasDesc.MatchString(body) {
			undescribed = append(undescribed, name)
		}
	}
	var out []Finding
	if len(untyped) > 0 {
		out = append(out, findingCat(dir, CatVariables, SevLow, fmt.Sprintf(
			`%d variable(s) with no type (%s) — add an explicit type so bad values fail fast at plan time.`,
			len(untyped), preview(untyped))))
	}
	if len(undescribed) > 0 {
		out = append(out, findingCat(dir, CatVariables, SevInfo, fmt.Sprintf(
			`%d variable(s) with no description (%s) — document them; the description shows up in tooling and plan output.`,
			len(undescribed), preview(undescribed))))
	}
	return out
}

// blockBody returns the source between the "{" at openIdx and its matching "}",
// tracking brace depth so nested blocks and one-line "{}" are handled correctly.
// If the block is unterminated (malformed input) it returns the rest of src.
func blockBody(src string, openIdx int) string {
	depth := 0
	for i := openIdx; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[openIdx+1 : i]
			}
		}
	}
	return src[openIdx:]
}

// preview renders up to 3 names, then "…", for a compact message.
func preview(names []string) string {
	sort.Strings(names)
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:3], ", ") + ", …"
}
