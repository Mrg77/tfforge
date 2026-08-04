package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Mrg77/tfforge/internal/anthropic"
	"github.com/Mrg77/tfforge/internal/repo"
	"github.com/Mrg77/tfforge/internal/trace"
)

// explainStats is the FinOps summary of the one --explain API call: which model,
// how many tokens, and the estimated USD cost. Surfaced in the HTML footer so the
// spend of the AI layer is visible (LLMOps: never hide what an agent cost).
type explainStats struct {
	Model  string
	InTok  int
	OutTok int
	Cost   float64
}

// explainFindings is the OPTIONAL AI layer of `audit --explain`: it asks the
// model, in ONE call, to write a concrete fix for each finding — a short prose
// line PLUS a copy-pasteable HCL snippet — tailored to the repo's actual cloud.
// It returns a map keyed the way repo.HTML expects (repo.EnrichKey). It's the
// "peaufinage IA" on top of a report that already stands on its own.
//
// Design constraints (Morgan's ADN — deterministic first, AI as a bonus):
//   - Costs tokens only when asked (--explain) AND a key is present.
//   - Degrades gracefully: no key, an API error, or a bad response → we log to
//     stderr and return nil, and the HTML/report renders WITHOUT explanations.
//   - ONE request for the whole batch, not one per finding (cheap, fast).
//   - Sends only findings (file + category + severity + message) + the detected
//     cloud — never file CONTENTS, so nothing about the repo leaks beyond the
//     findings already in the report.
func explainFindings(rep *repo.Report) (map[string]repo.Enrichment, *explainStats) {
	client, err := anthropic.New()
	if err != nil {
		// Almost always "missing ANTHROPIC_API_KEY" — say so, don't fail the audit.
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain skipped (", err, ") — report generated without AI explanations.")
		return nil, nil
	}
	if len(rep.Findings) == 0 {
		return nil, nil
	}

	// A batch of findings, each with prose + a before/after diff, easily exceeds
	// the default 4096-token cap — which silently truncates the JSON reply and
	// loses ALL explanations. Budget generously by finding count (bounded), so the
	// whole batch fits in one reply.
	maxTok := 1500 + len(rep.Findings)*350
	if maxTok > 32000 {
		maxTok = 32000
	}
	client.SetMaxTokens(maxTok)

	type item struct {
		I   int    `json:"i"`
		Sev string `json:"severity"`
		Cat string `json:"category"`
		Msg string `json:"message"`
	}
	items := make([]item, len(rep.Findings))
	for i, f := range rep.Findings {
		items[i] = item{I: i, Sev: f.Severity, Cat: string(f.Category), Msg: f.Message}
	}
	payload, _ := json.Marshal(items)

	system := `You are tfforge's audit explainer. For each Terraform finding, return a fix as
a before/after diff plus a one-line summary:
  - "fix": ONE short sentence (max ~35 words) — what to change, the modern
    idiomatic way. No preamble, no restating the problem, no markdown.
  - "before": a SHORT HCL snippet showing the CURRENT problematic code as it
    likely looks (reconstruct it from the finding — you don't see the file). Use
    "" if there's nothing meaningful to show (e.g. a missing block).
  - "after": the SAME snippet corrected — the fixed HCL, copy-pasteable, real
    Terraform, correctly indented.
Keep before/after aligned so the change reads as a diff. Omit both (use "") when
a snippet wouldn't help (e.g. "rotate this credential").

Tailor everything to the repo's actual cloud provider(s). Do NOT suggest AWS
services (S3, DynamoDB, Secrets Manager) for an OpenStack/OVH/GCP/Azure repo —
use that cloud's equivalents (OVH/OpenStack: Swift for remote state via the
"swift" backend or S3-compatible OVH Object Storage; secrets via a *.tfvars kept
out of VCS or a secret manager; GCP: gcs backend; Azure: azurerm backend).

Reply with ONLY a JSON object mapping each finding's index (as a string) to an
object {"fix":"...","before":"...","after":"..."}. Example:
{"0":{"fix":"Move the secret to a sensitive variable.","before":"provider \"openstack\" {\n  password = \"hunter2\"\n}","after":"variable \"os_password\" {\n  type      = string\n  sensitive = true\n}\n\nprovider \"openstack\" {\n  password = var.os_password\n}"}}
Nothing else — no markdown fences around the JSON.`

	user := "Findings (JSON array):\n" + string(payload)
	if cloud := rep.CloudContext(); cloud != "" {
		user = "This repo's cloud provider(s): " + cloud +
			". Tailor every fix and code snippet to this cloud, not AWS.\n\n" + user
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Fprintf(os.Stderr, "tfforge audit: --explain — asking %s to explain %d finding(s)…\n", client.Model(), len(rep.Findings))
	resp, err := client.CreateMessage(ctx, system, []anthropic.Message{{
		Role:    "user",
		Content: []anthropic.ContentBlock{{Type: "text", Text: user}},
	}}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain failed (", err, ") — report generated without AI explanations.")
		return nil, nil
	}

	// Price the call for FinOps visibility (LLMOps: the AI layer's cost is shown,
	// not hidden). Computed even if parsing later fails, so we always report spend.
	stats := &explainStats{
		Model:  client.Model(),
		InTok:  resp.Usage.InputTokens,
		OutTok: resp.Usage.OutputTokens,
		Cost:   trace.EstimateCost(client.Model(), resp.Usage.InputTokens, resp.Usage.OutputTokens),
	}
	fmt.Fprintf(os.Stderr, "tfforge audit: --explain done — %d in / %d out tokens · ~$%.4f\n", stats.InTok, stats.OutTok, stats.Cost)
	if resp.StopReason == "max_tokens" {
		// The reply hit the token cap — the tail JSON is cut off. We still salvage
		// the complete entries below, but warn: the last findings may be unexplained.
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain hit the token cap — some later findings may be unexplained (salvaging the complete ones).")
	}

	var raw strings.Builder
	for _, b := range resp.Content {
		if b.Type == "text" {
			raw.WriteString(b.Text)
		}
	}
	byIndex := parseEnrichMap(raw.String())
	if len(byIndex) == 0 {
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain returned nothing usable — report generated without AI explanations.")
		return nil, stats // still report the cost we already paid
	}

	// Re-key from index → the (file+message) key repo.HTML looks up.
	out := make(map[string]repo.Enrichment, len(byIndex))
	for i, f := range rep.Findings {
		if e, ok := byIndex[i]; ok && strings.TrimSpace(e.Prose) != "" {
			e.Prose = strings.TrimSpace(e.Prose)
			e.Before = strings.TrimSpace(e.Before)
			e.After = strings.TrimSpace(e.After)
			out[repo.EnrichKey(f)] = e
		}
	}
	return out, stats
}

type enrichEntry struct {
	Fix    string `json:"fix"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// parseEnrichMap extracts a {"0":{...},"1":{...}} object from the model's reply,
// tolerating prose or ```json fences around it. If the whole-object parse fails
// (e.g. the reply was truncated at the token cap and the tail is cut off), it
// falls back to salvaging every COMPLETE "index": {…} entry it can find — so a
// truncated batch still yields explanations for the findings that made it in,
// instead of losing all of them.
func parseEnrichMap(s string) map[int]repo.Enrichment {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return nil
	}
	out := map[int]repo.Enrichment{}

	// Fast path: the whole object is valid JSON.
	if end := strings.LastIndexByte(s, '}'); end > start {
		var m map[string]enrichEntry
		if json.Unmarshal([]byte(s[start:end+1]), &m) == nil {
			for k, v := range m {
				var i int
				if _, err := fmt.Sscanf(k, "%d", &i); err == nil {
					out[i] = repo.Enrichment{Prose: v.Fix, Before: v.Before, After: v.After}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}

	// Salvage path: scan for `"<int>": { ...balanced... }` entries and parse each
	// on its own, so a truncated tail doesn't discard the complete head.
	for _, m := range reEntryKey.FindAllStringSubmatchIndex(s, -1) {
		idxStr := s[m[2]:m[3]]
		var idx int
		if _, err := fmt.Sscanf(idxStr, "%d", &idx); err != nil {
			continue
		}
		obj := balancedObject(s, m[1]-1) // m[1]-1 is the "{" position
		if obj == "" {
			continue // this entry was itself cut off — skip it
		}
		var e enrichEntry
		if json.Unmarshal([]byte(obj), &e) == nil && strings.TrimSpace(e.Fix) != "" {
			out[idx] = repo.Enrichment{Prose: e.Fix, Before: e.Before, After: e.After}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// reEntryKey matches an entry opener like `"12": {` in the JSON reply.
var reEntryKey = regexp.MustCompile(`"(\d+)"\s*:\s*\{`)

// balancedObject returns the JSON object starting at the "{" at openIdx, matched
// to its closing "}", respecting quotes and escapes. Returns "" if unterminated
// (the reply was cut off inside this object).
func balancedObject(s string, openIdx int) string {
	depth, inStr, esc := 0, false, false
	for i := openIdx; i < len(s); i++ {
		ch := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[openIdx : i+1]
			}
		}
	}
	return ""
}
