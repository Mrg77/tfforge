package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mrg77/tfforge/internal/anthropic"
	"github.com/Mrg77/tfforge/internal/repo"
)

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
func explainFindings(rep *repo.Report) map[string]repo.Enrichment {
	client, err := anthropic.New()
	if err != nil {
		// Almost always "missing ANTHROPIC_API_KEY" — say so, don't fail the audit.
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain skipped (", err, ") — report generated without AI explanations.")
		return nil
	}
	if len(rep.Findings) == 0 {
		return nil
	}

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

	system := `You are tfforge's audit explainer. For each Terraform finding, return a fix with
two parts:
  - "fix": ONE short sentence (max ~35 words) — what to change, the modern
    idiomatic way. No preamble, no restating the problem, no markdown.
  - "code": a SHORT, copy-pasteable HCL snippet (a few lines) showing the fix
    concretely. Real Terraform, correctly indented. Omit or use "" when a snippet
    wouldn't help (e.g. "rotate this credential").

Tailor BOTH to the repo's actual cloud provider(s). Do NOT suggest AWS services
(S3, DynamoDB, Secrets Manager) for an OpenStack/OVH/GCP/Azure repo — use that
cloud's equivalents (OVH/OpenStack: Swift for remote state via the "swift"
backend or S3-compatible OVH Object Storage; secrets via a *.tfvars kept out of
VCS or a secret manager; GCP: gcs backend; Azure: azurerm backend).

Reply with ONLY a JSON object mapping each finding's index (as a string) to an
object {"fix": "...", "code": "..."}. Example:
{"0":{"fix":"Move the secret to a variable.","code":"variable \"password\" {\n  type      = string\n  sensitive = true\n}"}}
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
		return nil
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
		return nil
	}

	// Re-key from index → the (file+message) key repo.HTML looks up.
	out := make(map[string]repo.Enrichment, len(byIndex))
	for i, f := range rep.Findings {
		if e, ok := byIndex[i]; ok && strings.TrimSpace(e.Prose) != "" {
			e.Prose = strings.TrimSpace(e.Prose)
			e.Code = strings.TrimSpace(e.Code)
			out[repo.EnrichKey(f)] = e
		}
	}
	return out
}

// parseEnrichMap extracts a {"0":{"fix":...,"code":...}} object from the model's
// reply, tolerating any prose or ```json fences around it, and returns
// index→Enrichment.
func parseEnrichMap(s string) map[int]repo.Enrichment {
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end <= start {
		return nil
	}
	var m map[string]struct {
		Fix  string `json:"fix"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(s[start:end+1]), &m); err != nil {
		return nil
	}
	out := make(map[int]repo.Enrichment, len(m))
	for k, v := range m {
		var i int
		if _, err := fmt.Sscanf(k, "%d", &i); err == nil {
			out[i] = repo.Enrichment{Prose: v.Fix, Code: v.Code}
		}
	}
	return out
}
