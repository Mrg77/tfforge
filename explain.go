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
// model, in ONE call, to write a concrete modern-fix line for each finding, and
// returns a map keyed the way repo.HTML expects (repo.EnrichKey). It's the
// "peaufinage IA" on top of a report that already stands on its own.
//
// Design constraints (Morgan's ADN — deterministic first, AI as a bonus):
//   - Costs tokens only when asked (--explain) AND a key is present.
//   - Degrades gracefully: no key, an API error, or a bad response → we log to
//     stderr and return nil, and the HTML/report renders WITHOUT explanations.
//   - ONE request for the whole batch, not one per finding (cheap, fast).
func explainFindings(rep *repo.Report) map[string]string {
	client, err := anthropic.New()
	if err != nil {
		// Almost always "missing ANTHROPIC_API_KEY" — say so, don't fail the audit.
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain skipped (", err, ") — report generated without AI explanations.")
		return nil
	}
	if len(rep.Findings) == 0 {
		return nil
	}

	// Send a compact, indexed list; ask for indexed answers back. We only send
	// file + category + severity + message — never file CONTENTS — so --explain
	// leaks nothing about the repo beyond the findings already in the report.
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

	system := `You are tfforge's audit explainer. For each Terraform finding you are given,
write ONE short, concrete fix (max ~40 words): what to change and the modern,
idiomatic Terraform way to do it — name the resource/attribute where relevant
(e.g. "add aws_s3_bucket_server_side_encryption_configuration", "replace inline
acl with an aws_s3_bucket_acl resource"). No preamble, no restating the problem,
no markdown headers. Reply with ONLY a JSON object mapping the finding's index
(as a string) to its fix string, e.g. {"0":"...","1":"..."}. Nothing else.`

	user := "Findings (JSON array):\n" + string(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	// Concatenate any text blocks, then pull the JSON object out.
	var raw strings.Builder
	for _, b := range resp.Content {
		if b.Type == "text" {
			raw.WriteString(b.Text)
		}
	}
	byIndex := parseIndexMap(raw.String())
	if len(byIndex) == 0 {
		fmt.Fprintln(os.Stderr, "tfforge audit: --explain returned nothing usable — report generated without AI explanations.")
		return nil
	}

	// Re-key from index → the (file+message) key repo.HTML looks up.
	out := make(map[string]string, len(byIndex))
	for i, f := range rep.Findings {
		if ex, ok := byIndex[i]; ok && strings.TrimSpace(ex) != "" {
			out[repo.EnrichKey(f)] = strings.TrimSpace(ex)
		}
	}
	return out
}

// parseIndexMap extracts a {"0":"...","1":"..."} object from the model's reply,
// tolerating any prose around it, and returns index→explanation.
func parseIndexMap(s string) map[int]string {
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end <= start {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s[start:end+1]), &m); err != nil {
		return nil
	}
	out := make(map[int]string, len(m))
	for k, v := range m {
		var i int
		if _, err := fmt.Sscanf(k, "%d", &i); err == nil {
			out[i] = v
		}
	}
	return out
}
