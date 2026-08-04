package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes one file under dir (creating parents), for tests.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	root := buildRepo(t)
	rep, _ := Audit(root)
	html := rep.HTML(nil, nil)

	// A shareable report must pull NOTHING from the network — no external URLs,
	// no CDN links, no remote fonts. (w3.org appears only in a namespace, never
	// as a fetched resource; there are none here anyway.)
	for _, needle := range []string{"http://", "https://", "src=", "cdn", "@import", "url("} {
		if strings.Contains(strings.ToLower(html), needle) {
			t.Errorf("HTML report is not self-contained: found %q", needle)
		}
	}
	// It must be a real document with our content.
	for _, want := range []string{"<!doctype html>", "Terraform repo health", "Fix these first", "Security"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestHTMLEscapesContent(t *testing.T) {
	root := buildRepo(t)
	rep, _ := Audit(root)
	html := rep.HTML(nil, nil)
	// The root path is user-controlled; html/template must escape, so no raw
	// unescaped angle brackets leak from data into markup. (Smoke check: the doc
	// parses as balanced-ish — count of "<script" is the one we wrote, at most 1.)
	if n := strings.Count(html, "<script"); n > 1 {
		t.Errorf("unexpected extra <script> tags: %d", n)
	}
}

func TestHTMLEnrichmentShown(t *testing.T) {
	root := buildRepo(t)
	rep, _ := Audit(root)
	if len(rep.Findings) == 0 {
		t.Fatal("need findings to enrich")
	}
	// Enrich the first finding with prose + a before/after diff; the HTML must
	// render all three.
	enrich := map[string]Enrichment{
		EnrichKey(rep.Findings[0]): {
			Prose:  "SENTINEL_FIX_TEXT restrict the cidr_blocks",
			Before: "SENTINEL_BEFORE cidr = \"0.0.0.0/0\"",
			After:  "SENTINEL_AFTER cidr = var.allowed",
		},
	}
	cost := &ExplainCost{Model: "claude-test", InTok: 1200, OutTok: 340, USD: 0.0123}
	html := rep.HTML(enrich, cost)
	for _, want := range []string{"SENTINEL_FIX_TEXT", "SENTINEL_BEFORE", "SENTINEL_AFTER", "before", "after"} {
		if !strings.Contains(html, want) {
			t.Errorf("AI enrichment: HTML missing %q", want)
		}
	}
	if !strings.Contains(html, "AI-explained") {
		t.Error("enriched report should note it was AI-explained")
	}
	// The FinOps cost line must show the model and the dollar figure.
	if !strings.Contains(html, "claude-test") || !strings.Contains(html, "0.0123") {
		t.Error("HTML footer should show the --explain token cost")
	}
	// Without enrichment, that note must be absent.
	if strings.Contains(rep.HTML(nil, nil), "AI-explained") {
		t.Error("non-enriched report should NOT claim AI-explained")
	}
}

func TestHTMLCleanRepoSaysHealthy(t *testing.T) {
	// A repo with a single, clean root module → the "no findings" HTML branch.
	root := t.TempDir()
	writeFile(t, root, "main.tf", `
terraform {
  required_version = ">= 1.5"
  backend "s3" { bucket = "x" key = "y" region = "eu-west-1" }
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}
provider "aws" { region = var.r }`)
	rep, _ := Audit(root)
	html := rep.HTML(nil, nil)
	if !strings.Contains(html, "healthy") {
		t.Errorf("clean repo HTML should read healthy; got:\n%s", firstLines(html, 40))
	}
}

// firstLines is a tiny debug helper.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
