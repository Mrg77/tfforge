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
	html := rep.HTML(nil)

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
	html := rep.HTML(nil)
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
	// Enrich the first finding; the HTML must render the explanation.
	enrich := map[string]string{
		EnrichKey(rep.Findings[0]): "SENTINEL_FIX_TEXT restrict the cidr_blocks",
	}
	html := rep.HTML(enrich)
	if !strings.Contains(html, "SENTINEL_FIX_TEXT") {
		t.Error("AI enrichment not rendered in the HTML report")
	}
	if !strings.Contains(html, "AI-explained") {
		t.Error("enriched report should note it was AI-explained")
	}
	// Without enrichment, that note must be absent.
	if strings.Contains(rep.HTML(nil), "AI-explained") {
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
	html := rep.HTML(nil)
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
