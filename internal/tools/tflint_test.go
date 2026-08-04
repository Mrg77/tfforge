package tools

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunTFLintAbsentIsQuiet: when tflint isn't installed, runTFLint must return
// "" (the scan still works via checkov + our own rules) — never an error string.
func TestRunTFLintAbsentIsQuiet(t *testing.T) {
	if _, err := exec.LookPath("tflint"); err == nil {
		t.Skip("tflint is installed; this test covers the absent case")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "b" { bucket = "x" }`), 0o644)
	if out := runTFLint(context.Background(), dir); out != "" {
		t.Errorf("with tflint absent, runTFLint must be empty; got: %s", out)
	}
}

// TestRunTFLintFlagsIssues: when tflint IS installed, a config missing
// required_version must surface a tflint issue — proving the integration wires
// tflint's (community-maintained) rules through.
func TestRunTFLintFlagsIssues(t *testing.T) {
	if _, err := exec.LookPath("tflint"); err != nil {
		t.Skip("tflint not installed")
	}
	dir := t.TempDir()
	// No terraform{} block → tflint's terraform_required_version fires.
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
provider "aws" { region = "us-east-1" }
resource "aws_s3_bucket" "b" { bucket = "x" }
`), 0o644)
	out := runTFLint(context.Background(), dir)
	if out == "" || !strings.Contains(strings.ToLower(out), "issue") {
		t.Errorf("expected tflint to report issues; got: %q", out)
	}
}
