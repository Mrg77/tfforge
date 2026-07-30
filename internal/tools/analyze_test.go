package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTF writes a .tf file into a temp dir and returns the dir.
func writeTF(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAnalyzeFlagsIAMWildcard(t *testing.T) {
	dir := writeTF(t, `
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, `Action "*"`) {
		t.Errorf("expected wildcard-action finding, got:\n%s", out)
	}
	if !strings.Contains(out, `Resource "*"`) {
		t.Errorf("expected wildcard-resource finding, got:\n%s", out)
	}
}

func TestAnalyzeFlagsPublicS3(t *testing.T) {
	dir := writeTF(t, `
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
  acl    = "public-read"
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, "CRITICAL") || !strings.Contains(strings.ToLower(out), "public") {
		t.Errorf("expected a public-S3 CRITICAL finding, got:\n%s", out)
	}
}

func TestAnalyzeFlagsMissingEncryptionAndPAB(t *testing.T) {
	dir := writeTF(t, `
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, "encryption") {
		t.Errorf("expected missing-encryption finding, got:\n%s", out)
	}
	if !strings.Contains(out, "public_access_block") {
		t.Errorf("expected missing-public-access-block finding, got:\n%s", out)
	}
}

func TestAnalyzeFlagsHardcodedSecret(t *testing.T) {
	dir := writeTF(t, `
resource "aws_db_instance" "db" {
  password = "SuperSecretPassw0rd!"
  storage_encrypted = true
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, "CRITICAL") || !strings.Contains(out, "hard-coded") {
		t.Errorf("expected hard-coded secret finding, got:\n%s", out)
	}
	// The finding must NOT leak the secret value itself.
	if strings.Contains(out, "SuperSecretPassw0rd!") {
		t.Error("analyzer leaked the secret value in its output")
	}
}

func TestAnalyzeCleanCodeIsSilent(t *testing.T) {
	dir := writeTF(t, `
resource "aws_s3_bucket" "good" {
  bucket = "my-bucket"
}
resource "aws_s3_bucket_public_access_block" "good" {
  bucket                  = aws_s3_bucket.good.id
  block_public_acls       = true
  block_public_policy     = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "good" {
  bucket = aws_s3_bucket.good.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}`)
	if out := analyzeTerraformDir(dir); out != "" {
		t.Errorf("clean code should produce no findings, got:\n%s", out)
	}
}
