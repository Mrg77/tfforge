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

func TestAnalyzeFlagsSSHToWorld(t *testing.T) {
	dir := writeTF(t, `
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, "SSH") || !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected a CRITICAL SSH-to-world finding, got:\n%s", out)
	}
}

func TestAnalyzeFlagsServiceWildcard(t *testing.T) {
	// "s3:*" is broad but not "*", so checkov's plain-* rule can pass — our
	// fine-grained rule must still catch it.
	dir := writeTF(t, `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "arn:aws:s3:::b" }] })
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, "service-wide wildcard") {
		t.Errorf("expected a service-wildcard finding for s3:*, got:\n%s", out)
	}
}

func TestAnalyzeFlagsAccountWideS3(t *testing.T) {
	// The exact real-world gap we hit: checkov-clean but least-privilege leak.
	dir := writeTF(t, `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Action = ["s3:ListAllMyBuckets"], Resource = "arn:aws:s3:::*" }] })
}`)
	out := analyzeTerraformDir(dir)
	if !strings.Contains(out, "account-wide S3") {
		t.Errorf("expected an account-wide-S3 finding, got:\n%s", out)
	}
}

func TestSeverityGating(t *testing.T) {
	dir := writeTF(t, `
resource "aws_security_group" "bad" {
  ingress { from_port = 22 to_port = 22 cidr_blocks = ["0.0.0.0/0"] }
}`)
	fs := AnalyzeDir(dir)
	if MaxSeverity(fs) != SevCritical {
		t.Errorf("SSH-to-world should max at CRITICAL, got %v", MaxSeverity(fs))
	}
	// A clean dir maxes at INFO.
	clean := writeTF(t, `resource "random_pet" "x" {}`)
	if MaxSeverity(AnalyzeDir(clean)) != SevInfo {
		t.Error("clean code should max at INFO")
	}
}

// A secure, modern, complete config must produce NO findings at all — proving
// the analyzer stays quiet on genuinely good code (no false positives).
func TestAnalyzeCleanCodeIsSilent(t *testing.T) {
	dir := writeTF(t, `
terraform {
  required_version = ">= 1.5"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
  backend "s3" { bucket = "state" key = "x" region = "eu-west-1" }
}
provider "aws" {
  region = var.region
}
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
		t.Errorf("clean, modern code should produce no findings, got:\n%s", out)
	}
}
