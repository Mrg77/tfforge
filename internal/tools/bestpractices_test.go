package tools

import (
	"strings"
	"testing"
)

func findingsFor(t *testing.T, content string) []Finding {
	t.Helper()
	return AnalyzeDir(writeTF(t, content))
}

func hasCategory(fs []Finding, cat Category, substr string) bool {
	for _, f := range fs {
		if f.Category == cat && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestVersionDeprecations(t *testing.T) {
	fs := findingsFor(t, `
terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 3.0" } }
}
resource "aws_s3_bucket" "old" {
  bucket = "b"
  acl    = "private"
  versioning { enabled = true }
}`)
	if !hasCategory(fs, CatVersion, `inline "acl"`) {
		t.Error("should flag deprecated inline S3 acl")
	}
	if !hasCategory(fs, CatVersion, `inline "versioning"`) {
		t.Error("should flag deprecated inline S3 versioning")
	}
	if !hasCategory(fs, CatVersion, "v3 or older") {
		t.Error("should flag the outdated AWS provider v3")
	}
	if !hasCategory(fs, CatVersion, "no required_version") {
		t.Error("should flag a terraform{} block without required_version")
	}
}

func TestBestPractices(t *testing.T) {
	fs := findingsFor(t, `
provider "aws" {
  region = "us-east-1"
}
resource "aws_iam_role" "a" {}
resource "aws_iam_role" "b" {}
resource "aws_iam_role" "c" {}`)
	if !hasCategory(fs, CatBestPractice, "region is hard-coded") {
		t.Error("should flag a hard-coded provider region")
	}
	if !hasCategory(fs, CatBestPractice, "no required_providers") {
		t.Error("should flag missing required_providers")
	}
	if !hasCategory(fs, CatBestPractice, "no remote backend") {
		t.Error("should flag a multi-resource file with no remote backend")
	}
}

// Modern, clean code must produce NO version/best-practice noise (no false
// positives that would annoy a user on already-good code).
func TestModernCodeIsQuiet(t *testing.T) {
	fs := findingsFor(t, `
terraform {
  required_version = ">= 1.5"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
  backend "s3" { bucket = "state" key = "x" region = "eu-west-1" }
}
provider "aws" {
  region = var.region
}
resource "aws_s3_bucket" "good" { bucket = "b" }`)
	for _, f := range fs {
		if f.Category == CatVersion {
			t.Errorf("modern code produced a version finding: %s", f.Message)
		}
	}
}
