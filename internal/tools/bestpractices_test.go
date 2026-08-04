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
	if !hasCategory(fs, CatBestPractice, "region/location is hard-coded") {
		t.Error("should flag a hard-coded provider region")
	}
	if !hasCategory(fs, CatBestPractice, "no required_providers") {
		t.Error("should flag missing required_providers")
	}
	if !hasCategory(fs, CatBestPractice, "no remote backend") {
		t.Error("should flag a multi-resource file with no remote backend")
	}
}

// A "provider" mentioned only in a COMMENT must not trigger provider-based
// best-practice rules (the P1 multi-cloud hardening fix). This OpenStack repo
// mentions aws in a comment — the AWS-flavored required_providers finding must
// NOT fire on it.
func TestProviderInCommentIgnored(t *testing.T) {
	fs := findingsFor(t, `# we migrated off provider "aws" to OpenStack
terraform {
  required_providers { openstack = { source = "terraform-provider-openstack/openstack" } }
}
provider "openstack" {
  region = var.region
}
resource "openstack_compute_instance_v2" "a" {}`)
	// required_providers IS present here, so the only way a finding appears is if
	// the comment falsely counted as a provider without the block — guard anyway.
	for _, f := range fs {
		if f.Category == CatBestPractice && strings.Contains(f.Message, "required_providers") {
			t.Errorf("a provider named only in a comment triggered a best-practice finding: %s", f.Message)
		}
	}
}

// A hard-coded region must be caught for NON-AWS clouds too (OVH "GRA7"), not
// just the AWS "xx-xxxx-N" shape (the P1 provider-agnostic region fix).
func TestHardcodedRegionNonAWS(t *testing.T) {
	fs := findingsFor(t, `provider "openstack" {
  region = "GRA7"
}
resource "openstack_compute_instance_v2" "a" {}`)
	if !hasCategory(fs, CatBestPractice, "region/location is hard-coded") {
		t.Error("a hard-coded OVH region (GRA7) should be flagged, not just AWS regions")
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
