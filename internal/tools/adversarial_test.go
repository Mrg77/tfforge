package tools

import (
	"strings"
	"testing"
)

// These lock in the fixes found by adversarial fuzzing — the gaps a real
// reviewer would exploit. Each is a case the scanner USED to get wrong.

func scan(t *testing.T, tf string) []Finding {
	t.Helper()
	return AnalyzeDir(writeTF(t, tf))
}

func mustFlag(t *testing.T, fs []Finding, substr string) {
	t.Helper()
	for _, f := range fs {
		if strings.Contains(f.Message, substr) {
			return
		}
	}
	t.Errorf("expected a finding containing %q; got %d findings: %v", substr, len(fs), msgs(fs))
}

func mustNotFlag(t *testing.T, fs []Finding, substr string) {
	t.Helper()
	for _, f := range fs {
		if strings.Contains(f.Message, substr) {
			t.Errorf("false positive: did not expect a finding containing %q; got: %s", substr, f.Message)
		}
	}
}

func msgs(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Message
	}
	return out
}

// --- recovered false NEGATIVES (real risks that were missed) ---------------

func TestSSHOpenViaIPv6(t *testing.T) {
	mustFlag(t, scan(t, `
resource "aws_security_group" "s" {
  ingress { from_port = 22, to_port = 22, protocol = "tcp", ipv6_cidr_blocks = ["::/0"] }
}`), "opens SSH")
}

func TestPublicBucketPolicy(t *testing.T) {
	mustFlag(t, scan(t, `
resource "aws_s3_bucket_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" }] })
}`), "aws_s3_bucket_policy grants access to Principal")
}

func TestSecretInUserDataHeredoc(t *testing.T) {
	mustFlag(t, scan(t, `
resource "aws_instance" "web" {
  user_data = "export DB_PASSWORD=SuperSecret123456"
}`), "hard-coded")
}

func TestAuroraUnencryptedFlagged(t *testing.T) {
	mustFlag(t, scan(t, `resource "aws_rds_cluster" "c" { engine = "aurora-mysql" }`), "aws_rds_cluster")
}

func TestEgressOpenToWorldFlagged(t *testing.T) {
	mustFlag(t, scan(t, `
resource "aws_security_group" "s" {
  egress { from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"] }
}`), "ALL egress")
}

// --- recovered false POSITIVES (good code that must stay quiet) -------------

func TestServiceWildcardInDenyIsNotFlagged(t *testing.T) {
	// "s3:*" inside a Deny is good practice — must NOT be flagged.
	mustNotFlag(t, scan(t, `
data "aws_iam_policy_document" "deny" {
  statement { effect = "Deny", actions = ["s3:*"], resources = ["arn:aws:s3:::sensitive/*"] }
}`), "service-wide wildcard")
}

func TestVariableNamedPasswordNoValueIsNotFlagged(t *testing.T) {
	mustNotFlag(t, scan(t, `
variable "password" {
  type        = string
  description = "the db password"
}`), "hard-coded")
}

func TestModernS3AclIsNotFlaggedAsDeprecated(t *testing.T) {
	// The modern separate aws_s3_bucket_acl must not be confused with the
	// deprecated inline acl.
	mustNotFlag(t, scan(t, `
resource "aws_s3_bucket" "b" { bucket = "x" }
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.b.id
  acl    = "private"
}`), `inline "acl"`)
}

func TestHealthCheckHTTPIsNotFlagged(t *testing.T) {
	// A health_check on HTTP is internal, not user traffic — must not warn.
	mustNotFlag(t, scan(t, `
resource "aws_lb_target_group" "t" {
  health_check { protocol = "HTTP", path = "/health" }
}`), "unencrypted in transit")
}

// A wide port range (0–65535) open to the world exposes the whole instance —
// worse than a single sensitive port.
func TestWidePortRangeOpenToWorld(t *testing.T) {
	mustFlag(t, scan(t, `
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 0
    to_port     = 65535
    cidr_blocks = ["0.0.0.0/0"]
  }
}`), "WIDE port range")
}

// A secret stored as a literal in secretsmanager/ssm must be flagged; the same
// value passed via a variable must NOT (reference, not a literal).
func TestSecretLiteralInSecretsManager(t *testing.T) {
	mustFlag(t, scan(t, `
resource "aws_secretsmanager_secret_version" "s" {
  secret_string = "SuperSecret123!"
}`), "literal")

	mustNotFlag(t, scan(t, `
resource "aws_secretsmanager_secret_version" "s" {
  secret_string = var.db_secret
}`), "literal")

	mustNotFlag(t, scan(t, `
resource "aws_ssm_parameter" "p" {
  name  = "/app/config"
  value = var.config_value
}`), "literal")
}
