package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Severity levels for a finding, ordered so callers can gate on a threshold.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Category groups a finding by concern, so a scan can be read (and filtered) by
// what it's about: a security risk, an outdated/deprecated version, or a
// non-security best-practice.
type Category string

const (
	CatSecurity     Category = "security"
	CatVersion      Category = "version"       // outdated/deprecated Terraform, providers, syntax
	CatBestPractice Category = "best-practice" // structure, typing, backend, naming
)

// Finding is one issue tfforge's own analysis flagged.
type Finding struct {
	File     string   `json:"file"`
	Category Category `json:"category"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	sev      Severity // kept for gating/sorting, not serialized
}

// Sev returns the finding's severity level (for gating).
func (f Finding) Sev() Severity { return f.sev }

// AnalyzeDir runs tfforge's own provider-aware security heuristics over the .tf
// files in a directory and returns structured findings. This is NOT a
// replacement for checkov/trivy — it complements them with high-signal checks a
// reviewer flags first, INCLUDING least-privilege and network cases a coarse
// scanner phrases obscurely or passes (e.g. a "s3:*" service wildcard, an
// account-wide S3 ARN, SSH open to 0.0.0.0/0, iam:PassRole on "*").
//
// It parses text (regex over HCL), deliberately simple and dependency-free — the
// point is to demonstrate the security reasoning, not reimplement an HCL parser.
func AnalyzeDir(dir string) []Finding {
	files, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	var findings []Finding
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(data)
		base := filepath.Base(f)
		findings = append(findings, checkIAMWildcard(base, src)...)
		findings = append(findings, checkIAMFine(base, src)...)
		findings = append(findings, checkS3Public(base, src)...)
		findings = append(findings, checkEncryption(base, src)...)
		findings = append(findings, checkNetwork(base, src)...)
		findings = append(findings, checkTransit(base, src)...)
		findings = append(findings, checkHardcodedSecrets(base, src)...)
		findings = append(findings, checkVersions(base, src)...)      // outdated/deprecated TF & providers
		findings = append(findings, checkBestPractices(base, src)...) // objective best practices
	}
	return findings
}

// MaxSeverity returns the highest severity among findings (SevInfo if empty).
func MaxSeverity(fs []Finding) Severity {
	m := SevInfo
	for _, f := range fs {
		if f.sev > m {
			m = f.sev
		}
	}
	return m
}

// RenderFindings formats findings as the plain text block the agent's
// security_scan tool returns. Empty string when there are none.
func RenderFindings(fs []Finding) string {
	if len(fs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  [%s·%s] %s — %s\n", f.Severity, f.Category, f.File, f.Message)
	}
	return strings.TrimRight(b.String(), "\n")
}

// analyzeTerraformDir keeps the string API used by security_scan.
func analyzeTerraformDir(dir string) string {
	return RenderFindings(AnalyzeDir(dir))
}

var (
	reIAMWildcardAction   = regexp.MustCompile(`(?i)"?Action"?\s*[:=]\s*\[?\s*"\*"`)
	reIAMWildcardResource = regexp.MustCompile(`(?i)"?Resource"?\s*[:=]\s*\[?\s*"\*"`)
	reS3PublicACL         = regexp.MustCompile(`(?i)acl\s*=\s*"public-read(-write)?"`)
	reHardcodedSecret     = regexp.MustCompile(`(?i)(secret_key|password|private_key|api_key|access_key)\s*=\s*"[^"$][^"]{7,}"`)
)

func checkIAMWildcard(file, src string) []Finding {
	var out []Finding
	if reIAMWildcardAction.MatchString(src) {
		out = append(out, finding(file, SevHigh, `IAM policy grants Action "*" (all actions) — scope to the specific actions needed (least privilege).`))
	}
	if reIAMWildcardResource.MatchString(src) {
		out = append(out, finding(file, SevHigh, `IAM policy grants Resource "*" (all resources) — scope to specific ARNs.`))
	}
	return out
}

func checkS3Public(file, src string) []Finding {
	var out []Finding
	if reS3PublicACL.MatchString(src) {
		out = append(out, finding(file, SevCritical, "S3 bucket ACL is public-read/-write — the bucket is exposed to the internet. Use a private ACL and an aws_s3_bucket_public_access_block."))
	}
	if strings.Contains(src, `resource "aws_s3_bucket"`) && !strings.Contains(src, "aws_s3_bucket_public_access_block") {
		out = append(out, finding(file, SevMedium, "aws_s3_bucket without an aws_s3_bucket_public_access_block — add one to guarantee the bucket can't be made public."))
	}
	return out
}

func checkEncryption(file, src string) []Finding {
	var out []Finding
	if strings.Contains(src, `resource "aws_s3_bucket"`) && !strings.Contains(src, "server_side_encryption") {
		out = append(out, finding(file, SevMedium, "aws_s3_bucket without server-side encryption — add aws_s3_bucket_server_side_encryption_configuration."))
	}
	if strings.Contains(src, `resource "aws_db_instance"`) &&
		!regexp.MustCompile(`(?i)storage_encrypted\s*=\s*true`).MatchString(src) {
		out = append(out, finding(file, SevHigh, "aws_db_instance without storage_encrypted = true — RDS data at rest is unencrypted."))
	}
	if strings.Contains(src, `resource "aws_ebs_volume"`) &&
		!regexp.MustCompile(`(?i)encrypted\s*=\s*true`).MatchString(src) {
		out = append(out, finding(file, SevHigh, "aws_ebs_volume without encrypted = true — the volume is unencrypted."))
	}
	return out
}

func checkHardcodedSecrets(file, src string) []Finding {
	if reHardcodedSecret.MatchString(src) {
		return []Finding{finding(file, SevCritical, "a credential looks hard-coded in the .tf — move it to a variable, a secret manager, or a *.tfvars kept out of VCS. (tfforge does not print the value.)")}
	}
	return nil
}

// finding builds a SECURITY finding (the common case for the existing checks).
func finding(file string, sev Severity, msg string) Finding {
	return findingCat(file, CatSecurity, sev, msg)
}

// findingCat builds a finding in a specific category (version, best-practice…).
func findingCat(file string, cat Category, sev Severity, msg string) Finding {
	return Finding{File: file, Category: cat, Severity: sev.String(), Message: msg, sev: sev}
}
