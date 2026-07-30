package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// analyzeTerraformDir runs tfforge's own provider-aware security heuristics over
// the .tf files in a directory. This is NOT a replacement for checkov/trivy — it
// complements them with a few high-signal, DevOps-obvious checks phrased plainly,
// the ones a reviewer would flag first:
//
//   - AWS IAM: wildcard actions/resources ("*") — over-broad permissions.
//   - S3: public access (ACL public-read/-write, or missing public-access block).
//   - Encryption: unencrypted S3 buckets / EBS volumes / RDS instances.
//   - Secrets: hard-coded credentials in .tf (should be variables/secret stores).
//
// It parses text (regex over HCL), deliberately simple and dependency-free: the
// point is to demonstrate the security reasoning, not to reimplement a full HCL
// analyzer. Returns "" when nothing is flagged.
func analyzeTerraformDir(dir string) string {
	files, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	var findings []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		src := string(data)
		base := filepath.Base(f)
		findings = append(findings, checkIAMWildcard(base, src)...)
		findings = append(findings, checkS3Public(base, src)...)
		findings = append(findings, checkEncryption(base, src)...)
		findings = append(findings, checkHardcodedSecrets(base, src)...)
	}
	if len(findings) == 0 {
		return ""
	}
	return strings.Join(findings, "\n")
}

var (
	reIAMWildcardAction   = regexp.MustCompile(`(?i)"?Action"?\s*[:=]\s*\[?\s*"\*"`)
	reIAMWildcardResource = regexp.MustCompile(`(?i)"?Resource"?\s*[:=]\s*\[?\s*"\*"`)
	reS3PublicACL         = regexp.MustCompile(`(?i)acl\s*=\s*"public-read(-write)?"`)
	reHardcodedSecret     = regexp.MustCompile(`(?i)(secret_key|password|private_key|api_key|access_key)\s*=\s*"[^"$][^"]{7,}"`)
)

func checkIAMWildcard(file, src string) []string {
	var out []string
	if reIAMWildcardAction.MatchString(src) {
		out = append(out, finding(file, "HIGH", "IAM policy grants Action \"*\" (all actions) — scope to the specific actions needed (least privilege)."))
	}
	if reIAMWildcardResource.MatchString(src) {
		out = append(out, finding(file, "HIGH", "IAM policy grants Resource \"*\" (all resources) — scope to specific ARNs."))
	}
	return out
}

func checkS3Public(file, src string) []string {
	var out []string
	if reS3PublicACL.MatchString(src) {
		out = append(out, finding(file, "CRITICAL", "S3 bucket ACL is public-read/-write — the bucket is exposed to the internet. Use a private ACL and an aws_s3_bucket_public_access_block."))
	}
	// A bucket without a public-access block is a common miss.
	if strings.Contains(src, `resource "aws_s3_bucket"`) && !strings.Contains(src, "aws_s3_bucket_public_access_block") {
		out = append(out, finding(file, "MEDIUM", "aws_s3_bucket without an aws_s3_bucket_public_access_block — add one to guarantee the bucket can't be made public."))
	}
	return out
}

func checkEncryption(file, src string) []string {
	var out []string
	if strings.Contains(src, `resource "aws_s3_bucket"`) &&
		!strings.Contains(src, "server_side_encryption") {
		out = append(out, finding(file, "MEDIUM", "aws_s3_bucket without server-side encryption — add aws_s3_bucket_server_side_encryption_configuration."))
	}
	if strings.Contains(src, `resource "aws_db_instance"`) &&
		!regexp.MustCompile(`(?i)storage_encrypted\s*=\s*true`).MatchString(src) {
		out = append(out, finding(file, "HIGH", "aws_db_instance without storage_encrypted = true — RDS data at rest is unencrypted."))
	}
	if strings.Contains(src, `resource "aws_ebs_volume"`) &&
		!regexp.MustCompile(`(?i)encrypted\s*=\s*true`).MatchString(src) {
		out = append(out, finding(file, "HIGH", "aws_ebs_volume without encrypted = true — the volume is unencrypted."))
	}
	return out
}

func checkHardcodedSecrets(file, src string) []string {
	if reHardcodedSecret.MatchString(src) {
		return []string{finding(file, "CRITICAL", "a credential looks hard-coded in the .tf — move it to a variable, a secret manager, or a *.tfvars kept out of VCS. (tfforge does not print the value.)")}
	}
	return nil
}

func finding(file, sev, msg string) string {
	return fmt.Sprintf("  [%s] %s — %s", sev, file, msg)
}
