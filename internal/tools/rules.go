package tools

import (
	"regexp"
	"strings"
)

// This file holds tfforge's higher-signal, provider-aware security rules — the
// ones that show real DevOps security judgement, including cases a generic
// scanner phrases obscurely or misses. Each rule is a plain-text heuristic over
// HCL, deliberately dependency-free.

var (
	// Security-group rules open to the world — IPv4 (0.0.0.0/0) OR IPv6 (::/0).
	// Missing the IPv6 form leaves SSH reachable by any IPv6 host.
	reSGOpenWorld = regexp.MustCompile(`(?i)(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*("0\.0\.0\.0/0"|"::/0")`)
	// The dangerous ones specifically: SSH (22) / RDP (3389) open to the world.
	reIngress  = regexp.MustCompile(`(?is)ingress\s*\{.*?\}`)
	rePort22   = regexp.MustCompile(`(?i)(from_port|to_port)\s*=\s*22\b`)
	rePort3389 = regexp.MustCompile(`(?i)(from_port|to_port)\s*=\s*3389\b`)
	rePort0    = regexp.MustCompile(`(?i)(from_port|to_port)\s*=\s*0\b`)
	// A wide port range: from_port = 0 AND to_port = 65535 (the whole range).
	reWidePortRange = regexp.MustCompile(`(?is)from_port\s*=\s*0\b.*?to_port\s*=\s*65535\b`)
	// A secret literal in aws_secretsmanager_secret_version / aws_ssm_parameter:
	// secret_string / value = "literal" (not a var/local/data reference).
	reSecretLiteral = regexp.MustCompile(`(?i)(secret_string|value)\s*=\s*"[^"$][^"]{4,}"`)
	// A wide S3 resource like "arn:aws:s3:::*" or account-wide list actions.
	reS3ListAllBuckets = regexp.MustCompile(`(?i)"s3:ListAllMyBuckets"`)
	reArnAllBuckets    = regexp.MustCompile(`(?i)"arn:aws:s3:::\*"`)
	// IAM: PassRole with a wildcard resource — a classic privilege-escalation path.
	rePassRoleWildcard = regexp.MustCompile(`(?is)"iam:PassRole".*?Resource"?\s*[:=]\s*\[?\s*"\*"`)
	// Actions listed as a service wildcard, e.g. "s3:*", "iam:*" — broad, not "*"
	// (so checkov's "no *" rule may pass) but still over-privileged.
	reServiceWildcardAction = regexp.MustCompile(`(?i)"([a-z0-9]+):\*"`)
	// RDS / instances publicly accessible.
	rePubliclyAccessible = regexp.MustCompile(`(?i)publicly_accessible\s*=\s*true`)
	// Unencrypted-in-transit hints: an ELB/ALB listener on plain HTTP :80 only.
	// (kept conservative — informational)
	reHTTPListener = regexp.MustCompile(`(?i)protocol\s*=\s*"HTTP"`)
	// A bucket policy (or any resource policy) that grants access to Principal
	// "*" — public exposure via policy, one of the most common S3 leaks.
	rePrincipalStar    = regexp.MustCompile(`(?i)"?Principal"?\s*[:=]\s*"\*"`)
	rePrincipalAWSStar = regexp.MustCompile(`(?is)"?Principal"?\s*[:=]\s*\{[^}]*"AWS"\s*[:=]\s*\[?\s*"\*"`)
	// egress open to the world with all protocols — data exfiltration path.
	reEgress = regexp.MustCompile(`(?is)egress\s*\{.*?\}`)
)

// checkNetwork flags network-exposure risks — the class that actually gets
// people breached (an SSH port open to the internet).
func checkNetwork(file, src string) []Finding {
	var out []Finding
	for _, blk := range reIngress.FindAllString(src, -1) {
		if !reSGOpenWorld.MatchString(blk) {
			continue
		}
		if rePort22.MatchString(blk) {
			out = append(out, finding(file, SevCritical, "a security group opens SSH (port 22) to 0.0.0.0/0 — the whole internet can reach SSH. Restrict cidr_blocks to known IPs or use SSM."))
		}
		if rePort3389.MatchString(blk) {
			out = append(out, finding(file, SevCritical, "a security group opens RDP (port 3389) to 0.0.0.0/0 — restrict cidr_blocks to known IPs."))
		}
		// A wide port RANGE open to the world (e.g. from_port=0 to_port=65535) is
		// worse than a single sensitive port — the entire instance is exposed.
		if reWidePortRange.MatchString(blk) {
			out = append(out, finding(file, SevCritical, "a security group opens a WIDE port range (e.g. 0–65535) to 0.0.0.0/0 — every port on the instance is exposed to the internet. Open only the ports you need."))
		}
	}
	if rePubliclyAccessible.MatchString(src) {
		out = append(out, finding(file, SevHigh, "a resource sets publicly_accessible = true — databases/instances should not be reachable from the public internet."))
	}
	// A security-group EGRESS wide open to the world (all protocols) — an
	// exfiltration path; egress should be scoped too, not just ingress.
	for _, blk := range reEgress.FindAllString(src, -1) {
		if reSGOpenWorld.MatchString(blk) && (strings.Contains(blk, `"-1"`) || rePort0.MatchString(blk)) {
			out = append(out, finding(file, SevMedium, "a security group allows ALL egress to 0.0.0.0/0 (protocol -1) — scope outbound traffic; wide-open egress is a data-exfiltration path."))
			break
		}
	}
	return out
}

// checkPublicPolicy flags a resource policy that grants access to Principal "*"
// — public exposure via policy (e.g. an aws_s3_bucket_policy making a bucket
// world-readable), which the ACL/public-access-block checks don't catch.
func checkPublicPolicy(file, src string) []Finding {
	var out []Finding
	if rePrincipalStar.MatchString(src) || rePrincipalAWSStar.MatchString(src) {
		sev := SevHigh
		msg := `a resource policy grants access to Principal "*" (everyone) — this exposes the resource publicly.`
		if strings.Contains(src, "aws_s3_bucket_policy") {
			sev = SevCritical
			msg = `an aws_s3_bucket_policy grants access to Principal "*" — the bucket is public to the internet. Restrict the Principal, or this defeats the public-access block.`
		}
		out = append(out, finding(file, sev, msg))
	}
	return out
}

// checkIAMFine flags least-privilege gaps that a coarse "no Action *" check
// misses: service-wide wildcards, account-wide S3 resources, and PassRole *.
func checkIAMFine(file, src string) []Finding {
	var out []Finding
	// A service wildcard like "s3:*" is over-privileged in an Allow, but a GOOD
	// practice in a Deny (broad denial). Only flag it when the policy grants —
	// i.e. it's an Allow, not a pure Deny document.
	if m := reServiceWildcardAction.FindStringSubmatch(src); m != nil && grantsWildcard(src) {
		out = append(out, finding(file, SevMedium, "IAM grants a service-wide wildcard action (\""+m[1]+":*\") — broad even though it's not \"*\". Scope to the specific operations needed."))
	}
	if reArnAllBuckets.MatchString(src) || reS3ListAllBuckets.MatchString(src) {
		out = append(out, finding(file, SevLow, "IAM policy allows account-wide S3 access (arn:aws:s3:::* or s3:ListAllMyBuckets) — this lists/reaches ALL buckets, not just this one. Scope to the specific bucket ARN unless account-wide listing is truly required."))
	}
	if rePassRoleWildcard.MatchString(src) {
		out = append(out, finding(file, SevHigh, "iam:PassRole on Resource \"*\" — a classic privilege-escalation path (pass any role to a service). Restrict to specific role ARNs."))
	}
	return out
}

// checkSecretResources flags a secret stored as a literal in a secret-holding
// resource (aws_secretsmanager_secret_version, aws_ssm_parameter). Scoped to
// those resources so a plain `value = "..."` elsewhere isn't a false positive.
// A reference (var./local./data.) is never a literal, so it won't match.
func checkSecretResources(file, src string) []Finding {
	if !strings.Contains(src, "aws_secretsmanager_secret_version") &&
		!strings.Contains(src, "aws_ssm_parameter") {
		return nil
	}
	if reSecretLiteral.MatchString(src) {
		return []Finding{finding(file, SevCritical,
			"a secret is stored as a literal string in the .tf (secretsmanager/ssm) — pass it via a variable or generate it, never commit the value. (tfforge does not print it.)")}
	}
	return nil
}

// checkTransit is informational: a plain-HTTP LISTENER (user-facing traffic)
// with no HTTPS anywhere. It only fires for an aws_lb_listener — NOT for a
// health_check protocol, which is internal and legitimately HTTP.
func checkTransit(file, src string) []Finding {
	if !strings.Contains(src, "aws_lb_listener") && !strings.Contains(src, "aws_alb_listener") {
		return nil
	}
	// Look at the listener resource(s) only, not health_check blocks.
	for _, blk := range reLBListener.FindAllString(src, -1) {
		if reHTTPListener.MatchString(blk) && !strings.Contains(strings.ToUpper(blk), "HTTPS") {
			return []Finding{finding(file, SevInfo, "an aws_lb_listener serves plain HTTP with no HTTPS listener — user traffic is unencrypted in transit. Add an HTTPS (443) listener + redirect.")}
		}
	}
	return nil
}

// grantsWildcard reports whether the source appears to ALLOW (not only Deny) a
// wildcard — a cheap heuristic: an Allow effect is present.
func grantsWildcard(src string) bool {
	return regexp.MustCompile(`(?i)"?[Ee]ffect"?\s*[:=]\s*"Allow"`).MatchString(src)
}

var reLBListener = regexp.MustCompile(`(?is)resource\s+"aws_a?lb_listener"\s+"[^"]+"\s*\{.*?\n\}`)
