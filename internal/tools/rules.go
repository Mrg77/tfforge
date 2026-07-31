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
	// Security-group rules open to the world (0.0.0.0/0) on any port.
	reSGOpenWorld = regexp.MustCompile(`(?i)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"`)
	// The dangerous ones specifically: SSH (22) / RDP (3389) open to the world.
	reIngress  = regexp.MustCompile(`(?is)ingress\s*\{.*?\}`)
	rePort22   = regexp.MustCompile(`(?i)(from_port|to_port)\s*=\s*22\b`)
	rePort3389 = regexp.MustCompile(`(?i)(from_port|to_port)\s*=\s*3389\b`)
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
	}
	if rePubliclyAccessible.MatchString(src) {
		out = append(out, finding(file, SevHigh, "a resource sets publicly_accessible = true — databases/instances should not be reachable from the public internet."))
	}
	return out
}

// checkIAMFine flags least-privilege gaps that a coarse "no Action *" check
// misses: service-wide wildcards, account-wide S3 resources, and PassRole *.
func checkIAMFine(file, src string) []Finding {
	var out []Finding
	if m := reServiceWildcardAction.FindStringSubmatch(src); m != nil {
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

// checkTransit is informational: a plain-HTTP listener with no HTTPS anywhere.
func checkTransit(file, src string) []Finding {
	if reHTTPListener.MatchString(src) && !strings.Contains(strings.ToUpper(src), "HTTPS") {
		return []Finding{finding(file, SevInfo, "a load-balancer listener uses plain HTTP with no HTTPS listener present — traffic is unencrypted in transit. Add an HTTPS (443) listener + redirect.")}
	}
	return nil
}
