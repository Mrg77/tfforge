package tools

import (
	"regexp"
	"strings"
)

// GCP provider-aware security rules — the Google Cloud equivalents of the AWS
// checks. Same philosophy: high-signal, deterministic, plain-language. They only
// fire on GCP resources (google_*), so a pure-AWS or pure-Azure file sees nothing.

var (
	// A GCS bucket made public: an IAM member of allUsers / allAuthenticatedUsers.
	reGCSAllUsers = regexp.MustCompile(`(?i)"(allUsers|allAuthenticatedUsers)"`)
	// A firewall rule open to the world (0.0.0.0/0) — GCP's source_ranges.
	reGCPSourceRangesWorld = regexp.MustCompile(`(?i)source_ranges\s*=\s*\[[^\]]*"0\.0\.0\.0/0"`)
	// SSH (22) / RDP (3389) in a firewall's allow block.
	reGCPPort22   = regexp.MustCompile(`(?i)ports\s*=\s*\[[^\]]*"22"`)
	reGCPPort3389 = regexp.MustCompile(`(?i)ports\s*=\s*\[[^\]]*"3389"`)
	// A project-level IAM binding to a primitive role (roles/owner|editor) — over-broad.
	rePrimitiveRole = regexp.MustCompile(`(?i)role\s*=\s*"roles/(owner|editor)"`)
	// A service account key resource in Terraform = a long-lived credential (bad).
	reSAKey = regexp.MustCompile(`(?i)resource\s+"google_service_account_key"`)
	// A Compute instance with a public IP (access_config present, often empty {}).
	reComputePublicIP = regexp.MustCompile(`(?is)resource\s+"google_compute_instance".*?access_config\s*\{`)
)

// checkGCP runs the Google Cloud rules. No-op when the file has no google_ resources.
func checkGCP(file, src string) []Finding {
	if !strings.Contains(src, `"google_`) && !strings.Contains(src, "google_") {
		return nil
	}
	var out []Finding

	// Public GCS bucket via an IAM member of allUsers.
	if reGCSAllUsers.MatchString(src) &&
		(strings.Contains(src, "google_storage_bucket") || strings.Contains(src, "storage")) {
		out = append(out, finding(file, SevCritical,
			`a GCS bucket grants access to allUsers/allAuthenticatedUsers — the bucket is public to the internet. Remove the public IAM member.`))
	}

	// Firewall open to the world on SSH / RDP.
	if reGCPSourceRangesWorld.MatchString(src) {
		if reGCPPort22.MatchString(src) {
			out = append(out, finding(file, SevCritical,
				`a google_compute_firewall opens SSH (port 22) to 0.0.0.0/0 — restrict source_ranges or use IAP.`))
		}
		if reGCPPort3389.MatchString(src) {
			out = append(out, finding(file, SevCritical,
				`a google_compute_firewall opens RDP (port 3389) to 0.0.0.0/0 — restrict source_ranges.`))
		}
	}

	// Primitive (owner/editor) IAM role — the GCP equivalent of Action "*".
	if rePrimitiveRole.MatchString(src) {
		out = append(out, finding(file, SevHigh,
			`an IAM binding uses a primitive role (roles/owner or roles/editor) — far too broad. Use a predefined or custom role scoped to what's needed.`))
	}

	// A service-account key in Terraform: a long-lived credential that lands in
	// state and often in VCS. Prefer workload identity / short-lived creds.
	if reSAKey.MatchString(src) {
		out = append(out, finding(file, SevHigh,
			`a google_service_account_key creates a long-lived key (stored in state) — prefer workload identity or short-lived credentials.`))
	}

	// A Compute instance with a public IP.
	if reComputePublicIP.MatchString(src) {
		out = append(out, finding(file, SevMedium,
			`a google_compute_instance has a public IP (access_config) — avoid exposing VMs directly; use a bastion / IAP / load balancer.`))
	}

	return out
}
