package tools

import "testing"

// --- GCP ---

func TestGCPPublicBucket(t *testing.T) {
	mustFlag(t, scan(t, `
resource "google_storage_bucket_iam_member" "pub" {
  bucket = google_storage_bucket.b.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}`), "allUsers")
}

func TestGCPFirewallSSHOpen(t *testing.T) {
	mustFlag(t, scan(t, `
resource "google_compute_firewall" "ssh" {
  allow { protocol = "tcp", ports = ["22"] }
  source_ranges = ["0.0.0.0/0"]
}`), "opens SSH")
}

func TestGCPPrimitiveRole(t *testing.T) {
	mustFlag(t, scan(t, `
resource "google_project_iam_member" "own" {
  role   = "roles/owner"
  member = "user:x@y.com"
}`), "primitive role")
}

func TestGCPCleanIsQuiet(t *testing.T) {
	// A private bucket with uniform access must raise no security finding.
	fs := scan(t, `
resource "google_storage_bucket" "b" {
  name = "my-bucket"
  uniform_bucket_level_access = true
}`)
	for _, f := range fs {
		if f.Category == CatSecurity {
			t.Errorf("clean GCP produced a security finding: %s", f.Message)
		}
	}
}

// --- Azure ---

func TestAzureNSGOpenSSH(t *testing.T) {
	mustFlag(t, scan(t, `
resource "azurerm_network_security_rule" "ssh" {
  direction              = "Inbound"
  destination_port_range = "22"
  source_address_prefix  = "*"
}`), "inbound SSH")
}

func TestAzurePublicBlob(t *testing.T) {
	mustFlag(t, scan(t, `
resource "azurerm_storage_account" "s" {
  allow_nested_items_to_be_public = true
}`), "public blob access")
}

func TestAzureOldTLS(t *testing.T) {
	mustFlag(t, scan(t, `
resource "azurerm_storage_account" "s" {
  min_tls_version = "TLS1_0"
}`), "TLS 1.0")
}

// A pure-AWS file must not trigger any GCP/Azure rule, and vice versa — the
// provider gate keeps the checks isolated.
func TestProviderIsolation(t *testing.T) {
	awsOnly := scan(t, `resource "aws_s3_bucket" "b" { bucket = "x" }`)
	for _, f := range awsOnly {
		if len(f.Message) > 0 && (contains(f.Message, "GCS") || contains(f.Message, "NSG") || contains(f.Message, "azurerm") || contains(f.Message, "primitive role")) {
			t.Errorf("an AWS-only file triggered a GCP/Azure rule: %s", f.Message)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
