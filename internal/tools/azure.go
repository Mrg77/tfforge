package tools

import (
	"regexp"
	"strings"
)

// Azure provider-aware security rules (azurerm_*), the equivalents of the AWS/GCP
// checks. Deterministic, high-signal, fire only on Azure resources.

var (
	// An NSG rule allowing inbound from any source (* or 0.0.0.0/0 or "Internet").
	reAzureAnySource = regexp.MustCompile(`(?i)source_address_prefix\s*=\s*"(\*|0\.0\.0\.0/0|Internet)"`)
	reAzureInbound   = regexp.MustCompile(`(?i)direction\s*=\s*"Inbound"`)
	reAzurePort22    = regexp.MustCompile(`(?i)destination_port_range\s*=\s*"(22|\*)"`)
	reAzurePort3389  = regexp.MustCompile(`(?i)destination_port_range\s*=\s*"(3389|\*)"`)
	// A storage account allowing public blob access.
	reAzurePublicBlob = regexp.MustCompile(`(?i)allow_(nested_items_to_be_public|blob_public_access)\s*=\s*true`)
	// A storage account without HTTPS-only enforced (defaults changed over versions).
	reAzureHTTPSOnly = regexp.MustCompile(`(?i)(enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*false`)
	// A storage account without a minimum TLS version, or an old one.
	reAzureOldTLS = regexp.MustCompile(`(?i)min_tls_version\s*=\s*"TLS1_0"`)
)

// checkAzure runs the Azure rules. No-op when there are no azurerm_ resources.
func checkAzure(file, src string) []Finding {
	if !strings.Contains(src, "azurerm_") {
		return nil
	}
	var out []Finding

	// NSG inbound from anywhere on SSH / RDP.
	if reAzureAnySource.MatchString(src) && reAzureInbound.MatchString(src) {
		if reAzurePort22.MatchString(src) {
			out = append(out, finding(file, SevCritical,
				`an NSG rule allows inbound SSH (port 22) from any source (*/Internet) — restrict source_address_prefix to known IPs or use Azure Bastion.`))
		}
		if reAzurePort3389.MatchString(src) {
			out = append(out, finding(file, SevCritical,
				`an NSG rule allows inbound RDP (port 3389) from any source — restrict source_address_prefix.`))
		}
	}

	// Public blob access on a storage account.
	if reAzurePublicBlob.MatchString(src) {
		out = append(out, finding(file, SevCritical,
			`a storage account allows public blob access — containers can be exposed to the internet. Set allow_nested_items_to_be_public = false.`))
	}

	// HTTPS-only disabled — traffic can be plaintext.
	if reAzureHTTPSOnly.MatchString(src) {
		out = append(out, finding(file, SevHigh,
			`a storage account has HTTPS-only disabled — data can transit in plaintext. Enforce https_traffic_only_enabled = true.`))
	}

	// Old TLS floor.
	if reAzureOldTLS.MatchString(src) {
		out = append(out, finding(file, SevMedium,
			`a storage account allows TLS 1.0 — set min_tls_version = "TLS1_2".`))
	}

	return out
}
