package tools

import (
	"regexp"
	"strings"
)

// This file adds DETERMINISTIC checks beyond security: outdated/deprecated
// Terraform & provider usage (category "version") and a few concrete,
// non-subjective best practices (category "best-practice"). Deterministic means
// NO LLM and NO tokens — these run in the agent's scan AND standalone in CI.
//
// We stay conservative on "best practice": only rules that are objectively
// checkable (a missing required_version, a hard-coded provider region, an
// unpinned provider), never taste-based style opinions.

// --- version / deprecation checks ------------------------------------------

var (
	// The modern AWS provider (v4+) deprecates inline S3 sub-config in favor of
	// separate resources. Flagging these both modernizes the code AND is exactly
	// what makes a checkov-clean file still "old style".
	reS3InlineACL        = regexp.MustCompile(`(?is)resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[^}]*\bacl\s*=`)
	reS3InlineVersioning = regexp.MustCompile(`(?is)resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[^}]*\bversioning\s*\{`)
	reS3InlineSSE        = regexp.MustCompile(`(?is)resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[^}]*\bserver_side_encryption_configuration\s*\{`)
	reS3InlineLogging    = regexp.MustCompile(`(?is)resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[^}]*\blogging\s*\{`)

	// terraform { required_version = "..." } — presence + a too-old floor.
	reRequiredVersion = regexp.MustCompile(`(?i)required_version\s*=\s*"([^"]+)"`)
	// A provider version constraint like version = "~> 4.0" (to detect old floors).
	reProviderVersion = regexp.MustCompile(`(?is)source\s*=\s*"[^"]*aws"[^}]*?version\s*=\s*"([^"]+)"`)
)

// checkVersions flags outdated/deprecated Terraform & provider usage.
func checkVersions(file, src string) []Finding {
	var out []Finding

	if reS3InlineACL.MatchString(src) {
		out = append(out, findingCat(file, CatVersion, SevMedium,
			`deprecated: inline "acl" on aws_s3_bucket (AWS provider v4+) — use a separate aws_s3_bucket_acl resource.`))
	}
	if reS3InlineVersioning.MatchString(src) {
		out = append(out, findingCat(file, CatVersion, SevMedium,
			`deprecated: inline "versioning" block on aws_s3_bucket — use aws_s3_bucket_versioning.`))
	}
	if reS3InlineSSE.MatchString(src) {
		out = append(out, findingCat(file, CatVersion, SevMedium,
			`deprecated: inline "server_side_encryption_configuration" on aws_s3_bucket — use aws_s3_bucket_server_side_encryption_configuration.`))
	}
	if reS3InlineLogging.MatchString(src) {
		out = append(out, findingCat(file, CatVersion, SevLow,
			`deprecated: inline "logging" block on aws_s3_bucket — use aws_s3_bucket_logging.`))
	}

	// required_version: warn if a terraform{} block exists without it, and flag
	// a floor pinned below 1.0 (very old).
	if strings.Contains(src, "terraform {") || strings.Contains(src, "terraform{") {
		if m := reRequiredVersion.FindStringSubmatch(src); m == nil {
			out = append(out, findingCat(file, CatVersion, SevLow,
				`no required_version in the terraform{} block — pin a minimum (e.g. required_version = ">= 1.5") for reproducibility.`))
		} else if strings.Contains(m[1], "0.") && !strings.Contains(m[1], "1.") {
			out = append(out, findingCat(file, CatVersion, SevMedium,
				`required_version "`+m[1]+`" targets a pre-1.0 Terraform — upgrade the floor (current stable is 1.x).`))
		}
	}

	// Provider pinned to an old major (aws v3 or lower is well behind).
	if m := reProviderVersion.FindStringSubmatch(src); m != nil {
		if strings.HasPrefix(strings.TrimLeft(m[1], "~>= v"), "3.") ||
			strings.HasPrefix(strings.TrimLeft(m[1], "~>= v"), "2.") {
			out = append(out, findingCat(file, CatVersion, SevMedium,
				`the AWS provider is pinned to "`+m[1]+`" (v3 or older) — v5 is current; older majors miss the modern S3 resources and fixes.`))
		}
	}
	return out
}

// --- best-practice checks (objective only) ---------------------------------

var (
	// reAnyProvider / reAwsProvider match a `provider "<name>"` declaration at the
	// START of a line (?m)^\s* — so a "provider" inside a # comment or a string
	// does NOT count. This is what keeps best-practice rules from firing on an
	// OVH/OpenStack repo that merely mentions AWS in a comment.
	reAnyProvider = regexp.MustCompile(`(?m)^\s*provider\s+"[a-z0-9_-]+"`)
	reAwsProvider = regexp.MustCompile(`(?m)^\s*provider\s+"aws"`)
	// reProviderBody captures a provider block's body to look for a hard-coded
	// region/location inside it (provider-agnostic — AWS, OVH, GCP, Azure).
	reProviderBody = regexp.MustCompile(`(?ism)^[ \t]*provider\s+"[a-z0-9_-]+"\s*\{(.*?)\n\}`)
	// A hard-coded region OR location set to a string literal (not a var./local.).
	// Works for AWS "us-east-1", OVH "GRA7", GCP "us-central1", Azure "westeurope".
	reHardcodedRegion = regexp.MustCompile(`(?im)^\s*(region|location)\s*=\s*"[A-Za-z0-9_-]+"`)
	reRequiredProv    = regexp.MustCompile(`(?i)required_providers`)
	reBackend         = regexp.MustCompile(`(?i)backend\s+"`)
	reResourceCount   = regexp.MustCompile(`(?m)^\s*resource\s+"`)
)

// checkBestPractices flags a few concrete, non-subjective Terraform practices.
func checkBestPractices(file, src string) []Finding {
	var out []Finding

	// A hard-coded region/location inside a provider block (should be a variable).
	// Provider-agnostic so it also serves OVH/OpenStack/GCP/Azure, not just AWS.
	if m := reProviderBody.FindStringSubmatch(src); m != nil && reHardcodedRegion.MatchString(m[1]) {
		out = append(out, findingCat(file, CatBestPractice, SevLow,
			`the provider region/location is hard-coded — make it a variable (var.region) so the config is reusable across regions.`))
	}

	// Provider configured but not pinned via required_providers (reproducibility).
	if reAnyProvider.MatchString(src) && !reRequiredProv.MatchString(src) {
		out = append(out, findingCat(file, CatBestPractice, SevLow,
			`no required_providers block — pin provider sources/versions in terraform{ required_providers {} } for reproducible builds.`))
	}

	// NOTE: the "no remote backend" check is deliberately NOT here. A backend is a
	// property of a root MODULE (a whole directory), declared once — never per
	// file, and never in a child module at all. Checking it per file produced
	// false positives on every child module (e.g. monitors/redis). It now lives
	// in checkDirBestPractices, which sees the whole directory. See analyze.go.
	return out
}

// checkDirBestPractices runs the best-practice checks that need WHOLE-DIRECTORY
// context, not a single file. Terraform resolves a module (a directory) as a
// unit: the backend, the provider config, and required_version belong to the
// directory, so judging them file-by-file is wrong. dirSrc is every .tf file in
// the directory concatenated; hasProvider says whether any file configures a
// provider (i.e. this looks like a ROOT module, not a child module).
func checkDirBestPractices(dir, dirSrc string, hasProvider bool) []Finding {
	var out []Finding
	// A remote backend only makes sense for a ROOT module (one with provider
	// config and enough resources to have real state). A child module never
	// declares a backend, so flagging its absence there is a false positive.
	if hasProvider && countMatches(reResourceCount, dirSrc) >= 3 && !reBackend.MatchString(dirSrc) {
		out = append(out, findingCat(dir, CatBestPractice, SevInfo,
			`no remote backend configured — local state doesn't lock or share. Add a backend (s3+dynamodb, etc.) for team/production use.`))
	}
	return out
}

func countMatches(re *regexp.Regexp, src string) int {
	n := 0
	for _, line := range strings.Split(src, "\n") {
		if re.MatchString(line) {
			n++
		}
	}
	return n
}
