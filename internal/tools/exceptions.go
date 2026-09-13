package tools

import (
	"fmt"
	"regexp"
	"strings"
)

// An exception a scanner was already told about, in the file itself.
//
//	#checkov:skip=CKV_AWS_107:s3:* is service-wide on purpose in this account
//	#tfsec:ignore:aws-iam-no-policy-wildcards
//
// The rule id and the reason are both captured: an exception without a reason
// is not much of a decision, and we say so rather than honouring it silently.
// [^\S\n] rather than \s: the reason must be on the SAME line. With \s the
// match ran past the newline and swallowed the next line of HCL, which turned a
// bare "#checkov:skip=CKV_AWS_107" into a waiver "justified" by a resource
// declaration — honouring a silencer while quoting code as the reason.
var reException = regexp.MustCompile(`(?im)#[^\S\n]*(checkov:skip|tfsec:ignore|trivy:ignore)[=:]([A-Za-z0-9_.-]+)[^\S\n]*:?[^\S\n]*([^\n]*)$`)

// exception is one documented waiver found in a file.
type exception struct {
	tool   string // checkov, tfsec, trivy
	rule   string // CKV_AWS_107, aws-iam-no-policy-wildcards
	reason string // may be empty
}

// findExceptions collects the waivers declared anywhere in a file's source.
func findExceptions(src string) []exception {
	var out []exception
	for _, m := range reException.FindAllStringSubmatch(src, -1) {
		tool := strings.ToLower(strings.SplitN(m[1], ":", 2)[0])
		out = append(out, exception{
			tool:   tool,
			rule:   strings.TrimSpace(m[2]),
			reason: strings.TrimSpace(m[3]),
		})
	}
	return out
}

// topicOf maps a tfforge finding to the subject it is about, so it can be
// matched against another scanner's rule id. Deliberately coarse: findings carry
// no line number, so this works at the level of "what is this finding about",
// not "which line".
func topicOf(msg string) string {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, `resource "*"`), strings.Contains(l, "all resources"):
		return "iam-wildcard-resource"
	case strings.Contains(l, "service-wide wildcard"), strings.Contains(l, "wildcard action"):
		return "iam-wildcard-action"
	case strings.Contains(l, "public"), strings.Contains(l, `principal "*"`):
		return "public-access"
	case strings.Contains(l, "encrypt"):
		return "encryption"
	case strings.Contains(l, "logging"), strings.Contains(l, "access log"):
		return "logging"
	case strings.Contains(l, "version"):
		return "versioning"
	}
	return ""
}

// exceptionTopics maps the rule ids we can attribute to a subject. Only the ones
// that overlap with a tfforge heuristic are listed — guessing at a catalogue of
// several hundred checks would produce wrong silences, which is worse than noise.
var exceptionTopics = map[string]string{
	// checkov — IAM wildcards
	"CKV_AWS_107": "iam-wildcard-action", // credentials/secrets wildcard
	"CKV_AWS_108": "iam-wildcard-action", // data exfiltration wildcard
	"CKV_AWS_109": "iam-wildcard-resource",
	"CKV_AWS_110": "iam-wildcard-action", // privilege escalation
	"CKV_AWS_111": "iam-wildcard-resource",
	"CKV_AWS_356": "iam-wildcard-resource", // policy allows * on resources
	"CKV_AWS_1":   "iam-wildcard-action",
	"CKV_AWS_49":  "iam-wildcard-action",
	"CKV_AWS_63":  "iam-wildcard-action",
	// checkov — the other subjects tfforge also judges
	"CKV_AWS_18":  "logging",
	"CKV_AWS_21":  "versioning",
	"CKV_AWS_19":  "encryption",
	"CKV_AWS_145": "encryption",
	"CKV_AWS_20":  "public-access",
	"CKV_AWS_54":  "public-access",
	"CKV_AWS_55":  "public-access",
	"CKV_AWS_56":  "public-access",
	// tfsec / trivy
	"aws-iam-no-policy-wildcards":    "iam-wildcard-action",
	"aws-s3-enable-bucket-logging":   "logging",
	"aws-s3-enable-versioning":       "versioning",
	"aws-s3-encryption-customer-key": "encryption",
	"aws-s3-block-public-acls":       "public-access",
}

// match picks the waiver that actually covers this finding. Preference goes to
// one whose written reason mentions what the finding is about — a file may hold
// several waivers on the same topic, and pairing a finding with the wrong reason
// would put words in the author's mouth.
func match(exs []exception, f Finding) (exception, bool) {
	topic := topicOf(f.Message)
	if topic == "" {
		return exception{}, false
	}
	var fallback exception
	var haveFallback bool
	for _, e := range exs {
		if exceptionTopics[e.rule] != topic {
			continue
		}
		if mentionsSubject(e.reason, f.Message) {
			return e, true
		}
		if !haveFallback {
			fallback, haveFallback = e, true
		}
	}
	return fallback, haveFallback
}

// mentionsSubject reports whether a waiver's reason names the same thing the
// finding does — the service prefix in an IAM action, typically ("s3:*", "kms:*").
func mentionsSubject(reason, msg string) bool {
	re := regexp.MustCompile(`"([a-z0-9-]+:[A-Za-z*]+)"`)
	m := re.FindStringSubmatch(msg)
	if m == nil {
		return false
	}
	return strings.Contains(strings.ToLower(reason), strings.ToLower(m[1]))
}

// applyExceptions downgrades findings a scanner was already told to skip, in
// this same file, on the same subject — with a reason.
//
// The point is not to agree with the waiver. It is that the decision has been
// made and written down: repeating it at HIGH every run trains people to skim
// the report, and a report people skim hides the findings that matter. So the
// finding stays visible, at INFO, carrying the reason — a reviewer can still
// disagree with it, which they could not do if it had been deleted.
//
// A waiver with no reason is NOT honoured: "#checkov:skip=CKV_AWS_107" alone is
// a silencer, not a decision.
//
// Matching is deliberately strict about WHICH waiver applies. A file can carry
// several on the same subject, and attaching the wrong reason to a finding is
// worse than attaching none — the report would then justify a decision with an
// argument nobody made. So a waiver whose reason mentions the finding's subject
// wins over one that merely shares a topic.
func applyExceptions(findings []Finding, src string) []Finding {
	exs := findExceptions(src)
	if len(exs) == 0 {
		return findings
	}
	var usable []exception
	for _, e := range exs {
		if e.reason == "" {
			continue // silencing without justifying is not a decision
		}
		if exceptionTopics[e.rule] != "" {
			usable = append(usable, e)
		}
	}
	if len(usable) == 0 {
		return findings
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if e, ok := match(usable, f); ok && f.sev > SevInfo {
			reason := e.reason
			if len(reason) > 120 {
				reason = reason[:120] + "…"
			}
			f.Message = fmt.Sprintf("%s [documented exception · %s:%s — %q]",
				f.Message, e.tool, e.rule, reason)
			f.Severity = SevInfo.String()
			f.sev = SevInfo
		}
		out = append(out, f)
	}
	return out
}
