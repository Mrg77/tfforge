package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func analyzeSrc(t *testing.T, src string) []Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return AnalyzeDir(dir)
}

const wildcardPolicy = `
data "aws_iam_policy_document" "p" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]
  }
}`

// Without a waiver the finding keeps its severity: the exception mechanism must
// not soften anything on its own.
func TestWithoutWaiverSeverityIsUnchanged(t *testing.T) {
	for _, f := range analyzeSrc(t, wildcardPolicy) {
		if strings.Contains(f.Message, "documented exception") {
			t.Fatalf("no waiver was declared, nothing should be marked as excepted:\n  %s", f.Message)
		}
	}
}

// A waiver WITH a reason downgrades to INFO and carries the reason, so the
// decision stays visible and arguable instead of being repeated at HIGH forever.
func TestDocumentedWaiverDowngradesAndKeepsTheReason(t *testing.T) {
	src := "#checkov:skip=CKV_AWS_107:s3:* is service-wide on purpose in this practice account\n" + wildcardPolicy
	var seen bool
	for _, f := range analyzeSrc(t, src) {
		if !strings.Contains(f.Message, "documented exception") {
			continue
		}
		seen = true
		if f.Severity != SevInfo.String() {
			t.Fatalf("a documented exception must drop to INFO, got %s", f.Severity)
		}
		if !strings.Contains(f.Message, "practice account") {
			t.Fatalf("the reason must travel with the finding:\n  %s", f.Message)
		}
	}
	if !seen {
		t.Fatal("the waiver was not applied at all")
	}
}

// Silencing without justifying is not a decision, so a bare skip is ignored.
func TestWaiverWithoutReasonIsIgnored(t *testing.T) {
	src := "#checkov:skip=CKV_AWS_107\n" + wildcardPolicy
	for _, f := range analyzeSrc(t, src) {
		if strings.Contains(f.Message, "documented exception") {
			t.Fatalf("a reasonless waiver must not be honoured:\n  %s", f.Message)
		}
	}
}

// A file can carry several waivers on the same topic. Attaching the wrong
// reason to a finding would justify a decision with an argument nobody made.
func TestTheWaiverWhoseReasonMatchesWins(t *testing.T) {
	src := `#checkov:skip=CKV_AWS_110:iam:PassRole is limited to the medscan-* prefix
#checkov:skip=CKV_AWS_107:s3:* is service-wide on purpose in this practice account
` + wildcardPolicy
	for _, f := range analyzeSrc(t, src) {
		if !strings.Contains(f.Message, "documented exception") {
			continue
		}
		if strings.Contains(f.Message, `"s3:*"`) && !strings.Contains(f.Message, "CKV_AWS_107") {
			t.Fatalf("the s3 finding must cite the s3 waiver, got:\n  %s", f.Message)
		}
	}
}

// A waiver in one file must not excuse a finding in another.
func TestWaiverDoesNotLeakAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "waived.tf"),
		[]byte("#checkov:skip=CKV_AWS_107:deliberate in this file only\n"+wildcardPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.tf"), []byte(wildcardPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range AnalyzeDir(dir) {
		if f.File == "other.tf" && strings.Contains(f.Message, "documented exception") {
			t.Fatalf("a waiver must not cross file boundaries:\n  %s", f.Message)
		}
	}
}

// tfsec and trivy use a different syntax; both are decisions written in the code.
func TestTfsecIgnoreIsRecognised(t *testing.T) {
	src := "#tfsec:ignore:aws-iam-no-policy-wildcards wildcards are intentional here\n" + wildcardPolicy
	found := false
	for _, f := range analyzeSrc(t, src) {
		if strings.Contains(f.Message, "tfsec:aws-iam-no-policy-wildcards") {
			found = true
		}
	}
	if !found {
		t.Fatal("a tfsec:ignore with a reason must be recognised like a checkov:skip")
	}
}
