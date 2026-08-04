package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mrg77/tfforge/internal/tools"
)

// buildRepo writes a realistic multi-dir Terraform repo into a temp dir.
func buildRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	// A CRITICAL in a module, a HIGH in prod, a clean env, and a .terraform/
	// dir that must be ignored.
	write("modules/net/main.tf", `
resource "aws_security_group" "s" {
  ingress { from_port = 22, to_port = 22, cidr_blocks = ["0.0.0.0/0"] }
}`)
	write("environments/prod/main.tf", `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}`)
	write("environments/staging/main.tf", `
terraform {
  required_version = ">= 1.5"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
  backend "s3" { bucket = "x" key = "y" region = "eu-west-1" }
}
provider "aws" { region = var.r }`)
	// This must be skipped entirely.
	write(".terraform/junk.tf", `resource "aws_s3_bucket" "ignored" { acl = "public-read" }`)
	return root
}

func TestAuditWalksRecursively(t *testing.T) {
	root := buildRepo(t)
	rep, err := Audit(root)
	if err != nil {
		t.Fatal(err)
	}
	// 3 real dirs (net, prod, staging) — .terraform skipped.
	if rep.DirsScanned != 3 {
		t.Errorf("expected 3 scanned dirs (.terraform skipped), got %d", rep.DirsScanned)
	}
	// The ignored bucket in .terraform must not appear.
	for _, f := range rep.Findings {
		if strings.Contains(f.File, ".terraform") {
			t.Errorf(".terraform finding leaked into the report: %s", f.File)
		}
	}
}

func TestAuditPrioritizesWorstFirst(t *testing.T) {
	root := buildRepo(t)
	rep, _ := Audit(root)
	if len(rep.Findings) == 0 {
		t.Fatal("expected findings")
	}
	// The very first finding must be the CRITICAL (SSH to the world), not a LOW.
	if rep.Findings[0].Sev() != tools.SevCritical {
		t.Errorf("worst finding should be first; got %s (%s)", rep.Findings[0].Severity, rep.Findings[0].Message)
	}
	// Findings must be non-increasing in severity.
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i].Sev() > rep.Findings[i-1].Sev() {
			t.Errorf("findings not sorted worst-first at %d", i)
		}
	}
}

func TestAuditFileHasDirPrefix(t *testing.T) {
	root := buildRepo(t)
	rep, _ := Audit(root)
	// A finding's File must carry its directory, so the report is navigable.
	found := false
	for _, f := range rep.Findings {
		if strings.Contains(f.File, "modules/net") || strings.Contains(f.File, "environments/prod") {
			found = true
		}
	}
	if !found {
		t.Error("findings should be prefixed with their repo-relative directory")
	}
}

func TestAuditJSONShape(t *testing.T) {
	root := buildRepo(t)
	rep, _ := Audit(root)
	js := rep.JSON()
	for _, key := range []string{`"root"`, `"dirs_scanned"`, `"max_severity"`, `"findings"`, `"category"`} {
		if !strings.Contains(js, key) {
			t.Errorf("JSON report missing %s", key)
		}
	}
}

func TestAuditEmptyRepo(t *testing.T) {
	root := t.TempDir() // no .tf files
	rep, err := Audit(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || rep.TFFiles != 0 {
		t.Error("an empty repo should have no findings")
	}
	if !strings.Contains(rep.Text(10, false), "no findings") {
		t.Error("empty repo text should say 'no findings'")
	}
}
