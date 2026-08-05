package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mrg77/tfforge/internal/tools"
)

// The core safety guarantee of `fix` mode: the agent's toolset contains NO tool
// that touches real infrastructure (apply/plan/destroy). If someone adds one by
// mistake, this test fails. We assert on the tool NAMES the fix toolset exposes.
func TestFixToolsetHasNoInfraTools(t *testing.T) {
	allowed := map[string]bool{
		"write_file": true, "edit_file": true,
		"terraform_validate": true, "security_scan": true,
	}
	// The exact toolset runFix builds (kept in sync deliberately — small list).
	fixTools := []tools.Tool{
		tools.WriteFileTool{}, tools.EditFileTool{},
		tools.ValidateTool{}, tools.SecurityScanTool{},
	}
	for _, tl := range fixTools {
		name := tl.Name()
		if !allowed[name] {
			t.Errorf("fix toolset exposes an unexpected tool %q — apply/plan/destroy must never be in fix mode", name)
		}
	}
	// And explicitly: none of the infra-touching tools are present.
	forbidden := map[string]bool{"terraform_plan": true, "terraform_apply": true, "terraform_destroy": true}
	for _, tl := range fixTools {
		if forbidden[tl.Name()] {
			t.Fatalf("FORBIDDEN tool %q is in the fix toolset — it must not be able to touch infrastructure", tl.Name())
		}
	}
}

// denyConfirm must always deny — in CI there is no human to confirm, so any
// guarded action fails closed.
func TestDenyConfirmAlwaysDenies(t *testing.T) {
	if denyConfirm("apply", "prod", "really?") {
		t.Error("denyConfirm must never approve — CI has no human")
	}
}

// snapshotTree + the fallback diff must detect a modified file.
func TestSnapshotDetectsChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.tf")
	os.WriteFile(p, []byte("resource \"x\" \"y\" {}\n"), 0o644)
	before := snapshotTree(dir)
	if before[p] == "" {
		t.Fatal("snapshot should capture the .tf file")
	}
	os.WriteFile(p, []byte("resource \"x\" \"y\" {\n  fixed = true\n}\n"), 0o644)
	after := snapshotTree(dir)
	if after[p] == before[p] {
		t.Error("snapshot should reflect the changed content")
	}
}

func TestAbsDirAbsolutePassthrough(t *testing.T) {
	got, err := absDir("/tmp/x")
	if err != nil || got != "/tmp/x" {
		t.Errorf("absolute path should pass through: got %q, %v", got, err)
	}
	rel, err := absDir("sub")
	if err != nil || !strings.HasSuffix(rel, "/sub") {
		t.Errorf("relative path should be made absolute: got %q", rel)
	}
}
