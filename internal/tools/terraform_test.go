package tools

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// tfBinary must prefer tofu when present (open-source, newer features like
// use_lockfile), fall back to terraform, and honor an explicit TFFORGE_TF_BINARY
// override — the fix for "agent regressed to DynamoDB on an old terraform 1.5.7".
func TestTFBinaryOverride(t *testing.T) {
	// An explicit override that doesn't exist must error, not silently fall back.
	t.Setenv("TFFORGE_TF_BINARY", "definitely-not-a-real-binary-xyz")
	if _, err := tfBinary(); err == nil {
		t.Error("a bogus TFFORGE_TF_BINARY should error, not fall back")
	}
	// An explicit override that DOES exist (any real binary on PATH) is honored.
	if _, err := exec.LookPath("sh"); err == nil {
		t.Setenv("TFFORGE_TF_BINARY", "sh")
		if bin, err := tfBinary(); err != nil || bin != "sh" {
			t.Errorf("override should be honored: got %q, %v", bin, err)
		}
	}
}

func TestTFBinaryPrefersTofu(t *testing.T) {
	os.Unsetenv("TFFORGE_TF_BINARY")
	_, hasTofu := exec.LookPath("tofu")
	bin, err := tfBinary()
	if err != nil {
		t.Skip("neither tofu nor terraform on PATH")
	}
	if hasTofu == nil && bin != "tofu" {
		t.Errorf("tofu is on PATH but tfBinary chose %q — tofu must be preferred", bin)
	}
}

// TestConfineBlocksEscape verifies the path-confinement boundary: since the
// `dir` argument comes from the LLM, a model (or a prompt-injected .tf file)
// must not be able to point terraform outside the project root — neither via an
// absolute path nor via `..` escape.
func TestConfineBlocksEscape(t *testing.T) {
	root := t.TempDir()
	SetProjectRoot(root)
	t.Cleanup(func() { SetProjectRoot("") })

	ok := []string{
		".",
		"staging",
		"envs/prod",
		root,                       // the root itself
		filepath.Join(root, "sub"), // an absolute path inside root
	}
	for _, d := range ok {
		if _, err := confine(d); err != nil {
			t.Errorf("confine(%q) should be allowed under root, got error: %v", d, err)
		}
	}

	bad := []string{
		"/etc",
		"/etc/passwd",
		"../outside",
		"../../way/outside",
		"staging/../../escape",
		filepath.Join(root, "..", "sibling"), // absolute but climbs out
	}
	for _, d := range bad {
		if _, err := confine(d); err == nil {
			t.Errorf("confine(%q) should be REJECTED (escapes project root), but was allowed", d)
		}
	}
}

// TestConfineReturnsAbsolute checks the returned path is absolute and cleaned,
// so runTerraform gets an unambiguous -chdir target.
func TestConfineReturnsAbsolute(t *testing.T) {
	root := t.TempDir()
	SetProjectRoot(root)
	t.Cleanup(func() { SetProjectRoot("") })

	got, err := confine("staging")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
	if got != filepath.Join(root, "staging") {
		t.Errorf("got %q, want %q", got, filepath.Join(root, "staging"))
	}
}
