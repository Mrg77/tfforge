package tools

import (
	"path/filepath"
	"testing"
)

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
