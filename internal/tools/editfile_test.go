package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func editInput(path, old, new string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"path": path, "old": old, "new": new})
	return b
}

func TestEditFileReplacesOnce(t *testing.T) {
	root := t.TempDir()
	SetProjectRoot(root)
	t.Cleanup(func() { SetProjectRoot("") })
	os.WriteFile(filepath.Join(root, "f.tf"), []byte("acl = \"public-read\"\n"), 0o644)

	out, err := (EditFileTool{}).Run(context.Background(), editInput("f.tf", `"public-read"`, `"private"`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 replacement") {
		t.Errorf("unexpected result: %s", out)
	}
	data, _ := os.ReadFile(filepath.Join(root, "f.tf"))
	if !strings.Contains(string(data), `"private"`) {
		t.Error("edit did not apply")
	}
}

func TestEditFileRefusesAmbiguous(t *testing.T) {
	root := t.TempDir()
	SetProjectRoot(root)
	t.Cleanup(func() { SetProjectRoot("") })
	// "true" appears twice → ambiguous, must error rather than edit the wrong one.
	os.WriteFile(filepath.Join(root, "f.tf"), []byte("a = true\nb = true\n"), 0o644)

	if _, err := (EditFileTool{}).Run(context.Background(), editInput("f.tf", "true", "false")); err == nil {
		t.Error("editing an ambiguous (multi-match) snippet must error")
	}
}

func TestEditFileRefusesMissing(t *testing.T) {
	root := t.TempDir()
	SetProjectRoot(root)
	t.Cleanup(func() { SetProjectRoot("") })
	os.WriteFile(filepath.Join(root, "f.tf"), []byte("x = 1\n"), 0o644)

	if _, err := (EditFileTool{}).Run(context.Background(), editInput("f.tf", "not-there", "y")); err == nil {
		t.Error("editing a missing snippet must error")
	}
}

func TestEditFileConfinedAndTyped(t *testing.T) {
	root := t.TempDir()
	SetProjectRoot(root)
	t.Cleanup(func() { SetProjectRoot("") })

	// Outside the project root → rejected.
	if _, err := (EditFileTool{}).Run(context.Background(), editInput("/etc/hosts", "a", "b")); err == nil {
		t.Error("editing outside the project root must be rejected")
	}
	// A non-config extension → rejected.
	os.WriteFile(filepath.Join(root, "s.sh"), []byte("echo hi\n"), 0o644)
	if _, err := (EditFileTool{}).Run(context.Background(), editInput("s.sh", "hi", "bye")); err == nil {
		t.Error("editing a non-config file must be rejected")
	}
}
