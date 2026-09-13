package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mrg77/tfforge/internal/repo"
)

// verifyEnrichments runs every AI-proposed "after" block through the Terraform
// parser before it is ever shown, and marks the ones that do not parse.
//
// Why this exists, from a real run: the model was asked to fix a
// "no required_providers" finding and proposed adding a second
// required_providers block to a module that already had one in versions.tf.
// The suggestion read perfectly and would have broken `init`. The model had no
// way to know — it saw one file, and it trusted the rule.
//
// So the deterministic half checks the agentic half, which is the same
// arrangement as `fix`: the model proposes, the parser decides. A suggestion
// that does not parse is not hidden — it is labelled, because a reviewer should
// see that the tool caught it rather than wonder what was filtered out.
func verifyEnrichments(dir string, enr map[string]repo.Enrichment) map[string]repo.Enrichment {
	bin := tfBinaryOrEmpty()
	if bin == "" || len(enr) == 0 {
		return enr
	}
	for i, e := range enr {
		if strings.TrimSpace(e.After) == "" {
			continue
		}
		if err := parses(bin, dir, e.After); err != nil {
			e.Prose = strings.TrimSpace(e.Prose)
			if e.Prose != "" && !strings.HasSuffix(e.Prose, ".") {
				e.Prose += "."
			}
			e.Prose = strings.TrimSpace(e.Prose + " ⚠ This suggestion does not parse on its own (" +
				firstLine(err.Error()) + "). It may still be correct as a fragment of a larger block — " +
				"read it before applying, do not paste it blindly.")
			enr[i] = e
		}
	}
	return enr
}

// parses writes the snippet to a throwaway directory and asks the CLI whether
// it is valid HCL. A fragment (a single statement pulled out of a block) will
// legitimately fail here, which is why the result is a warning and not a
// deletion.
func parses(bin, dir, snippet string) error {
	tmp, err := os.MkdirTemp("", "tfforge-verify-*")
	if err != nil {
		return nil // cannot verify: say nothing rather than accuse wrongly
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "candidate.tf"), []byte(snippet+"\n"), 0o644); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// `fmt -check` parses the file without needing providers, a backend, or the
	// network — `validate` would demand an init and turn a 20 ms check into a
	// download.
	cmd := exec.CommandContext(ctx, bin, "fmt", "-check", "-no-color", filepath.Join(tmp, "candidate.tf"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// `fmt -check` exits non-zero for a formatting difference too, which is not
	// a syntax error. Only a parse error mentions the file and a position.
	s := string(out)
	if strings.Contains(s, "Argument or block definition required") ||
		strings.Contains(s, "Invalid") || strings.Contains(s, "Unclosed") ||
		strings.Contains(s, "Missing") || strings.Contains(s, "Unsupported") {
		return fmt.Errorf("%s", strings.TrimSpace(s))
	}
	return nil
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			if len(t) > 90 {
				t = t[:90] + "…"
			}
			return t
		}
	}
	return "parse error"
}

// tfBinaryOrEmpty returns the CLI to parse with, or "" when neither is present:
// verification is a bonus, never a reason to fail the report.
func tfBinaryOrEmpty() string {
	for _, b := range []string{"tofu", "terraform"} {
		if _, err := exec.LookPath(b); err == nil {
			return b
		}
	}
	return ""
}
