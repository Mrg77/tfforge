package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// runDrift is the "is reality still what Terraform thinks?" command:
//
//	tfforge drift <dir> [--markdown]
//
// It answers two questions a running deployment needs, without an LLM:
//  1. DRIFT — did someone change a managed resource by hand (in the console,
//     the CLI…)? Detected with `tofu plan -detailed-exitcode` against the real
//     state: exit 0 = in sync, 2 = drift.
//  2. UNMANAGED — resources that exist in the cloud but are NOT in the state
//     (created by hand, never imported). Detected by listing the cloud (aws cli)
//     and diffing against `tofu state list`.
//
// It shells out to the same tofu/terraform binary the rest of tfforge uses, and
// to the aws cli for the unmanaged sweep — orchestrating existing tools rather
// than reimplementing cloud discovery.
func runDrift(args []string) int {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	asMarkdown := fs.Bool("markdown", false, "emit a GitHub-flavored Markdown report (for a CI job summary)")
	failOnDrift := fs.Bool("fail-on-drift", false, "exit non-zero if drift or unmanaged resources are found (gate CI/cron)")
	skipUnmanaged := fs.Bool("no-unmanaged", false, "skip the unmanaged-resource sweep (drift only)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tfforge drift <dir> [--markdown] [--fail-on-drift] [--no-unmanaged]")
	}
	dir, rest := splitDirAndFlags(args)
	if dir == "" {
		fs.Usage()
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "tfforge drift: %q is not a directory\n", dir)
		return 2
	}

	rep := &driftReport{Dir: dir}

	// --- 1. Drift: tofu plan -detailed-exitcode ------------------------------
	bin := tfBin()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// init (quiet) so plan can reach the backend.
	if out, err := runTF(ctx, bin, dir, "init", "-input=false"); err != nil {
		fmt.Fprintln(os.Stderr, "tfforge drift: init failed:\n"+out)
		return 1
	}
	// Plan to a binary file, then read it as STRUCTURED JSON (tofu show -json) —
	// never parse the human text, which is fragile on tags/nested blocks/lists.
	changed, code, err := planJSON(ctx, bin, dir)
	switch {
	case err != nil:
		rep.Drift = driftError
		rep.Err = err.Error()
	case code == 0:
		rep.Drift = driftNone
	default:
		rep.Drift = driftFound
		rep.DriftedResources = changed
	}

	// --- 2. Unmanaged resources: cloud vs state ------------------------------
	// Scan the region the Terraform actually targets, NOT the shell's default
	// (AWS_DEFAULT_REGION). A VPC created by hand in eu-west-3 is invisible to a
	// describe-vpcs run against us-east-1 — that would silently miss real drift.
	if !*skipUnmanaged && rep.Drift != driftError {
		region := providerRegion(dir)
		rep.Region = region
		stateIDs := managedCloudIDs(ctx, bin, dir)
		rep.Unmanaged = findUnmanaged(ctx, stateIDs, region)
	}

	// --- Render --------------------------------------------------------------
	if *asMarkdown {
		fmt.Println(rep.markdown())
	} else {
		fmt.Println(rep.text(colorStdout()))
	}

	if *failOnDrift && (rep.Drift == driftFound || len(rep.Unmanaged) > 0) {
		return 1
	}
	if rep.Drift == driftError {
		return 1
	}
	return 0
}

// tfBin resolves tofu (preferred) or terraform for the drift command, honoring
// TFFORGE_TF_BINARY. Mirrors internal/tools.tfBinary (kept local to package main).
func tfBin() string {
	if b := os.Getenv("TFFORGE_TF_BINARY"); b != "" {
		return b
	}
	if _, err := exec.LookPath("tofu"); err == nil {
		return "tofu"
	}
	return "terraform"
}

func runTF(ctx context.Context, bin, dir string, args ...string) (string, error) {
	full := append([]string{"-chdir=" + dir}, args...)
	cmd := exec.CommandContext(ctx, bin, full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// providerRegion reads the AWS region the config targets, from a
// `region = "..."` in the .tf files (the provider block). Returns "" if not
// found — the aws cli then falls back to its default region. This makes the
// unmanaged sweep look where the infra actually lives, not where the shell's
// AWS_DEFAULT_REGION points.
func providerRegion(dir string) string {
	files, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	re := regexp.MustCompile(`(?m)^\s*region\s*=\s*"([a-z]{2}-[a-z]+-\d)"`)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if m := re.FindSubmatch(data); m != nil {
			return string(m[1])
		}
	}
	return ""
}

// planJSON plans to a binary file, then reads it as STRUCTURED JSON so drift is
// detected exactly (no text parsing). Returns the drifted resources, the plan
// exit code (0 = no changes, 2 = changes), and any error.
func planJSON(ctx context.Context, bin, dir string) ([]driftedRes, int, error) {
	tmp, err := os.CreateTemp("", "tfforge-plan-*.bin")
	if err != nil {
		return nil, 1, err
	}
	planFile := tmp.Name()
	tmp.Close()
	defer os.Remove(planFile)

	// Plan to the file. -detailed-exitcode: 0 = no changes, 1 = error, 2 = drift.
	planCmd := exec.CommandContext(ctx, bin, "-chdir="+dir, "plan",
		"-input=false", "-no-color", "-detailed-exitcode", "-out="+planFile)
	planErrOut, planErr := planCmd.CombinedOutput()
	code := 0
	if ee, ok := planErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if planErr != nil {
		code = 1
	}
	if code == 1 {
		return nil, 1, fmt.Errorf("tofu plan failed:\n%s", string(planErrOut))
	}
	if code == 0 {
		return nil, 0, nil // in sync — nothing to read
	}

	// Convert the binary plan to JSON and parse the structured changes.
	jsonOut, err := runTF(ctx, bin, dir, "show", "-json", planFile)
	if err != nil {
		return nil, 2, fmt.Errorf("tofu show -json failed: %w", err)
	}
	return parsePlanJSON(jsonOut), 2, nil
}
