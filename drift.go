package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	planOut, code := planExitCode(ctx, bin, dir)
	rep.PlanOutput = planOut
	switch code {
	case 0:
		rep.Drift = driftNone
	case 2:
		rep.Drift = driftFound
		rep.DriftedResources = parseChangedResources(planOut)
	default:
		rep.Drift = driftError
		rep.Err = "tofu plan failed — see output"
	}

	// --- 2. Unmanaged resources: cloud vs state ------------------------------
	if !*skipUnmanaged && rep.Drift != driftError {
		stateIDs := managedCloudIDs(ctx, bin, dir)
		rep.Unmanaged = findUnmanaged(ctx, stateIDs)
	}

	// --- Render --------------------------------------------------------------
	if *asMarkdown {
		fmt.Println(rep.markdown())
	} else {
		fmt.Println(rep.text())
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

// planExitCode runs `tofu plan -detailed-exitcode` and returns (output, code):
// 0 = no changes, 1 = error, 2 = changes (drift).
func planExitCode(ctx context.Context, bin, dir string) (string, int) {
	full := []string{"-chdir=" + dir, "plan", "-input=false", "-no-color", "-detailed-exitcode"}
	cmd := exec.CommandContext(ctx, bin, full...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = 1
	}
	return string(out), code
}
