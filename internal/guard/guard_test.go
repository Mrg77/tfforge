package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Mrg77/tfforge/internal/agent"
	"github.com/Mrg77/tfforge/internal/tools"
)

// stubTool is a minimal tool with a chosen name + danger, so we can drive the
// guard without running terraform.
type stubTool struct {
	name   string
	danger tools.Danger
}

func (s stubTool) Name() string                                         { return s.name }
func (s stubTool) Description() string                                  { return "" }
func (s stubTool) Schema() map[string]any                               { return nil }
func (s stubTool) Danger() tools.Danger                                 { return s.danger }
func (s stubTool) Run(context.Context, json.RawMessage) (string, error) { return "", nil }

func input(dir string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"dir": dir})
	return b
}

// alwaysConfirm / neverConfirm are approver stubs.
func alwaysConfirm(_, _, _ string) bool { return true }
func neverConfirm(_, _, _ string) bool  { return false }

// TestDestroyOnProdIsDenied — THE headline behavior: the agent cannot destroy
// production. No approver can override a DENY.
func TestDestroyOnProdIsDenied(t *testing.T) {
	g := New(Default(), alwaysConfirm) // even a yes-man approver can't override deny
	destroy := stubTool{name: "terraform_destroy", danger: tools.Destructive}

	d, reason := g.Check(destroy, input("envs/prod"))
	if d != agent.Deny {
		t.Fatalf("destroy on prod must be DENIED, got %v (%s)", d, reason)
	}
}

// TestApplyOnProdNeedsApproval — apply on prod is confirm: approved → allow,
// refused → deny (fail-safe).
func TestApplyOnProdNeedsApproval(t *testing.T) {
	apply := stubTool{name: "terraform_apply", danger: tools.Mutating}

	if d, _ := New(Default(), alwaysConfirm).Check(apply, input("prod")); d != agent.Allow {
		t.Errorf("apply on prod with approval should ALLOW, got %v", d)
	}
	if d, _ := New(Default(), neverConfirm).Check(apply, input("prod")); d != agent.Deny {
		t.Errorf("apply on prod without approval should DENY (fail-safe), got %v", d)
	}
}

// TestConfirmWithNoApproverFailsSafe — a confirm decision with a nil approver
// must deny, never silently proceed.
func TestConfirmWithNoApproverFailsSafe(t *testing.T) {
	destroy := stubTool{name: "terraform_destroy", danger: tools.Destructive}
	// destroy on non-prod is "confirm"; nil approver → deny.
	if d, _ := New(Default(), nil).Check(destroy, input("dev")); d != agent.Deny {
		t.Errorf("confirm with no approver must fail safe (deny), got %v", d)
	}
}

// TestReadOnlyAlwaysAllowed — plan/analyze bypass the policy entirely, even a
// misconfigured one, and even in prod.
func TestReadOnlyAlwaysAllowed(t *testing.T) {
	plan := stubTool{name: "terraform_plan", danger: tools.ReadOnly}
	if d, _ := New(Default(), neverConfirm).Check(plan, input("prod")); d != agent.Allow {
		t.Errorf("read-only must always be allowed, got %v", d)
	}
}

// TestApplyOnDevIsAllowed — non-prod apply flows (approved), proving the policy
// isn't just "block everything".
func TestApplyOnDevIsAllowed(t *testing.T) {
	apply := stubTool{name: "terraform_apply", danger: tools.Mutating}
	// apply on dev doesn't match any confirm/deny rule → allow.
	if d, _ := New(Default(), neverConfirm).Check(apply, input("dev")); d != agent.Allow {
		t.Errorf("apply on dev should be allowed by default policy, got %v", d)
	}
}

// TestPolicyEvaluateFirstMatchWins — the engine itself: order matters.
func TestPolicyEvaluateFirstMatchWins(t *testing.T) {
	if d := Default().Evaluate("terraform destroy", "prod"); d.Action != ActionDeny {
		t.Errorf("destroy+prod should hit the deny rule first, got %v", d.Action)
	}
	if d := Default().Evaluate("terraform destroy", "dev"); d.Action != ActionConfirm {
		t.Errorf("destroy+dev should fall to the confirm-any-destroy rule, got %v", d.Action)
	}
	if d := Default().Evaluate("terraform plan", "prod"); d.Action != ActionAllow {
		t.Errorf("plan should match nothing and be allowed, got %v", d.Action)
	}
}

// TestDestroyFailsClosedOnUnknownContext — the critical fix: a destroy on infra
// whose context we can't prove is non-prod (path doesn't say dev/staging, no
// workspace file) must be DENIED, not downgraded to confirm. This is what makes
// "the agent can't destroy prod" hold even when prod isn't literally named "prod".
func TestDestroyFailsClosedOnUnknownContext(t *testing.T) {
	destroy := stubTool{name: "terraform_destroy", danger: tools.Destructive}
	// "infra/live/us-east-1" is real prod but says neither "prod" nor "dev".
	if d, r := New(Default(), alwaysConfirm).Check(destroy, input("infra/live/us-east-1")); d != agent.Deny {
		t.Errorf("destroy on an unknown context must fail closed (deny), got %v (%s)", d, r)
	}
	// A clearly-dev path still flows (confirm), proving it's not "block everything".
	if d, _ := New(Default(), alwaysConfirm).Check(destroy, input("infra/dev/eu")); d != agent.Allow {
		t.Errorf("destroy on a dev context with approval should be allowed, got %v", d)
	}
}

// TestWarnOnDestructiveIsGated — a `warn` rule on a destructive action must not
// be a free pass; it routes through the approver.
func TestWarnOnDestructiveIsGated(t *testing.T) {
	yml := []byte(`
version: 1
rules:
  - name: warn on any destroy
    match: {action: destroy}
    do: warn
`)
	p, err := Parse(yml)
	if err != nil {
		t.Fatal(err)
	}
	destroy := stubTool{name: "terraform_destroy", danger: tools.Destructive}
	// warn + no approver → deny (not a silent run).
	if d, _ := New(p, neverConfirm).Check(destroy, input("dev")); d != agent.Deny {
		t.Errorf("warn on a destructive action without approval must deny, got %v", d)
	}
	if d, _ := New(p, alwaysConfirm).Check(destroy, input("dev")); d != agent.Allow {
		t.Errorf("warn on a destructive action with approval should allow, got %v", d)
	}
}

// TestEmptyPolicyFallsBackToDefault — a blank policy must not disable the guard.
func TestEmptyPolicyFallsBackToDefault(t *testing.T) {
	destroy := stubTool{name: "terraform_destroy", danger: tools.Destructive}
	// Empty policy → New falls back to Default → destroy on prod still denied.
	if d, _ := New(&Policy{Version: 1}, alwaysConfirm).Check(destroy, input("prod")); d != agent.Deny {
		t.Errorf("empty policy must fall back to Default (deny prod destroy), got %v", d)
	}
	if d, _ := New(nil, alwaysConfirm).Check(destroy, input("prod")); d != agent.Deny {
		t.Errorf("nil policy must fall back to Default, got %v", d)
	}
}

// TestParseCustomPolicy — a user-supplied YAML policy loads and evaluates.
func TestParseCustomPolicy(t *testing.T) {
	yml := []byte(`
version: 1
rules:
  - name: block all destroys everywhere
    match:
      action: destroy
    do: deny
    message: no destroys allowed here
`)
	p, err := Parse(yml)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate("terraform destroy", "dev"); d.Action != ActionDeny {
		t.Errorf("custom policy should deny destroy on dev, got %v", d.Action)
	}
}
