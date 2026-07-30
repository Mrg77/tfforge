package agent

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Mrg77/tfforge/internal/anthropic"
	"github.com/Mrg77/tfforge/internal/tools"
)

// fakeLLM plays back a scripted sequence of responses, so the agent loop can be
// tested deterministically without an API key or tokens. Each call pops the
// next response.
type fakeLLM struct {
	responses []*anthropic.Response
	calls     int
}

func (f *fakeLLM) CreateMessage(_ context.Context, _ string, _ []anthropic.Message, _ []anthropic.Tool) (*anthropic.Response, error) {
	r := f.responses[f.calls]
	f.calls++
	return r, nil
}

// fakeTool records whether it ran, and returns a canned result.
type fakeTool struct {
	name   string
	danger tools.Danger
	ran    bool
	result string
}

func (t *fakeTool) Name() string           { return t.name }
func (t *fakeTool) Description() string    { return "fake" }
func (t *fakeTool) Schema() map[string]any { return map[string]any{"type": "object"} }
func (t *fakeTool) Danger() tools.Danger   { return t.danger }
func (t *fakeTool) Run(context.Context, json.RawMessage) (string, error) {
	t.ran = true
	return t.result, nil
}

// recordingTracer captures decisions for assertions.
type recordingTracer struct{ decisions []string }

func (r *recordingTracer) ToolCall(_ string, _ tools.Danger, decision, _ string) {
	r.decisions = append(r.decisions, decision)
}

// staticGuard returns a fixed decision — lets us test allow vs deny paths.
type staticGuard struct {
	decision Decision
	reason   string
}

func (g staticGuard) Check(tools.Tool, json.RawMessage) (Decision, string) {
	return g.decision, g.reason
}

func toolUse(id, name string) anthropic.ContentBlock {
	return anthropic.ContentBlock{Type: "tool_use", ID: id, Name: name, Input: json.RawMessage(`{}`)}
}

// TestLoopRunsToolThenFinishes: model asks for a tool, we run it, model then
// returns text and stops. The canonical happy path.
func TestLoopRunsToolThenFinishes(t *testing.T) {
	ft := &fakeTool{name: "terraform_plan", danger: tools.ReadOnly, result: "Plan: 2 to add"}
	llm := &fakeLLM{responses: []*anthropic.Response{
		{StopReason: "tool_use", Content: []anthropic.ContentBlock{toolUse("t1", "terraform_plan")}},
		{StopReason: "end_turn", Content: []anthropic.ContentBlock{{Type: "text", Text: "Two resources would be created."}}},
	}}
	var out strings.Builder
	ag := New(llm, "sys", []tools.Tool{ft}, staticGuard{Allow, "ok"}, &recordingTracer{}, &out)

	if err := ag.Run(context.Background(), "analyze", 5); err != nil {
		t.Fatal(err)
	}
	if !ft.ran {
		t.Error("tool should have run when guard allows")
	}
	if !strings.Contains(out.String(), "Two resources would be created.") {
		t.Errorf("final text not emitted; got %q", out.String())
	}
	if llm.calls != 2 {
		t.Errorf("expected 2 model calls, got %d", llm.calls)
	}
}

// TestGuardDenyBlocksTool: guard denies, the tool must NOT run, and the model
// receives a BLOCKED result. This is the differentiator, tested.
func TestGuardDenyBlocksTool(t *testing.T) {
	ft := &fakeTool{name: "terraform_destroy", danger: tools.Destructive, result: "destroyed"}
	llm := &fakeLLM{responses: []*anthropic.Response{
		{StopReason: "tool_use", Content: []anthropic.ContentBlock{toolUse("t1", "terraform_destroy")}},
		{StopReason: "end_turn", Content: []anthropic.ContentBlock{{Type: "text", Text: "Understood, I won't destroy prod."}}},
	}}
	tr := &recordingTracer{}
	var out strings.Builder
	ag := New(llm, "sys", []tools.Tool{ft}, staticGuard{Deny, "destroy on prod context"}, tr, &out)

	if err := ag.Run(context.Background(), "destroy everything", 5); err != nil {
		t.Fatal(err)
	}
	if ft.ran {
		t.Error("destructive tool ran despite guard DENY — this is the exact bug the guard must prevent")
	}
	if len(tr.decisions) != 1 || tr.decisions[0] != "deny" {
		t.Errorf("expected a single 'deny' trace, got %v", tr.decisions)
	}
}

// TestMaxTurnsStopsLoop: a model that keeps asking for tools forever must be
// bounded, not loop infinitely (a real agent reliability concern).
func TestMaxTurnsStopsLoop(t *testing.T) {
	ft := &fakeTool{name: "terraform_plan", danger: tools.ReadOnly, result: "again"}
	loopResp := &anthropic.Response{StopReason: "tool_use", Content: []anthropic.ContentBlock{toolUse("t1", "terraform_plan")}}
	llm := &fakeLLM{responses: []*anthropic.Response{loopResp, loopResp, loopResp, loopResp, loopResp}}
	ag := New(llm, "sys", []tools.Tool{ft}, staticGuard{Allow, "ok"}, &recordingTracer{}, io.Discard)

	err := ag.Run(context.Background(), "loop forever", 3)
	if err == nil || !strings.Contains(err.Error(), "possible loop") {
		t.Errorf("expected a loop-bound error after maxTurns, got %v", err)
	}
}

// TestUnknownToolReturnsError: model asks for a tool we don't have → error
// result, not a crash.
func TestUnknownToolReturnsError(t *testing.T) {
	llm := &fakeLLM{responses: []*anthropic.Response{
		{StopReason: "tool_use", Content: []anthropic.ContentBlock{toolUse("t1", "rm_rf_slash")}},
		{StopReason: "end_turn", Content: []anthropic.ContentBlock{{Type: "text", Text: "no such tool"}}},
	}}
	ag := New(llm, "sys", []tools.Tool{}, staticGuard{Allow, "ok"}, &recordingTracer{}, io.Discard)
	if err := ag.Run(context.Background(), "x", 5); err != nil {
		t.Fatal(err)
	}
}
