# tfforge

**An AI agent that builds and analyzes Terraform — with a safety layer it can't bypass.**

tfforge reasons over your infrastructure (plan, analyze, and — soon — build),
but every destructive action passes through **policy-as-code guards** and is
**traced**. So the agent can help without being able to wreck production.

> It's not another "LLM that writes HCL". The market is full of those. The point
> here is the **safety and reliability layer** around an agent — the part real
> teams struggle with in production.

## Why this exists

Agentic AI in production is, above all, an infrastructure and orchestration
problem: an agent that calls tools, handles errors, respects guardrails, and
logs every action it takes. tfforge is a from-scratch demonstration of exactly
that, on a DevOps task an engineer knows intimately: Terraform.

Built **from scratch on the Anthropic Messages API** (no agent framework) so the
loop is fully visible — the same loop that powers tools like Claude Code.

## How it works

```
  user task ─▶ [ model ] ─▶ text? ──▶ done
                   │
                   └─▶ tool_use ─▶ [ GUARD ] ─▶ allow ─▶ run tool ─▶ result ─┐
                                       │                                      │
                                       └─▶ deny ─▶ "blocked, here's why" ─────┤
                                                                              │
                       ◀────────────────── loop with the result ─────────────┘
```

The **GUARD** step is the differentiator: a read-only tool (`terraform_plan`)
runs freely, but a destructive one (`terraform destroy`) is checked against
policy — and denied on a production context — before it can touch anything.
Every decision is recorded for audit.

## Status

Early, but real and tested end-to-end.

- [x] From-scratch Anthropic Messages API client (raw HTTP, tool use)
- [x] The agentic loop (message → tool_use → guard → run → result → loop), with
      a turn bound so it can't loop forever
- [x] Tool contract with a `Danger` level (read-only / mutating / destructive)
- [x] First tool: `terraform_plan` (read-only) + a credential-free example
      (`local`/`random` providers — demoable with no cloud account)
- [x] Pluggable guard + tracer, unit-tested (allow / **deny blocks the tool** /
      loop-bound / unknown-tool) — no API key or tokens needed to run the tests
- [ ] Real policy-as-code guard (reuse the opsforge guard engine)
- [ ] Security scanning as agent tools (tfsec / checkov)
- [ ] Guarded `apply` / `destroy`
- [ ] Infra build (generate + plan from a request)
- [ ] Audit trail + token/cost reporting

## Run it

```sh
# 1. An Anthropic API key (billed per token — separate from a Claude subscription)
export ANTHROPIC_API_KEY=...        # from https://console.anthropic.com

# 2. Build
go build -o tfforge .

# 3. Ask the agent to analyze the example
cd examples/staging && terraform init && cd -
./tfforge "run the plan in ./examples/staging and explain what would change"
```

The tests need neither a key nor network:

```sh
go test ./...
```

## Design notes

- **No framework, on purpose.** The whole value is seeing the loop. `internal/agent`
  is the ~100 lines that make an agent click.
- **Danger lives on the tool.** Each tool declares whether it's read-only,
  mutating, or destructive — so the guard gates by real blast radius, not by
  re-guessing intent.
- **The client is an interface.** Tests swap in a scripted fake LLM, so the loop
  (including the guard-deny path) is verified deterministically, for free.

---

Part of a DevOps portfolio (alongside [opsforge](https://github.com/Mrg77/opsforge)
and [KubeForge](https://github.com/Mrg77/kubeforge)). © Mrg77 · MIT.
