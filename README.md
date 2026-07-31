# tfforge

*Read this in [French](README.fr.md).*

**An AI agent that builds, validates, and secures Terraform — with a safety layer it can't bypass.**

tfforge writes Terraform code itself, validates it, scans it for security issues,
and **auto-corrects until it's clean** — while every destructive action passes
through **policy-as-code guards**, so the agent can help without being able to
wreck production. It's built **from scratch on the Anthropic Messages API** (no
agent framework), so the agent loop is fully visible.

> Not another "LLM that writes HCL". The market is full of those. The value here
> is the **safety, reliability, and auditability** layer around an agent — the
> part real teams struggle with when putting agents in production.

## Why this exists

Agentic AI in production is, above all, an **infrastructure and orchestration**
problem: an agent that calls tools, handles errors, respects guardrails, logs
every action, and whose cost you can see. That's DevOps. tfforge is a from-scratch
demonstration of exactly that, on a task a DevOps engineer knows intimately —
Terraform — with the security and LLMOps concerns that make an agent trustworthy.

## How it works

```
  you: "build a private, encrypted S3 bucket with least-privilege IAM,
        scan it, and fix any findings"
        │
   1. GENERATE ──▶ the agent writes the Terraform itself (write_file)
        │
   2. VALIDATE ──▶ terraform_validate (won't scan code that doesn't parse)
        │
   3. SECURE ────▶ security_scan: checkov / trivy / tfsec + provider-aware
        │           checks (wildcard IAM, public S3, missing encryption…)
        │
   4. AUTO-CORRECT ▶ findings? the agent REWRITES the code and scans AGAIN
        │            (the loop that makes it feel alive) — until clean
        │
   5. PLAN ──────▶ terraform_plan, rendered as a readable table
        │
   6. GUARD ─────▶ apply/destroy pass through policy — destroy on prod is BLOCKED
```

## What it does

- **A from-scratch agent loop** — `message + tools → tool_use → guard → run →
  result → loop`, turn-bounded. Written on raw HTTP against the Anthropic
  Messages API, no framework — the ~100 lines that make an agent click. The
  model client is an interface, so the whole loop is unit-tested with a scripted
  fake (no API key, no tokens).
- **It builds infrastructure.** `write_file` lets the agent generate and rewrite
  `.tf` files (confined to the project). Security-by-default is baked into the
  system prompt: private S3 + public-access block + encryption, least-privilege
  IAM (never `Action "*"`), encryption at rest, no hard-coded secrets.
- **It secures what it builds.** `security_scan` uses the best installed scanner
  (**checkov** preferred, then trivy, then tfsec) plus a **provider-aware pass**
  (`internal/tools/analyze.go`) that flags the classics in plain language —
  wildcard IAM, public S3, missing S3/RDS/EBS encryption, hard-coded secrets
  (never printing the value). The agent scans, fixes, and **re-scans until clean**.
- **The guard — the differentiator.** The same policy-as-code idea as
  [opsforge](https://github.com/Mrg77/opsforge)'s shell guards, applied to the
  agent's actions: rules (`action × context → allow/warn/confirm/deny`, first
  match wins). The default policy **denies `destroy` on production and confirms
  `apply` on production** — and it **fails closed**: a destroy on a context it
  can't *prove* is non-prod (it reads the Terraform workspace passively, not just
  the path) is blocked. Read-only actions bypass it; custom YAML policies are
  supported.
- **Readable plans for big repos.** `terraform_plan` parses `terraform show -json`
  into a colored table — `+create / ~update / -destroy / ±replace` counts,
  **destructive changes first**, a ⚠ warning, capped with a by-type rollup for
  the long tail. The agent receives only a **compact digest**, so a 500-change
  plan doesn't blow the context or the token bill. *Deterministic parsing counts;
  the LLM only explains* — the pattern that scales.
- **Audit + cost (the LLMOps layer).** Every turn and every guarded action is
  written to a JSONL **audit log** (`~/.local/state/tfforge/audit.jsonl`) — a
  reviewable trail of what the agent did *and what the guard blocked*. Token
  usage is priced into an estimated **cost**, printed in a run summary. This is
  what teams ask for before letting an agent near real infra.

## Run it

```sh
# 1. An Anthropic API key — billed per token, separate from a Claude subscription.
export ANTHROPIC_API_KEY=...        # https://console.anthropic.com

# 2. Build
go build -o tfforge .

# 3. Build + scan + auto-correct a secure S3 stack (the headline demo)
./tfforge "build a private, encrypted S3 bucket with least-privilege IAM in \
  ./examples/out, scan it for security issues, and fix anything the scan finds"

# 4. Watch the guard block a production destroy
./tfforge "destroy the infrastructure in ./examples/prod"     # → BLOCKED by policy

# 5. Watch the scan + auto-correct fix deliberately-broken code
./tfforge "scan ./examples/insecure and fix every security finding, \
  telling me what was wrong and what you changed"
```

Each run prints a summary: `run summary · N turns · … tokens · M tool call(s)
(K denied) · ~$cost`. Optional scanners: `opsforge install checkov` (or trivy).

## Tests

No API key or network needed — the model client is faked, terraform/policy/plan
logic is exercised directly:

```sh
go test ./...
```

Coverage includes: the agent loop (happy path, **guard-deny blocks the tool**,
loop bound, unknown tool), the guard (**deny prod destroy**, fail-closed on an
unknown context, warn-gated, empty-policy fallback), the provider-aware analyzer,
the plan parser (replace both orders, big-plan truncation), and cost/audit.

## Design notes

- **No framework, on purpose.** The whole value is seeing the loop. `internal/agent`
  is the small core that demystifies how an agent (like Claude Code) works.
- **Danger lives on the tool.** Each tool declares read-only / mutating /
  destructive, so the guard gates by real blast radius, not by re-guessing intent.
- **The guard fails closed.** When it can't prove an action is safe, it refuses —
  the opposite of trusting a path name to contain "prod".
- **Honest limits.** The provider-aware checks complement (don't replace)
  checkov/trivy; the cost figure is an estimate; the guard is a strong safety net,
  not an absolute barrier — pair it with least-privilege cloud credentials
  (defence in depth).

## Configuration

| Env var | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | required — the API key (billed per token) |
| `TFFORGE_MODEL` | override the model (default `claude-sonnet-4-5`) |
| `TFFORGE_AUDIT` | `off` to disable the audit file, or a path to redirect it |
| `NO_COLOR` | disable colored plan output |

---

Part of a DevOps portfolio, alongside
[opsforge](https://github.com/Mrg77/opsforge) (a policy-as-code DevOps
workstation) and [KubeForge](https://github.com/Mrg77/kubeforge) (a local-first
Kubernetes analysis app). MIT · © Mrg77.
