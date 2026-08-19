# PAJIN

PAJIN is a policy-governed multi-agent security validation and red-team platform. It is designed to
keep attack execution inside explicit Scope, Capability, approval, budget, and evidence boundaries
while preserving enough lineage to independently replay and verify security findings.

The project is currently in **Phase 11 — LLM Pentest Productization**. The core policy, evidence,
replay, validation, and Pentest Profile foundations are implemented. Productized pentest execution
is still intentionally narrow: approved, deployment-pinned read-only Recon and independently
authorized Replay are available, while broader LLM/Web/RAG/MCP attack coverage is a follow-up
milestone.

> PAJIN is not yet a general public-target autonomous pentesting engine. Current executable pentest
> coverage is deliberately bounded while the end-to-end authority and evidence workflow is being
> completed.

## What PAJIN is building

PAJIN separates **discovery**, **authorization**, **execution**, and **validation** instead of treating
an agent decision as execution authority.

```text
Operator / Supervisor
        |
        v
Campaign + Profile + Scope
        |
        v
Canonical Graph + Planning
        |
        v
Capability + Approval + ActionPermit
        |
        v
Gateway + Isolated Worker
        |
        v
Evidence + Independent Replay
        |
        v
Validation + Finding + Report
```

The intended result is an attack workflow where discovering a target or hypothesis never
implicitly expands Scope, and a positive Worker result never becomes a confirmed Finding without
independent evidence and replay gates.

## Core security model

PAJIN is built around a few non-negotiable boundaries:

- **Scope is authority.** Discovered hosts, routes, tools, or hypotheses are not automatically
  authorized targets.
- **Capabilities are explicit and versioned.** Execution is tied to registered code-backed
  Capability authority rather than free-form agent intent.
- **Permits are single-use and bounded.** Risk, time, request, cost, and rate ceilings are checked
  before dispatch.
- **Network access is denied by default.** Network-enabled actions receive campaign-derived egress
  policy through the Gateway.
- **Workers are isolated execution boundaries.** The Control Plane can bind Worker identity to
  direct mTLS evidence.
- **Evidence is first-class.** Runs, receipts, artifacts, and decisions are sealed and re-opened by
  downstream validators.
- **Replay is independent.** A finding cannot be promoted merely because the original execution
  reported success.
- **Fail closed is preferred.** Missing, stale, substituted, ambiguous, or unverifiable authority
  stops execution or confirmation instead of being inferred.

## Current implementation status

| Area | Status |
| --- | --- |
| Policy, Scope, budgets, Capability enforcement | Implemented |
| Canonical Graph, approvals, single-use permits | Implemented |
| Evidence sealing, replay, validation gates | Implemented |
| `pentest`, `bug-hunt`, `ctf`, `ai-assessment` Profiles | Registered |
| Pentest signed authorization and Profile-native compilation | Implemented |
| Approved one-shot read-only HTTP GET Recon | Implemented |
| Dedicated independently authorized Pentest Replay Worker | Implemented |
| Controlled validity evidence and validity-only Finding projection | Implemented |
| Durable five-stage Pentest coordination | In progress |
| Concrete coordination child deployment adapters | In progress (`PENTEST-004C2B2`) |
| General LLM/Web/RAG/MCP pentest attack coverage | Planned (`REDTEAM-001`) |
| Detection / false-positive / replay / cost benchmark | Planned (`REDTEAM-002`) |
| Product Scope → Evidence → Finding → report flow | Planned (`UX-008`) |
| Production distributed Workers / cross-host fencing / KMS-HSM | Not complete |

For the authoritative roadmap and exact completion state, use [`PLAN.md`](PLAN.md), not this table.

## Supported modes and surfaces

PAJIN currently includes several development and validation paths:

- **Pentest** — signed assessment compilation, approved one-shot Recon, independent Replay,
  controlled validity evidence, and resumable local validity reporting.
- **AI Red Team** — KISA-aligned threat catalog and selected executable scenarios with replay and
  validation controls.
- **Bug Bounty** — program-policy review, canonical scope compilation, duplicate triage, local report
  drafts, and a fixed Boolean-SQLi lab.
- **CTF** — bounded local Web and Crypto challenge flows.
- **Discovery / Graph** — HTTP/OpenAPI, RAG, and registered MCP surface discovery with
  `registered-not-authorized` semantics.
- **Benchmark / research infrastructure** — deterministic targets, scanner baselines, local
  model-backed agent measurements, and sealed comparison artifacts.

These paths do not imply unrestricted or generic public-target attack automation.

## Development setup

Python 3.12 is the contributor and CI baseline. The checked-in `uv.lock` is the canonical dependency
lock.

```powershell
uv sync --locked --extra dev --extra control-plane
```

For environments without `uv`, an editable pip install is supported as a bootstrap path:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev,control-plane]"
```

The Docker Worker has a separate dependency boundary under `containers/worker/`.

## Quick checks

Validate an example campaign:

```powershell
.venv\Scripts\pajin validate examples/ai-redteam.yaml
```

Inspect the CLI surface:

```powershell
.venv\Scripts\pajin --help
```

Common command groups include:

| Group | Commands |
| --- | --- |
| Core | `validate`, `run`, `multi-run`, `multi-cancel-check` |
| Provider / agent loop | `provider-check`, `provider-agent-run`, `tool-loop-run` |
| KISA AI Red Team | `kisa-run`, `kisa-plan-remediation`, `kisa-retest` |
| Campaign Builder | `campaign-draft-create`, `campaign-draft-inspect` |
| Bug Bounty | `bug-bounty-review`, `bug-bounty-compile`, `bug-bounty-report`, `bug-bounty-run` |
| CTF | `ctf-run`, `ctf-web-run`, `ctf-suite-run` |
| Evidence / infrastructure | `evidence-verify`, `replay-verify`, `sarif-export`, `worker-check`, `egress-check`, `mcp-check` |
| Pentest | `pentest-compile`, `pentest-recon-dispatch`, `pentest-replay-dispatch`, `pentest-workflow-run` |

Run `pajin <command> --help` for the authoritative options.

Optional server processes are installed as:

- `pajin-control-plane`
- `pajin-worker-daemon`
- `pajin-replay-worker-daemon`

## Quality checks

The repository CI runs the locked Linux/Python 3.12 environment with linting, strict type checks,
and pytest.

```powershell
uv run --locked ruff check src tests containers
uv run --locked mypy src
uv run --locked pytest
```

Some platform-specific durability and live TLS/provider tests require Linux/WSL or explicitly
provisioned local infrastructure. See [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) for reproduced limits.

## Architecture and documentation

README is intentionally an overview. Detailed implementation state, contracts, and design rationale
live in their own authority documents:

- [`PLAN.md`](PLAN.md) — implementation roadmap and current priority
- [`HANDOFF.md`](HANDOFF.md) — verified development checkpoint and validation evidence
- [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) — reproduced unresolved constraints
- [`docs/README.md`](docs/README.md) — documentation index
- [`docs/rfc/0001-pajin-architecture-v2.md`](docs/rfc/0001-pajin-architecture-v2.md) — Architecture v2
- [`docs/orchestration/`](docs/orchestration/) — versioned execution and workflow contracts
- [`docs/adr/`](docs/adr/) — architecture decision records
- [`docs/DOCUMENTATION_POLICY.md`](docs/DOCUMENTATION_POLICY.md) — documentation authority policy

When implementation detail conflicts with a status summary in this README, prefer the versioned
contract, `PLAN.md`, and the current `HANDOFF.md`.

## Current roadmap

The active productization sequence is:

```text
PENTEST-004C2B2
  concrete Recon / Replay child deployment adapters
        |
        v
REDTEAM-001
  executable LLM / Web / RAG / MCP coverage
        |
        v
REDTEAM-002
  detection / false-positive / replay / cost benchmark
        |
        v
UX-008
  Scope / Evidence / Finding / report product flow
```

See [`PLAN.md`](PLAN.md) for the authoritative milestone definitions and exit gates.

## Responsible use

PAJIN is intended for authorized security testing, controlled research, and defensive validation.
Use it only against systems and environments for which you have explicit authorization. The
platform's Scope and approval controls are safety mechanisms, not substitutes for legal authority or
rules of engagement.
