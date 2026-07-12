# PAJIN

PAJIN is a policy-governed multi-agent AI red-team and security validation platform.

The current implementation is a policy-governed, worker-backed vertical slice. It validates a
campaign manifest, dynamically creates a bounded Supervisor/Planner/Specialist/Validator/Reporter
team, evaluates every tool request through the Tool Gateway, executes registered mock, HTTP, or MCP
tools in an isolated Docker Worker, independently validates the result, and writes audit evidence
plus a Markdown report.

## Current safety boundary

- Network access is denied by default and cannot be granted by a Tool Adapter.
- A network-enabled tool receives a campaign-derived egress policy only from the Tool Gateway.
- Each network execution gets a private internal Docker network and a dedicated allowlist proxy.
- Public destinations are the default; loopback, link-local, private, reserved, multicast, and
  unspecified addresses are rejected unless the rules of engagement explicitly allow private IPs.
- MCP process commands are kept in the Worker catalog. Agents can submit only registered server
  IDs, tool names, and typed arguments.
- Planner-provided agent identities are ignored; the Supervisor binds each request to the assigned
  Specialist and issues an attenuated, task-specific Capability Grant.
- A child tool call consumes both its grant and every ancestor grant, preventing sibling agents from
  multiplying the campaign call budget.
- Agent count, spawn depth, tool calls, elapsed time, cost, low-risk retries, and cancellation are
  controlled by the PAJIN runtime rather than model instructions.
- Explicit deny scope takes precedence over allow scope.
- Authorization, capability, risk tier, method, and call budgets are checked before execution.
- Unregistered tools are rejected before Worker dispatch.
- Docker images are allowlisted and are never pulled implicitly during a campaign.
- A result cannot be reported as confirmed unless the validator marks it as validated.

## Development setup

Python 3.12 or newer is required.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

If `uv` is available:

```powershell
uv sync --extra dev
```

## Run the vertical slice

```powershell
.venv\Scripts\pajin validate examples\ai-redteam.yaml
.venv\Scripts\pajin run examples\ai-redteam.yaml --worker simulated
```

The simulated backend exists only for deterministic development and unit tests. It is not an
isolation boundary.

## KISA AI Red Team Mode Pack

Run the KISA-aligned indirect prompt-injection and unauthorized tool-use scenario with two
independent repetitions:

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker simulated --repetitions 2
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker docker --repetitions 2
```

The Mode Pack maps the 19 threat classes in the KISA AI Security Red Teaming Guide to a typed
catalog, selects target-compatible scenarios, executes each scenario through separate Specialist
agents, and deduplicates only independently validated findings. Requested threats without an
executable target-linked scenario are retained as explicit coverage gaps.

In addition to the standard run artifacts, `kisa-run` writes:

```text
kisa-results.json
kisa-checklist.json
kisa-test-plan.json
kisa-completion-report.json
kisa-execution-log.json
kisa-report.md
```

Checklist values distinguish `yes`, `no`, `not-applicable`, and `needs-review`. Legal, ethical,
personnel, business-impact, remediation, and lifecycle-governance questions are not inferred from
technical execution evidence. The generated report supports an assessment; it is not a compliance
certification.

## Dynamic multi-agent engine

Run the deterministic five-role team through the simulated or Docker Worker:

```powershell
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker simulated
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker docker
```

The Supervisor creates one Specialist per planned step, while Planner, Validator, and Reporter have
zero tool-call authority. Tasks form an explicit dependency graph. T0/T1 failures may retry once
within the same grant; higher-risk tools are never retried automatically. The independent Validator
can confirm a finding only when its target is declared and every cited artifact was produced by a
Specialist in the same run.

Verify live Kill Switch propagation into a running Worker:

```powershell
.venv\Scripts\pajin multi-cancel-check --worker docker
```

For operator-driven runs, `multi-run` also accepts `--kill-file <path>`. Creating that file activates
the one-way Kill Switch, cancels the active operation, marks pending graph tasks as cancelled,
revokes the complete Capability lineage, and records the reason. Docker cancellation forcibly
removes the running container and any per-execution egress resources.

## Docker Worker

Prepare the MCP SDK bundle using the platform trust store and the hash-locked Linux resolution,
then build both development images:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/prepare-worker-dependencies.ps1
docker build --tag pajin-worker:dev containers/worker
docker build --tag pajin-egress-proxy:dev containers/egress-proxy
```

`containers/worker/requirements.lock` pins the MCP v1 SDK and every transitive dependency with
distribution hashes. The generated `containers/worker/vendor/` directory is intentionally ignored
by Git and must exist before building the Worker image.

Verify the effective isolation controls from inside the container:

```powershell
.venv\Scripts\pajin worker-check
```

Run the campaign through the Docker Worker:

```powershell
.venv\Scripts\pajin run examples\ai-redteam.yaml --worker docker
```

The Docker backend applies the following fixed profile:

- image allowlist and `--pull never`
- network namespace set to `none` unless the Tool Gateway injects an egress policy
- read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges`
- non-root UID/GID `65532`
- bounded writable tmpfs workspace
- CPU, memory, PID, execution-time, stdout, and stderr limits
- forced container cleanup after timeout

## Egress proxy

Run a real public HTTP example and verify allowed traffic, denied traffic, and direct-socket bypass
blocking:

```powershell
.venv\Scripts\pajin run examples\egress-proxy.yaml --worker docker
.venv\Scripts\pajin egress-check
```

The Worker is attached only to a per-execution `--internal` network. The dedicated proxy is attached
to that network and the external Docker bridge, validates the destination again after DNS
resolution, and records allow/deny decisions in the execution evidence. HTTP paths and methods are
enforced directly. HTTPS uses CONNECT, so only host-wide allow rules are accepted; any deny rule for
that HTTPS authority rejects the entire tunnel.

## Registered MCP tools

The demo uses the official MCP Python SDK over stdio entirely inside the isolated Worker:

```powershell
.venv\Scripts\pajin run examples\mcp-tool.yaml --worker simulated
.venv\Scripts\pajin run examples\mcp-tool.yaml --worker docker
.venv\Scripts\pajin mcp-check
```

The bridge initializes the MCP session, verifies the server-advertised tool list, and invokes only a
tool present in the Worker's fixed catalog. Neither an agent nor the host-side adapter can supply an
executable path or arbitrary process arguments. `mcp-check` also proves that unknown server and tool
IDs fail closed in the real Worker.

Worker job standard input is represented in audit metadata by byte length and SHA-256 digest. Raw
Worker stdout, stderr, and egress decision logs are retained in the protected evidence artifact for
reproduction. Query values are redacted from proxy logs.

Run artifacts are written under `.pajin/runs/<campaign>/<run-id>/`:

```text
campaign.json
run.json
events.jsonl
plan.json
findings.json
report.md
evidence/
agents.json
task-graph.json
capabilities.json
budget.json
control.json
```

## Test and lint

```powershell
.venv\Scripts\python -m pytest
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

## Architecture rule

PydanticAI is an adapter for model-backed planning and validation. It does not own campaign state
or execute privileged tools directly. Every MCP, CLI, browser, and sandbox call must pass through
the PAJIN Tool Gateway and Policy Engine.

See [the product plan](docs/PAJIN_PRODUCT_PLAN.md),
[the KISA traceability matrix](docs/KISA_TRACEABILITY.md),
[ADR-0001](docs/adr/0001-agent-runtime-and-orchestration.md), and
[ADR-0002](docs/adr/0002-tool-gateway-and-worker-isolation.md), and
[ADR-0003](docs/adr/0003-egress-proxy-and-mcp-boundary.md), and
[ADR-0004](docs/adr/0004-dynamic-multi-agent-execution.md), and
[ADR-0005](docs/adr/0005-kisa-ai-red-team-mode-pack.md).
