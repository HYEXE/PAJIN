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
  unspecified addresses are rejected. The Bug Bounty private-network exception is limited to the
  fixed `local-lab` profile and `host.docker.internal` entry points.
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
- Optional tool-category allowlists, recurring IANA-timezone testing windows, and per-campaign
  request rates are enforced by the Policy Engine and Tool Gateway.
- Unregistered tools are rejected before Worker dispatch.
- Provider endpoints, model IDs, function-tool allowlists, and credential references are fixed by
  trusted registration; an Agent cannot override them in a chat request.
- Provider credentials are materialized through audience-bound, single-use Secret Leases and enter
  the Worker only through its stdin envelope, never Docker arguments, environment variables, Job
  metadata, events, or evidence.
- Docker images are allowlisted and are never pulled implicitly during a campaign.
- A result cannot be reported as confirmed unless the validator marks it as validated.
- Audit Events form a sequence-checked SHA-256 chain, and completed Run artifacts are captured in
  append-only integrity seals. Mode Pack outputs extend the previous root instead of overwriting it.

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

## Bug Bounty Scope Parser

Bug Bounty execution starts from a typed program-policy snapshot, not an agent's interpretation of
free-form scope. The first command normalizes the source policy and emits `program.normalized.json`,
`scope-review.json`, and an operator-facing `scope-review.md`:

```powershell
.venv\Scripts\pajin bug-bounty-review examples\bug-bounty-program.yaml
```

The review prints a SHA-256 scope digest over canonical policy JSON, including the original policy
text. After comparing the review with the authoritative program page, compile only that exact digest:

```powershell
.venv\Scripts\pajin bug-bounty-compile examples\bug-bounty-program.yaml `
  --scope-digest <digest-from-review> `
  --approved-by <program-owner> `
  --approved-at 2026-07-13T10:00:00+09:00 `
  --expires-at 2026-07-20T10:00:00+09:00 `
  --evidence <authorization-ticket>
.venv\Scripts\pajin validate .pajin\campaigns\example-bug-bounty-lab.yaml
```

Any change to the raw policy, assets, methods, tool categories, limits, or time windows invalidates
the digest. The compiler caps this MVP at T2, injects mandatory prohibitions for denial of service,
social engineering, persistence, credential stuffing, real-user-data access, and exfiltration, and
requires concrete entry points that match an allow rule without matching a deny rule. The runtime
then enforces allow/deny scope, method and category allowlists, weekly test windows, and a sliding
one-minute request limit before Worker dispatch.

Evidence retention remains an explicit manual control. Duplicate triage can consume a typed local
snapshot, but synchronizing that snapshot with a platform or issue tracker remains manual.

### Finding triage and submission drafts

After a completed Bug Bounty Campaign has independently validated findings, compare them with an
optional program-specific known-finding index and generate submission drafts:

```powershell
.venv\Scripts\pajin bug-bounty-report `
  examples\bug-bounty-program.yaml `
  <completed-run-directory> `
  --known-findings examples\bug-bounty-known-findings.yaml
```

The reporter rechecks that the Run used the current program digest and exact compiled scope policy,
accepts only declared targets, and requires every cited evidence file to resolve inside that Run's
`evidence/` directory. It writes an immutable-input report set under:

```text
bug-bounty-reports/<triage-id>/
  bug-bounty-triage.json
  bug-bounty-report.md
  submissions/<finding-id>.md
```

Exact fingerprints use the program, normalized target path and query-parameter names,
vulnerability class, affected component, and normalized root cause. Only exact matches against an
unresolved known Finding or the same Run are automatically suppressed. A resolved known Finding or
the same cause on a different endpoint becomes `needs-review`, preserving possible regressions and
multi-endpoint impact. Missing impact, remediation, component, or root-cause data produces a draft
with explicit TODOs instead of an automatic submission.

The generated Markdown is a local draft only. PAJIN does not submit to a Bug Bounty platform or
claim that the unsigned local evidence has production-grade artifact integrity.

### Automated local Bug Bounty lab

The executable Bug Bounty slice is intentionally narrower than the general scope parser. It runs
only the compiled `boolean-sqli-lab` profile against the synthetic loopback-bound target. The
Planner can select only `bug-bounty.boolean-sqli-probe`; the Tool accepts no agent-authored attack
payload and the trusted Worker performs exactly one baseline, one negative control, and one boolean
comparison. The Validator ignores the Worker's claimed conclusion and recomputes the signal from
the three bounded observations. One Tool call reserves three request-rate units.

Build the Worker and egress proxy, then start the vulnerable lab:

```powershell
docker build --tag pajin-worker:dev containers\worker
docker build --tag pajin-egress-proxy:dev containers\egress-proxy
docker compose -f containers\compose.bug-bounty-lab.yaml up --build --detach

.venv\Scripts\pajin bug-bounty-review `
  examples\bug-bounty-lab-program.yaml `
  --output .pajin\bug-bounty-lab-review
```

Inspect the generated review and copy its printed digest into the approval command:

```powershell
.venv\Scripts\pajin bug-bounty-compile `
  examples\bug-bounty-lab-program.yaml `
  --scope-digest <reviewed-digest> `
  --approved-by <local-lab-owner> `
  --approved-at <offset-aware-approval-time> `
  --expires-at <offset-aware-expiry-time> `
  --evidence <local-authorization-record> `
  --output .pajin\campaigns

.venv\Scripts\pajin bug-bounty-run `
  examples\bug-bounty-lab-program.yaml `
  .pajin\campaigns\local-bug-bounty-sqli-lab.yaml
```

The vulnerable profile should produce one independently validated draft. Recreate the target with
the hardened override and run the same digest-approved Campaign again; the fixed probe should then
produce zero findings:

```powershell
docker compose `
  -f containers\compose.bug-bounty-lab.yaml `
  -f containers\compose.bug-bounty-lab.hardened.yaml `
  up --build --detach --force-recreate

.venv\Scripts\pajin bug-bounty-run `
  examples\bug-bounty-lab-program.yaml `
  .pajin\campaigns\local-bug-bounty-sqli-lab.yaml

docker compose -f containers\compose.bug-bounty-lab.yaml down
```

`bug-bounty-run` always uses the Docker Worker, creates local evidence and triage drafts, and never
submits a report externally. Generic public Bug Bounty assets remain reviewable and compilable, but
are not executable until a separately bounded probe profile is implemented.

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

### Provider-neutral AI Chat/RAG lab

PAJIN defines a fixed, provider-neutral chat contract for authorized AI application targets. The
registered `ai.chat-probe` Tool can send only bounded POST conversations selected from the KISA
scenario catalog; it cannot inject arbitrary process commands or grant itself network access. The
Tool Gateway derives egress from Campaign Scope, and the independent Validator rechecks the raw
transcript instead of trusting the Tool's vulnerability flag.

Build and start the intentionally vulnerable local target, then run the M03, M06, and A04 campaign:

```powershell
docker build --tag pajin-worker:dev containers/worker
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml down
```

The six Specialist Tasks use unique session IDs and cover system-prompt disclosure, jailbreak
policy bypass, and persistent memory poisoning. The lab binds only to `127.0.0.1:8765`, runs as a
non-root user with a read-only filesystem and no Linux capabilities, and is not a production AI
service.

### Remediation and retest loop

Create the remediation plan from a completed vulnerable baseline before applying the change:

```powershell
.venv\Scripts\pajin kisa-plan-remediation <baseline-run-directory>
```

After the owner applies the planned controls, recreate the lab with its hardened profile and run
the same attacks plus two normal-function checks:

```powershell
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml up --detach --force-recreate
.venv\Scripts\pajin kisa-retest <baseline-run-directory> `
  examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml down
```

`kisa-retest` classifies each baseline Finding as `fixed`, `still-vulnerable`, or `inconclusive`,
reports any new Finding, and evaluates normal-function regression separately from attack metrics.
A Finding is `fixed` only when the repeated attack calls succeeded and every result lacked the
original compromise signal. Missing or failed evidence produces `inconclusive`. The command exits
non-zero when a Finding remains, evidence is inconclusive, a new Finding appears, or regression
fails.

The retest run adds `remediation-plan.json`, `kisa-retest.json`,
`kisa-checklist-overlay.json`, and `kisa-retest-report.md`. The overlay supersedes only five
evidence-backed KISA items; owner assignment, due dates, and operational adoption remain human
review items.

## OpenAI-compatible Provider Gateway

PAJIN uses a provider-neutral message and result contract at the Agent boundary. A trusted
`ProviderRegistration` fixes the Chat Completions endpoint, model, credential reference, streaming
permission, and allowed function names. The Worker translates that contract to an OpenAI-compatible
`POST /chat/completions` request and normalizes either a JSON response or data-only SSE stream.
Function-call argument fragments are assembled and parsed as JSON, but the Provider Gateway never
executes the requested function; a separately registered PAJIN Tool and Capability Grant would be
required for execution.

Run the authenticated local validation target and four-Specialist campaign:

```powershell
docker build --tag pajin-worker:dev containers/worker
docker build --tag pajin-egress-proxy:dev containers/egress-proxy
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1' # public local fixture only
.venv\Scripts\pajin provider-check examples\provider-openai-compatible-lab.yaml --worker docker
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

`provider-check` validates authentication, non-streaming text, SSE text, streamed function calls,
credential redaction, Lease issuance/revocation, and the absence of the raw credential from every
run artifact. For a real provider, place its credential in the selected environment variable only;
do not add it to a Campaign manifest or provider registration file. The current in-memory broker is
a local runtime boundary, not a production secret manager; a deployment should source values from
a platform vault and isolate the supervisor process accordingly.

### Provider-backed Planner, Validator, and Reporter

`provider-agent-run` connects the registered Provider Gateway to the three reasoning roles without
giving them offensive execution authority. Each role receives a distinct developer prompt, a
strict JSON Schema, and an attenuated Capability containing only the exact Provider Tool and
endpoint. Campaign, plan, result, and finding data are supplied as untrusted user content. The
Supervisor validates model-created plans again before Specialist creation and rejects undeclared
targets, Provider control-plane tools, unregistered tools, and unregistered methods.

Run the complete model-driven M03 lab:

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1' # public local fixture only
.venv\Scripts\pajin provider-agent-run examples\provider-agent-lab.yaml `
  --worker docker --allow-private-provider
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

The flow is Provider Planner → isolated `ai.chat-probe` Specialist → Provider Validator → Provider
Reporter. Validator findings are still accepted only when they cite evidence produced by a
Specialist in the same run. Reporter output is stored separately in `model-narrative.json` and is
appended as a clearly subordinate section; it cannot alter canonical findings or execution state.

`maxModelCalls` and `maxModelTokens` bound model usage independently, while actual token usage and
registration-supplied per-million token rates contribute to `maxCostUsd`. Provider failures,
refusals, and schema errors retry at most twice before deterministic fallback. Duration, Capability,
token, and cost exhaustion never activate fallback and terminate the campaign instead.
Private Provider destinations are denied unless `--allow-private-provider` is explicitly supplied.
For billable Providers, configure `--input-cost-per-million` and `--output-cost-per-million` from
the Provider's trusted pricing configuration.

### Policy-governed iterative Tool Loop

`tool-loop-run` exposes strict function definitions to the Provider but treats every returned call
as an untrusted intent. Parallel calls are disabled. The Supervisor maps the function name to one
fixed PAJIN Tool, target, method, and JSON Schema; rejects unknown, invalid, parallel, or duplicate
calls; then creates a new Specialist with a one-call Capability. Only the Specialist result is sent
back as a `tool` message with the original call ID. The Provider may then return a final response or
request another bounded turn.

Run the two-turn local loop:

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1' # public local fixture only
.venv\Scripts\pajin tool-loop-run examples\tool-loop-lab.yaml `
  --worker docker --allow-private-provider
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

Every transition writes a versioned checkpoint containing conversation state, call fingerprints,
pending intent, Tool results, and cumulative budget usage, but no credential. Resumption creates a
linked continuation run and restores Agent, Tool, Model, token, cost, and elapsed-time usage.

T3 and T4 intents never dispatch a Worker without an exact, active approval bound to the call
fingerprint, Tool ID, and target. The local approval check first proves the T3 intent is paused with
zero Tool results, then supplies an explicit approval and resumes from that checkpoint:

```powershell
docker compose -f containers/compose.ai-lab.yaml up --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1'
.venv\Scripts\pajin tool-loop-approval-check examples\tool-loop-approval-lab.yaml `
  --worker docker --allow-private-provider --approved-by local-security-owner
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

`mock.approval-probe` performs only the safe mock operation but is classified T3 specifically to
exercise approval controls. Production approvals must come from an authenticated external control
plane; the lab CLI identity is verification data, not production authentication.

## Durable Control Plane

The optional Control Plane adds authenticated FastAPI endpoints and a PostgreSQL durable Job queue
without replacing the existing file-backed CLI. Run submission is idempotent, Worker claims use
bounded leases and heartbeats, crashed leases are requeued, and every transition appends an audit
event. PostgreSQL rejects update or delete attempts against the event table.

T3/T4 checkpoint creation records the exact call fingerprint, Tool, target, tier, and expiry. The
checkpoint payload is signed with a key kept outside the database. Only an Approver credential can
decide the request; only an Operator can consume an approved decision. Resume verifies the stored
payload and signature before atomically claiming the checkpoint and creating one continuation Job.

Install the optional server dependencies and run locally with SQLite:

```powershell
.venv\Scripts\python -m pip install -e ".[dev,control-plane]"
$env:PAJIN_CP_DATABASE_URL='sqlite:///./.pajin/control-plane.db'
$env:PAJIN_CP_OPERATOR_TOKEN='<distinct-random-operator-token>'
$env:PAJIN_CP_APPROVER_TOKEN='<distinct-random-approver-token>'
$env:PAJIN_CP_WORKER_TOKEN='<distinct-random-worker-token>'
$env:PAJIN_CP_CHECKPOINT_KEY='<random-signing-key-at-least-32-bytes>'
.venv\Scripts\pajin-control-plane
```

SQLite is a local compatibility store, not a production multi-Worker queue. Run the PostgreSQL lab
on loopback instead:

```powershell
docker compose -f containers/compose.control-plane.yaml up --build --detach --wait
$env:PAJIN_TEST_POSTGRES_URL=`
  'postgresql+psycopg://pajin:pajin-control-plane-lab-password@127.0.0.1:55432/pajin_test'
.venv\Scripts\pytest -q tests/test_control_plane_postgres.py
Remove-Item Env:PAJIN_TEST_POSTGRES_URL
docker compose -f containers/compose.control-plane.yaml down --volumes
```

The Compose credentials are public fixtures for an isolated local lab. Production deployment must
use a secret manager, TLS termination, network isolation, distinct role credentials, a separately
held signing key, database backups, and managed schema migrations. See
[`ADR 0011`](docs/adr/0011-durable-control-plane.md) for state and threat-boundary details.

### Lease-aware Worker daemon

`pajin-worker-daemon` turns queued Control Plane Jobs into existing PAJIN engine runs. It keeps one
bounded async HTTP connection pool, claims only configured Job kinds, heartbeats throughout execution
and finalization, retries transient completion calls, and cancels execution if the lease becomes
stale. Authentication rejection is fatal. SIGTERM stops new claims and drains the active Job.

The initial trusted registry contains:

- `campaign`: strict embedded Campaign manifest → deterministic `LocalCampaignRunner`
- `tool-loop`: strict embedded Campaign and prompt → real `PolicyToolLoopRunner`

No Job field can name a command, Python module, class, executable, or arbitrary manifest path.
Unknown kinds and invalid payloads fail closed. The Docker Tool Loop uses a no-network deterministic
Provider fixture and safe T3 mock Tool, while retaining Provider Gateway, Secret Lease, Capability,
policy, checkpoint, and approval behavior.

The Control Plane Compose stack starts PostgreSQL, the API, and one non-root Worker daemon:

```powershell
docker compose -f containers/compose.control-plane.yaml up --detach --no-build --wait
$env:PAJIN_TEST_CONTROL_PLANE_URL='http://127.0.0.1:18090'
.venv\Scripts\pytest -q tests/test_worker_daemon_live.py
Remove-Item Env:PAJIN_TEST_CONTROL_PLANE_URL
docker compose -f containers/compose.control-plane.yaml down --volumes
```

The live test submits a Tool Loop Job, waits for the daemon to upload its T3 checkpoint, approves it,
resumes it, and verifies the continuation Job completed through the real Tool Loop adapter. The
opt-in crash test additionally kills only the isolated lab Worker container and verifies PostgreSQL
lease recovery:

```powershell
$env:PAJIN_TEST_CONTROL_PLANE_URL='http://127.0.0.1:18090'
$env:PAJIN_TEST_WORKER_CRASH_CONTAINER='containers-worker-daemon-1'
.venv\Scripts\pytest -q tests/test_worker_daemon_crash_live.py
Remove-Item Env:PAJIN_TEST_WORKER_CRASH_CONTAINER
Remove-Item Env:PAJIN_TEST_CONTROL_PLANE_URL
```

Job delivery is at least once. A crash after an external Tool side effect but before durable
completion can replay that Tool, so production adapters must propagate destination idempotency keys
or make replay risk an explicit policy/approval decision. Compose artifacts use tmpfs and are not a
durable evidence store. See [`ADR 0012`](docs/adr/0012-lease-aware-worker-daemon.md).

## Dynamic multi-agent engine

Run the deterministic five-role team through the simulated or Docker Worker:

```powershell
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker simulated
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker docker
```

The Supervisor creates one Specialist per planned step. Deterministic Planner, Validator, and
Reporter roles have zero tool-call authority; provider-backed roles receive only their registered
Provider Tool and endpoint. Tasks form an explicit dependency graph. T0/T1 Specialist failures may
retry once within the same grant; higher-risk tools are never retried automatically. The
independent Validator can confirm a finding only when its target is declared and every cited
artifact was produced by a Specialist in the same run.

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
run-integrity.jsonl
agents.json
task-graph.json
capabilities.json
budget.json
control.json
```

## Evidence integrity verification

Every completed local Run writes `run-integrity.jsonl`. Each seal binds its new artifact paths,
byte sizes, media types, SHA-256 digests, available request/Tool/Worker provenance, the current Audit
Event chain head, and the previous seal root. Core execution produces the first seal; KISA
assessment, remediation/retest, Bug Bounty triage, and direct Tool Loop checkpoint claims append
extension seals after verifying the current root.

Verify a Run before consuming or transferring its evidence:

```powershell
.venv\Scripts\pajin evidence-verify <run-directory>
```

Verification fails on changed or missing sealed files, unsealed file additions, reordered or edited
Audit Events, invalid seal links, and appended events without a matching extension seal. A sealed
artifact cannot be overwritten through `RunStore`.

The root digest provides deterministic local tamper detection, not signer identity or protection
from a privileged actor who can replace the Run and every externally unanchored digest. Production
deployment should publish the displayed root to an independent signed transparency or object-store
record.

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
[ADR-0005](docs/adr/0005-kisa-ai-red-team-mode-pack.md), and
[ADR-0006](docs/adr/0006-provider-neutral-ai-chat-probe.md), and
[ADR-0007](docs/adr/0007-kisa-remediation-and-retest-loop.md), and
[ADR-0013](docs/adr/0013-bug-bounty-scope-parser.md), and
[ADR-0014](docs/adr/0014-conservative-bug-bounty-deduplication.md), and
[ADR-0015](docs/adr/0015-fixed-bug-bounty-lab-execution.md), and
[ADR-0016](docs/adr/0016-tamper-evident-run-integrity.md).
