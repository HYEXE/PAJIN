# PAJIN

PAJIN is a policy-governed multi-agent AI red-team and security validation platform.

The current implementation is a CLI-first backend approaching MVP. It validates typed campaign and
Mode Pack manifests, dynamically creates a bounded Supervisor/Planner/Specialist/Semantic
Validator/Reporter team, evaluates every tool request through the Tool Gateway, executes registered
mock, HTTP, or MCP tools through a simulated or isolated Docker Worker, admits Candidates, reviews
them through separate semantic and objective evidence gates, and writes audit evidence plus
structured JSON and Markdown reports. An optional FastAPI/PostgreSQL Control Plane and lease-aware
Worker daemon provide the first durable execution path without replacing the local CLI.

## Current implementation status

The implementation baseline as of 2026-07-18 is:

| Area | Current scope |
| --- | --- |
| Core engine | Typed Campaigns, policy and capability enforcement, dynamic Specialists, budgets, retries, cancellation, Candidate admission, semantic evidence review, versioned replay contracts, a deterministic Replay Compiler, single-use execution tickets, a local SQLite replay-ticket ledger, stateless and registered fresh-session Restricted Reproducer paths, receipt-reloading confirmation/retest gates, and tamper-evident evidence seals |
| AI Red Team | KISA catalog for 19 threat classes and 52 checklist items; executable A01, A02, A04, M03, and M06 scenarios; exact M03, M06, and A04 fresh-session replay through `kisa-run` and an explicit Local path; verified reproduction-backed confirmation projections; and baseline-bound negative replay for hardened retest |
| Bug Bounty | Program-policy review, canonical scope compilation, conservative duplicate triage, local report drafts, and one fixed Boolean SQL injection lab |
| CTF | Typed local Web backup and offline single-byte XOR challenges, plus a bounded Web + Crypto Suite |
| Control Plane | Optional authenticated FastAPI API, PostgreSQL Job queue, approval checkpoints, fenced and cooperative execution cancellation, leases, crash recovery, one Worker daemon, a same-origin Web Console preview, an owner-controlled managed filesystem Artifact repository, server-derived non-dispatchable planned/pending records for exact KISA M03, M06, and A04 confirmation compilations, M6-07B-2C schema-v5 durable reservation and internal first-attempt Job/ticket issuance, M6-07B-2D schema-v6 append-only one-use per-call permit ledger plus idempotent internal service issuance, M6-07B-2E fail-closed dedicated Worker HTTP transport, and M6-07B-2F schema-v7 append-only exact Replay execution-context authority |
| Primary gaps | Remaining Control Plane Replay orchestration, including a public Replay admission/read API, an actual Replay executor with pre-dispatch permit-use enforcement, the Worker execute/seal split, output import and typed finalization, new-identity retries, Gate wiring, and negative Control Plane retest; non-KISA Local replay orchestration; portable/off-host replay proof; Finding/report review UI; distributed Workers; external integrations; and independently anchored production evidence |

The primary operator interface remains CLI + YAML. Generic public-target attack automation,
external Bug Bounty or CTF submission, and production multi-tenant deployment are not implemented.

> **Validation status:** PAJIN currently implements trusted Candidate admission, semantic review,
> objective evidence gates, sealed Decision snapshots, and versioned `ValidationPacket`,
> `ReplayIntent`, `ModeReplayContract`, `CompiledReplaySpec`, `ReplayAttempt`, `ReplayOracleResult`,
> and `ReplayOutcome` contracts. A pure deterministic compiler now checks the original Plan, bound
> Tool request, Specialist grant, evidence digests, Scope, authorization, cancellation and budget,
> then emits only a five-minute non-delegable `ReplayCapabilityGrant` and single-use execution
> ticket. A separate Restricted Reproducer claims one ticket, executes compiled operations through
> the existing Tool Gateway and Worker, produces fresh request/evidence lineage, forbids Tool-authored
> Secret Lease requests, applies the Campaign deadline and cancellation through an async Mode
> Oracle, and returns a twice-sealed receipt with a verified disk loader. Exact KISA
> `ai.chat-probe` contracts now use a trusted fresh-session materializer and a raw-transcript Mode
> Oracle. After a completed source Run is sealed, `kisa-run` and the explicitly opted-in Local
> `pajin run ... --kisa-replay` path coordinate Candidate-bound replay in distinct replay Runs, with
> one new session per attempt and the same shared Campaign budget and rate limits. The ordinary
> `pajin run` path never enables replay implicitly. Worker-authored `vulnerable` and `matched` fields
> are not trusted. Other session-bearing
> contracts still fail closed without a registered trusted materializer. The M6 common gate now
> reopens every KISA replay Run, verifies both seals and ticket finalization, applies the shared
> reason matrix, and appends `validation/v1alpha1/` without rewriting the sealed source snapshot.
> Only verified reproduction-backed Decisions enter that versioned Finding projection, as required
> by [ADR 0027](docs/adr/0027-independent-reproduction-confirmation-boundary.md). M6-05의 KISA
> retest 경로는 이 투영의 reproduction-backed Confirmed Finding만 기준선으로 받아들인다.
> 일반 retest Run은 정상 기능 probe와 regression을 담당하고, 별도의 baseline-bound
> Restricted Replay가 기준 Candidate의 정확한 공격 계약을 실행한다. 모든 기대 반복이 성공하고
> canonical receipt를 다시 검증한 trusted negative Oracle이 명시적으로
> `ReplayOracleVerdict.CONTRADICTS`를 반환할
> 때만 해당 Finding을 `fixed`로 닫는다. 로컬 KISA positive/negative 경로는 개별 sealed replay
> Run 밖의 안정된 SQLite 원장에 ticket 발급 context와 `issued → claimed → finalized` 전이 및
> event journal을 원자적으로 기록한다. `mode=ro` verifier는 프로세스를 다시 시작한 뒤에도
> compilation, source root, replay Run, artifact digest와 최종 seal root를 대조한다. 자세한
> 신뢰 경계는 [ADR 0028](docs/adr/0028-durable-local-replay-ticket-ledger.md)을 따른다.

## Current safety boundary

- Network access is denied by default and cannot be granted by a Tool Adapter.
- A network-enabled tool receives a campaign-derived egress policy only from the Tool Gateway.
- Each network execution gets a private internal Docker network and a dedicated allowlist proxy.
- Public destinations are the default; loopback, link-local, private, reserved, multicast, and
  unspecified addresses are rejected. Private-network Mode Pack exceptions are limited to fixed
  synthetic labs: Bug Bounty uses its `local-lab` profile, while the CTF Web slice permits only
  `host.docker.internal:8780/backup/config.json.bak`.
- The CTF Crypto slice has no egress policy. It accepts only a content-addressed inline artifact of
  at most 4 KiB and evaluates exactly 256 single-byte XOR keys inside the no-network Worker.
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
- Product-level confirmation requires a successful independent Restricted Reproducer outcome and
  the objective gate; a Semantic Validator mark alone is insufficient.
- KISA `fixed` 판정은 봉인된 `validation/v1alpha1`의 reproduction-backed baseline과 exact
  Candidate/Decision/Finding/remediation/retest Run/root/request/scenario/threat/Tool/target 결박을
  요구한다. 단순한 공격 신호 부재, Worker 판정 플래그, 또는 `supports_claim == false`는 negative
  증명이 아니다. 결박·무결성 불일치는 명령을 fail closed로 종료하며 baseline artifact를
  변경하지 않는다.
- `ReplayIntent` is a strict, non-executable schema: raw Tool requests, commands, arbitrary URLs,
  Capability Grants, and undeclared executable fields are rejected. Versioned replay artifacts bind
  Candidate, Run, original and replay request, Mode, scenario, Tool, target, and threat identities
  before the deterministic compiler can issue a candidate-bound, non-delegable replay Grant and
  opaque single-use execution ticket. The Restricted Reproducer rechecks the Campaign, Tool,
  scenario fingerprint, shared budget/rate ledger, fresh evidence JSON, sealed artifact digest, and
  finalized ticket receipt before a Mode Oracle can support the claim. Replay dispatch and Oracle
  evaluation share deadline/cancellation bounds, and the Tool Adapter cannot request new Secret
  Leases. The exact KISA M03, M06, and A04 `ai.chat-probe` contracts may materialize only a fresh
  per-attempt `session_id`; every other catalog argument remains compiler-bound. Unregistered
  session-bearing contracts fail closed.
- Local KISA replay ticket state is stored in a stable SQLite ledger outside the sealed replay Run.
  The ledger uses atomic single-use state transitions and a read-only verifier, but it is trusted as
  a local database under the host OS account/ACL boundary. It is not a portable signed proof, an
  off-host attestation, or the PostgreSQL Control Plane replay authority.
- The explicit Local KISA coordinator is limited to one process and one writer, and only the exact
  M03, M06, and A04 `ai.chat-probe` contracts are allowlisted. It is not a generic structural replay
  predicate or a distributed lock. Accepted ADR 0029 governs Control Plane replay artifact handoff,
  lease fencing, PostgreSQL ticket/batch/item state, and durable budget/rate state. The implemented
  M6-07B-2B foundation includes the versioned Replay aggregate and burn-on-claim lifecycle, an
  owner-controlled managed filesystem repository, immutable `cp_artifacts` metadata, and
  server-owned admission of completed sealed sources. Producer Control Plane Run identity remains
  distinct from the sealed Run identity. Consumers provide only the exact opaque
  `(artifact_id, repository_version)` locator, and the server resolves it and re-verifies content
  and seals. As of 2026-07-18, batch creation accepts only that locator and an idempotency key; the
  Control Plane rereads the managed sealed AI Red Team source, derives eligible exact M03, M06, and
  A04 confirmation Candidates and contracts, runs the trusted Replay Compiler, and persists the
  canonical `ReplayCompilation` plus its `ReplayCapabilityGrant` as an append-only planned/pending,
  non-dispatchable derivation record and proof in PostgreSQL. Caller-authored Candidate, contract,
  policy, digest, target, and arguments are not authority inputs. Schema v4 extends the forward
  v1→v2→v3→v4 path with canonical,
  non-dispatchable compilation derivation records. Each append-only row has its own
  `compilation_id`, Replay Run identity, compilation digest, and Grant digest; its non-unique
  `item_id` and Candidate/contract plan-identity foreign key allow later attempt/version rows for
  the same item. M6-07B-2C durable issuance is also implemented as of 2026-07-18. The internal,
  idempotent `ControlPlaneService.issue_replay_batch(batch_id, actor=...)` path resolves and
  re-verifies the managed source again, then uses schema v5 `cp_replay_budget_accounts`,
  `cp_replay_budget_reservations`, `cp_replay_rate_accounts`, and
  `cp_replay_rate_reservations` authority. It conservatively binds the sealed budget and request-rate
  snapshot, reserves the complete first-attempt Tool-call/request-unit requirement, recompiles every
  pending item with a fresh Replay Run identity and five-minute Grant, appends a new canonical
  `ReplayCompilation`, and atomically creates exactly one internal Job and `issued` ticket per item.
  The Job payload and ticket are bound by foreign keys and strict models to the exact
  `compilation_id`, `budget_reservation_id`, `rate_reservation_id`, attempt, Replay Run, compilation
  digest, and Grant digest. The original planned compilation remains a non-dispatchable proof and is
  never promoted or reused. Only a response-loss retry against the current active exact authority
  graph reconstructs that issuance: the ticket/Job pair must still be `issued`/`queued` immediately
  after issuance, or `claimed`/`running` after claim. A terminal or otherwise changed graph must
  fail closed. M6-07B-2D internal service-only per-call permit ledger and issuance is also implemented
  as of 2026-07-18. Schema v6 extends the forward v1→v2→v3→v4→v5→v6 path with append-only
  `cp_replay_tool_permits`. The strict `ReplayToolPermitRequest` accepts only the executor profile,
  lease token, ticket ID, fencing value, and 1-based call ordinal. The idempotent
  `ControlPlaneService.issue_replay_tool_permit(job_id, request, actor=...)` service rechecks the
  authenticated principal and registered executor profile; the exact Job/ticket lease token and
  fence; active Run, batch, item, and ticket state; canonical compilation and Grant; exact
  reservation counters; and rolling request-rate admission. With a configured cap, admission counts
  the current sealed baseline, post-admission unconsumed units in still-live reservations, active permit units in
  their 60-second windows, and the new trusted request cost. With no cap, rate rejection is skipped
  but exact reservation counters are still consumed. A canonical permit binds that authority graph,
  source and original request, Tool and version, target, method, 1-based ordinal, one Tool-call unit, and the
  trusted request-unit cost. Its TTL is at most 30 seconds and never exceeds the lease, compiled
  spec, or Grant deadline; rate-reservation expiry is not a permit-TTL cap. The unique ticket/ordinal
  key plus persisted permit digest and request ID makes an exact response-loss duplicate return the same row without consuming counters or
  appending an event twice. First issuance atomically moves its reserved budget and rate units to
  consumed and appends the audit event. An issued permit remains consumed if execution is uncertain;
  cancellation or abandonment releases only the definitely unissued remainder. Stale, mismatched,
  cancelled, expired, finalized, ordinal-gap, and over-limit requests fail closed. M6-07B-2E now
  exposes that existing service authority only through dedicated WORKER-role HTTP endpoints for
  Replay claim, heartbeat, and Tool-permit issuance, plus matching async client methods. The strict
  JSON `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` subject-to-executor-profile-array allowlist accepts only
  authenticated Worker subjects; when unset it is empty and fails closed. For example,
  `{"worker-service":["kisa-exact-v1"]}` grants that one profile to that one subject. Claim and heartbeat return a
  `ReplayExecutionClaimView` containing the exact server-validated canonical `ReplayCompilation`,
  and the envelope rechecks its canonical compilation, Candidate, contract, Grant, Campaign, Mode,
  Candidate Run, and Replay Run bindings. The permit remains a non-bearer proof whose issuance has
  already consumed the durable units; M6-07B-2E adds no separate redeem mutation. M6-07B-2F now
  creates one append-only schema-v7 `cp_replay_execution_contexts` row for every fresh compilation
  during issuance. Its canonical `ReplayExecutionContext` binds the exact typed Campaign, exact KISA
  Scenario, and canonical `AIChatProbeTool.spec`, stores a digest for each component and the complete
  context, fixes `required_executor_profile` to `kisa-exact-v1`, forbids Secret Leases, and allocates
  only an opaque `stage_<uuid>` output slot rather than a Worker path. The Job payload repeats the
  context ID/digest; claim and heartbeat return the same server-validated context; profile checks and
  every permit issuance revalidate the transitive compilation/context/ticket binding. A v6→v7
  migration advances only non-dispatchable v6 state with an empty context table and fails closed if
  tickets, permits, internal Replay Jobs, durable reservations, or advanced batch/item state already
  exist, because those exact historical context bytes cannot be backfilled. These context bytes do
  not implement execution or output storage. No actual Replay executor exists yet, and Compose does
  not enable a dedicated Replay executor daemon. A public Replay admission/read API, the actual
  executor and pre-dispatch permit-use enforcement, the Worker execute/seal split, output import and
  typed finalization, new-identity retry issuance, Gate wiring, and negative Control Plane retest
  remain outstanding, so full M6-07B remains incomplete.
- Audit Events form a sequence-checked SHA-256 chain, and completed Run artifacts are captured in
  append-only integrity seals. Mode Pack outputs extend the previous root instead of overwriting it.

## Development setup

Python 3.12 or newer is supported. The repository `.python-version` selects Python 3.12 as the
portable contributor and CI baseline.

The checked-in root `uv.lock` is the canonical dependency lock for the application, development
tools, and optional Control Plane. Create an exact environment from a clean clone with:

```powershell
uv sync --locked --extra dev --extra control-plane
```

Use `uv lock` after an intentional dependency constraint change and review the resulting lockfile
diff. Use `uv lock --upgrade-package <package>` for a targeted upgrade rather than refreshing every
package implicitly. The Docker Worker remains a separate execution boundary and continues to use
`containers/worker/requirements.lock`.

For environments where `uv` is unavailable, the editable pip install remains a supported
bootstrap path, but it resolves within the declared version ranges and is not the reproducible
quality-gate environment:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev,control-plane]"
```

## Supported command surface

| Group | Commands |
| --- | --- |
| Core | `validate`, `run`, `multi-run`, `multi-cancel-check` |
| Provider and agent loop | `provider-check`, `provider-agent-run`, `tool-loop-run`, `tool-loop-approval-check` |
| KISA AI Red Team | `kisa-run`, `kisa-plan-remediation`, `kisa-retest` |
| Bug Bounty | `bug-bounty-review`, `bug-bounty-compile`, `bug-bounty-report`, `bug-bounty-run` |
| CTF | `ctf-run`, `ctf-web-run` (compatibility alias), `ctf-suite-run` |
| Evidence and infrastructure | `evidence-verify`, `replay-verify`, `worker-check`, `egress-check`, `mcp-check` |

The optional server processes are installed as `pajin-control-plane` and `pajin-worker-daemon`.
Run `pajin --help` or `pajin <command> --help` for the authoritative option list.

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

After a completed Bug Bounty Campaign has validation findings, compare them with an optional
program-specific known-finding index and generate submission drafts:

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
The current draft flow consumes the legacy validation projection. Until the control-set probe is
executed again with a new replay request and evidence lineage, it is not product-level Confirmed.

### Automated local Bug Bounty lab

The executable Bug Bounty slice is intentionally narrower than the general scope parser. It runs
only the compiled `boolean-sqli-lab` profile against the synthetic loopback-bound target. The
Planner can select only `bug-bounty.boolean-sqli-probe`; the Tool accepts no agent-authored attack
payload and the trusted Worker performs exactly one baseline, one negative control, and one boolean
comparison. The Validator ignores the Worker's claimed conclusion and recomputes the signal from
the three bounded observations. This protects the evidence-review boundary but reuses the original
execution and is not independent reproduction. One Tool call reserves three request-rate units.

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

The vulnerable profile currently produces one legacy validation draft. Recreate the target with
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

## Local CTF Mode

CTF Mode accepts a typed `CTFChallenge` manifest and runs the existing five-role team as Triage
Planner, category Specialist, independent flag Validator, and Reporter under the Supervisor. The
Triage Planner currently recognizes two separately bounded scenarios:

- `web.exposed-backup-config` routes to the fixed Web Specialist;
- `crypto.single-byte-xor` routes to the no-network Crypto Specialist.

Both manifests keep the expected flag as SHA-256 rather than plaintext and cannot select a Docker
image, command, executable, or scoreboard destination. `ctf-run` is the category-aware entry point;
`ctf-web-run` remains a backward-compatible alias that rejects non-Web manifests.

### Web challenge

Build the Worker and egress proxy, then start the vulnerable loopback-bound challenge target:

```powershell
docker build --tag pajin-worker:dev containers\worker
docker build --tag pajin-egress-proxy:dev containers\egress-proxy
docker compose -f containers\compose.ctf-web-lab.yaml up --build --detach

.venv\Scripts\pajin ctf-run examples\ctf-web-backup-lab.yaml
```

The Triage Planner can create only one `ctf.web-backup-probe` step. The Tool and trusted Worker both
enforce one GET to `http://host.docker.internal:8780/backup/config.json.bak`; the Gateway injects
the private-network egress policy from the compiled Campaign. The Specialist never receives the
expected digest. The Mode-specific digest Validator hashes the candidate and produces a verified
solve result only on a constant-time digest match.

The vulnerable profile should produce `solved` plus `ctf-result.json` and `ctf-writeup.md`. Recreate
the same target with the hardened override to confirm the backup artifact is absent and the command
returns an `unsolved` non-zero result:

```powershell
docker compose `
  -f containers\compose.ctf-web-lab.yaml `
  -f containers\compose.ctf-web-lab.hardened.yaml `
  up --build --detach --force-recreate

.venv\Scripts\pajin ctf-run examples\ctf-web-backup-lab.yaml

docker compose -f containers\compose.ctf-web-lab.yaml down
```

### Crypto challenge

The Crypto manifest carries one bounded inline artifact as lowercase hex plus the SHA-256 of its
decoded bytes. The compiler derives a logical `artifact.invalid` content address; the manifest does
not supply any network target or filesystem path. The Tool rechecks the digest before creating a
Worker Job, and the Worker rechecks it again before evaluating all 256 single-byte XOR keys. The
Tool declares T0 risk, receives no egress policy, invokes no external process, and returns at most
one `PAJIN{...}` candidate.

Build the updated Worker and run the synthetic artifact without starting any target service:

```powershell
docker build --tag pajin-worker:dev containers\worker
.venv\Scripts\pajin ctf-run examples\ctf-crypto-xor-lab.yaml
```

The Crypto Specialist never receives the expected flag digest. The Mode-specific digest Validator
binds the candidate to same-run evidence and compares its SHA-256 with the sealed Campaign value.
The write-up records category routing, offline analysis, and the final digest decision.

Core execution creates the first evidence-integrity seal; CTF result and write-up finalization
verifies that root and appends a second seal. `ctf-run` is Docker-only and has no scoreboard
credential, API client, or external submission path. Additional categories require a separate
typed scenario, Tool grammar, isolated fixture, independent verification rule, and safety review.

### Web + Crypto Suite

`ctf-suite-run` compiles exactly one Web manifest and one Crypto manifest into one Campaign. The
two manifests must have distinct challenge IDs, the same approving authority, and overlapping
authorization windows. The compiled Campaign uses only their approval-window intersection, binds
both member contracts into authorization evidence, derives a six-agent budget, and permits exactly
two Tool calls.

Start the local Web fixture, then run both typed challenges together:

```powershell
docker compose -f containers\compose.ctf-web-lab.yaml up --build --detach

.venv\Scripts\pajin ctf-suite-run `
  web-crypto-suite `
  examples\ctf-web-backup-lab.yaml `
  examples\ctf-crypto-xor-lab.yaml

docker compose -f containers\compose.ctf-web-lab.yaml down
```

The deterministic Triage Planner creates one `ctf-web-specialist` and one
`ctf-crypto-specialist`. Each receives a separate Capability Grant restricted to its own target and
Tool. Both fixed Tools opt in to `parallelSafe`, so the generic runner executes them in the same
bounded local wave and restores their results to deterministic plan order. The aggregate
`ctf-suite-result.json` retains `solved`, `unsolved`, or `invalid-flag` for each challenge, while
`ctf-suite-writeup.md` records only independently digest-validated flags. Any non-solved member
makes the CLI return non-zero after still sealing the complete aggregate evidence. No scoreboard
submission is available.

## KISA AI Red Team Mode Pack

Run the KISA-aligned indirect prompt-injection and unauthorized tool-use scenario with two
independent repetitions:

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker simulated --repetitions 2
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker docker --repetitions 2
```

For the exact KISA AI Chat contracts, the ordinary Local runner can opt into the same
Candidate-to-replay-to-Gate boundary explicitly:

```powershell
.venv\Scripts\pajin run examples\kisa-ai-chat-lab.yaml --worker docker --kisa-replay --repetitions 2
```

Without `--kisa-replay`, `pajin run` remains the normal Local execution path and does not create
replay tickets or invoke the confirmation Gate. The opt-in path is limited to AI Red Team Campaigns
and the exact M03, M06, and A04 allowlist; unsupported or missing contracts stay unconfirmed rather
than being selected by a generic predicate.

The Mode Pack maps the 19 threat classes in the KISA AI Security Red Teaming Guide to a typed
catalog, selects target-compatible scenarios, executes each scenario through separate Specialist
agents, and deduplicates Candidate and legacy validation findings after same-Run evidence checks.
M03·M06·A04의 trusted Candidate는 별도 replay Run과 공통 Gate를 거쳐 reproduction-backed
Confirmed 투영으로 승격될 수 있다. 그 밖의 요청 위협은 실행 가능한 target-linked scenario와
명시적인 replay 계약이 추가될 때까지 coverage gap 또는 `needs-review`로 남는다.

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
Tool Gateway derives egress from Campaign Scope, and the Semantic Validator rechecks the raw
transcript instead of trusting the Tool's vulnerability flag. This is semantic and deterministic
evidence review over the original execution, not a second reproduction request.

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

A completed `kisa-run` additionally reproduces eligible trusted M03, M06, and A04 Candidates in
separate replay Runs. Each attempt uses a session distinct from the source execution and every other
attempt. The live KISA Oracle recomputes the exact catalog checks from the raw transcript, and the
source/replay link is written to `kisa-replay-index.json`. When at least one verified receipt is
projected, `confirmationMutationApplied` is `true`; a run with no eligible verified receipt remains
`false`. The common gate reloads the receipts and appends a sealed `validation/v1alpha1`
Decision/Finding/report projection; the original flat artifacts remain the immutable pre-replay
snapshot.

로컬 positive replay ticket 원장은 선택한 output root의
`<output>/replay/replay-tickets.sqlite3`에 저장된다. 발급된 compilation과 source root, replay
Run, 최종 artifact digest 및 receipt seal root는 실행 프로세스가 종료된 뒤 새 read-only
verifier로 다시 확인할 수 있다.

명시적 Local `pajin run --kisa-replay` 경로는 이와 분리된
`<output>/local-replay/replay-tickets.sqlite3`를 사용한다. 원 Run, Candidate, SQLite ticket과
별도 replay Run을 같은 프로세스의 단일 writer가 순서대로 만든 뒤 공통 Gate가 canonical
receipt를 다시 읽는다. Gate는 flat `findings.json`을 변경하지 않고
`validation/v1alpha1/` 투영만 reproduction-backed Confirmed로 확장한다.

```powershell
.venv\Scripts\pajin replay-verify <replay-run-directory> `
  --ledger <output>\replay\replay-tickets.sqlite3

.venv\Scripts\pajin replay-verify <local-replay-run-directory> `
  --ledger <output>\local-replay\replay-tickets.sqlite3
```

`replay-verify`는 ledger를 생성하거나 ticket 상태를 변경하지 않는다. 파일 누락, ticket 미완료,
context·digest·Run·seal 불일치는 fail closed로 종료한다.

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

`kisa-retest`는 봉인된 `validation/v1alpha1`에 reproduction-backed Confirmed로 기록된 baseline
Finding만 소비한다. legacy flat Finding, semantic-only Candidate, 미확정 baseline은 재검증
기준으로 받아들이지 않는다. 일반 parent retest Run은 정상 기능 probe와 regression을
수행하고, baseline-bound Restricted Replay는 각 기준 Candidate의 원 request·scenario·threat·
Tool·target을 그대로 컴파일해 별도 공격 replay Run에서 실행한다. 두 경로의 결과는 구분해
기록하되 호출은 같은 Campaign 예산·rate limit·취소 경계를 소비한다.

재검증 Gate는 canonical receipt를 디스크에서 다시 열어 Candidate, source Decision, versioned
Finding, remediation action, baseline/retest Run과 seal root, original/replay request, scenario,
threat, Tool, target 결박을 확인한다. 모든 기대 반복이 성공하고 trusted negative Oracle이 원
compromise claim에 대해 명시적으로 `ReplayOracleVerdict.CONTRADICTS`를 반환할 때만 `fixed`다. verified
`ReplayOracleVerdict.SUPPORTS`는
`still-vulnerable`, support와 contradiction이 섞였거나 반복 부족·실행 실패·취소·timeout·target
unavailable·명시적인 방어 증적 부재는 `inconclusive`다. 기존 positive Oracle은 zero support를
계속 `inconclusive`로 처리하며, Worker의 `vulnerable=false`나 단순 신호 부재만으로 `fixed`를
주장하지 않는다. 결박 또는 무결성 불일치는 상태로 축소하지 않고 명령을 fail closed로
종료한다.

현재 trusted negative predicate는 결정론 KISA Lab의 M03·M06·A04에 등록된 정확한 방어 응답,
전 턴 compromise marker 부재, `toolCalls`·`memoryWrites` 부재를 함께 재계산한다. A04는 첫 쓰기
거부와 후속 조회의 비지속 응답을 구분한다. `safety.blocked`·reason만으로는 반증이 되지 않으며
등록 응답과 불일치하는 메타데이터, 미등록 방어 문구나 target은 안전하게 `inconclusive`다.

정상 기능 regression은 Finding 상태와 독립적으로 평가한다. `kisa-retest`의 범위 한정 Exit
Gate는 모든 baseline Finding이 `fixed`, `still-vulnerable`·`inconclusive`가 0, 실행 중 관찰된
새 Confirmed Finding이 0, regression이 `pass`일 때만 열린다. 그 밖의 결과는 산출물을 봉인한
뒤 non-zero로 종료한다. 이 명령은 baseline 폐루프이지 새로운 위협 유형을 찾는 전체 재스캔이
아니다. 신규 취약점 부재까지 주장하려면 별도의 fresh `pajin kisa-run` discovery Gate를 실행해야
한다. 이 discovery도 현재 실행 가능한 시나리오 범위만 다루며, 나머지 KISA 위협은 아직
`not assessed`다.

`kisa-plan-remediation`은 versioned baseline projection과 기존 seal entry를 덮어쓰지 않고
`remediation-plan.json`과 event를 append한 뒤 새 current root를 만든다. `kisa-retest`는 이
확정된 root를 모든 baseline-bound receipt에 결박하며, 이후 baseline 변경은 hard fail한다.
retest Run은 `remediation-plan.json`, `kisa-retest.json`, `kisa-retest-index.json`,
`kisa-checklist-overlay.json`, `kisa-retest-report.md`와 baseline-bound replay/receipt lineage를
append-only seal로 보호한다. overlay는 증적으로 확인한 다섯 KISA 항목만 supersede하고,
담당자·기한·운영 반영은 계속 사람 검토 항목으로 남긴다.

negative replay ticket은 `<output>/retest-replay/replay-tickets.sqlite3` 원장에 같은 원자적
상태 전이와 발급 context를 기록한다. 재시작 후 검증 명령은 위와 동일하며 `--ledger`에 이
retest 원장 경로를 지정한다. 이 로컬 원장은 기존 인메모리 API의 단위 테스트 호환 경계를
대체하지 않으며, PostgreSQL Control Plane replay나 외부 검증 가능한 서명 proof를 제공하지
않는다.

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

The implemented flow is Provider Planner → isolated `ai.chat-probe` Specialist → trusted Candidate
Producer → Provider Semantic Validator → objective gate → Provider Reporter. Validator findings are
accepted only when they cite evidence produced by a Specialist in the same run. The Restricted
Reproducer stage required before product-level confirmation is not implemented yet. Reporter output
is stored separately in `model-narrative.json` and is appended as a clearly subordinate section; it
cannot alter canonical findings or execution state.

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
$env:PAJIN_CP_ARTIFACT_STAGING_ROOT='C:\private\pajin-artifact-staging'
$env:PAJIN_CP_ARTIFACT_REPOSITORY_ROOT='C:\private\pajin-artifact-repository'
.venv\Scripts\pajin-control-plane
```

The Artifact roots are optional, but they must be configured together or both omitted. Keep both
directories private to the Control Plane service account and outside any Worker- or user-controlled
tree. Staging is an explicit handoff boundary; repository object paths remain server-owned and are
never accepted from an Artifact consumer. If the pair is omitted, managed Artifact admission and
Replay-batch source resolution remain unavailable and fail closed. Current durable admission also
requires a POSIX filesystem/runtime with directory `fsync` support; unsupported environments fail
closed.

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

### Web Console preview

The Control Plane serves a dependency-free, same-origin operator shell at
`http://127.0.0.1:8090/ui`. The shell itself contains no Run data and is public so a browser can load
it without placing a credential in a URL or cookie. All `/v1` data calls still require the existing
Bearer role checks. After the server above starts, open the URL and enter an Operator, Approver, or
Auditor credential.

The first Console slice supports:

- authenticated session-role discovery;
- Operator-only idempotent Run submission for registered `campaign` or `tool-loop` Job kinds;
- bounded Run listing with state filtering and stable pagination;
- selected Run input and append-only event inspection;
- minimized current-approval intent review without exposing checkpoint execution state;
- Approver-only approval or denial, with denial terminating the Run as `cancelled`;
- Operator-only one-time checkpoint resume and idempotent Run cancellation;
- optional five-second polling without WebSocket or SSE state.

Run lists return a summary DTO and never bulk-load or expose submitted input. The selected Run
detail remains authorized and includes that input. Browser credentials live only in JavaScript
memory: there is no cookie, local/session storage, IndexedDB, credential URL, or external asset.
Lock, refresh, tab close, and HTTP 401 clear the in-memory value. A restrictive CSP, no-store cache
policy, no-referrer policy, same-origin isolation headers, and text-only DOM rendering reduce the
browser attack surface.

Cancellation atomically fences queued or leased Jobs, clears active lease material, revokes a
pending or approved decision, and records bounded actor/reason events. While an executor is active,
the next rejected heartbeat activates its first-write-wins cancellation context. The Worker gives
that executor a bounded cooperative cleanup grace period before forced async task cancellation.
Built-in Local Campaign and Tool Loop runners seal `cancellation.json` after engine cleanup, and
their trusted Job executors append `quiescence.json` after the owned execution stack unwinds. If the
engine has already returned, a completion, failure, or checkpoint conflict fences the result
immediately and records the cause in daemon status; it does not reopen the runner or synthesize a
cancellation receipt. Neither receipt is a Control Plane acknowledgement: they do not roll back
external side effects or prove physical quiescence outside that local process.

This is a local single-tenant preview, not a production identity boundary. HTTPS must terminate in
front of the API before remote use. Report download, Agent Graph, user accounts, tenant isolation,
and a fleet-wide approval queue remain unimplemented. See
[`ADR 0022`](docs/adr/0022-same-origin-control-plane-web-console.md),
[`ADR 0023`](docs/adr/0023-fenced-control-plane-actions.md), and
[`ADR 0024`](docs/adr/0024-cooperative-execution-cancellation.md).

### Lease-aware Worker daemon

`pajin-worker-daemon` turns queued Control Plane Jobs into existing PAJIN engine runs. It keeps one
bounded async HTTP connection pool, claims only configured Job kinds, heartbeats throughout execution
and finalization, and retries transient completion calls. While an executor is active, Run
cancellation, lease loss, heartbeat unavailability, or daemon shutdown signals its typed cancellation
context. Once execution has returned, a finalization conflict is an immediate result fence rather
than a new cooperative runner-cleanup phase. Authentication rejection is fatal. SIGTERM stops new
claims, gives the active executor a bounded cooperative cleanup grace period, and then uses forced
task cancellation as a fallback.

The initial trusted registry contains:

- `campaign`: strict embedded Campaign manifest → deterministic `LocalCampaignRunner`
- `tool-loop`: strict embedded Campaign and prompt → real `PolicyToolLoopRunner`

No Job field can name a command, Python module, class, executable, or arbitrary manifest path.
Unknown kinds and invalid payloads fail closed. The Docker Tool Loop uses a no-network deterministic
Provider fixture and safe T3 mock Tool, while retaining Provider Gateway, Secret Lease, Capability,
policy, checkpoint, and approval behavior. Cancellation source selection is first-write-wins, so a
later shutdown or transport failure cannot relabel the original cause. A local runner receipt is
sealed with the Run evidence when cleanup completes; its absence does not imply successful cleanup.

| Worker setting | Default and accepted range | Boundary |
| --- | --- | --- |
| `PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS` | 2 seconds; 0.05-30 | Cooperative return before the daemon calls `task.cancel()` |
| `PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS` | 5 seconds; 0.05-30 | Bounded wait after forced task cancellation and for each final drain |

The daemon may use one grace window, one forced window, and one additional forced window to drain a
task that is still pending. A process supervisor must therefore allow more than
`grace + (2 * force)` plus scheduling margin. The Compose lab pins these defaults and uses a
15-second `stop_grace_period`, which exceeds its 12-second daemon bound. These are asyncio deadlines:
they advance only while the process and event loop run, and they cannot preempt synchronous blocking
code. `SIGKILL`, host loss, and process isolation failure bypass in-process cleanup entirely.

A backend's own cancellation cleanup must also fit the daemon window. The standalone
`DockerWorkerBackend` has a 20-second internal cleanup cap; the default five-second forced window is
not sufficient for an adapter that embeds that backend. The current Control Plane Compose adapters
are deterministic in-process profiles and do not embed it. A custom Docker-backed adapter should use
a forced window greater than 20 seconds and increase its supervisor allowance accordingly; for
example, `grace=2`, `force=25`, and a stop grace of at least 60 seconds.

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
retry once within the same grant only when a retry slot was assigned. After planning, the Supervisor
first reserves the maximum downstream calls for model-backed Validator and Reporter roles, then one
call for every Specialist. Remaining calls are assigned in plan order as at most one retry for each
T0/T1 task. A plan that cannot fund every first Specialist attempt fails before partial fan-out.
The Semantic Validator can support a Candidate only when its target is declared and every cited
artifact was produced by a Specialist in the same run. For cataloged KISA `ai.chat-probe`
scenarios, a Tool-less trusted Candidate Producer independently recomputes the raw transcript
checks before validation. The Tool, Candidate Producer, and deterministic Validator parse the same
strict `AIChatProbeOutput` contract and do not trust Worker-authored `matched` or `vulnerable`
verdict fields. A semantic Validator that returns no Finding therefore leaves a
`needs-review` Candidate instead of deleting the observation. Matching semantic support plus the
common objective gate also remains `needs-review` with `independent-reproduction-missing`; it cannot
enter the confirmed compatibility projection until a fresh Restricted Reproducer outcome exists.
Validator-only claims inside the Producer's request or target/threat authority remain review
Candidates, and cancellation or Validator failure preserves already observable Candidates as
`inconclusive`.

Specialist concurrency is opt-in at the Tool contract. `parallelSafe: false` is the default;
non-opted-in Tools execute as single-task barriers in plan order. Consecutive opted-in tasks run in
bounded local waves with a default limit of four, while results are restored to plan order before
validation and reporting. Kill Switch activation cancels active sibling Workers. This local
cooperative scheduler does not provide distributed or crash-durable reservations.

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
- bounded forced-container and per-execution egress-cleanup attempts after timeout, cancellation, or
  unexpected base exception

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
candidate-findings.json
validation-decisions.json
validation-index.json
findings.json
report.md
evidence/
run-integrity.jsonl
agents.json
task-graph.json
capabilities.json
budget.json
rate-limits.json
control.json
kisa-replay-index.json  # kisa-run only
validation/v1alpha1/    # verified replay Decision/Finding/report projection, when applied
```

The Restricted Reproducer uses a distinct replay Run. Its `replay/`
directory stores the Validation Packet, Mode contract, non-executable intent, compiled spec,
dedicated grant, attempts, Oracle result, aggregate outcome, and verification receipt. The first
integrity seal binds the outcome and complete artifact set; the receipt records that verified root,
and a second seal binds the receipt. `kisa-run` and the explicit Local `run --kisa-replay` path
coordinate this boundary for exact M03, M06, and A04 Candidates after sealing the source Run. They
then pass those replay Run paths to the common gate, which reloads canonical receipts instead of
trusting mutable in-memory records. The Local path is one-process/one-writer orchestration; it does
not provide Control Plane leases, cross-process Gate locking, or PostgreSQL replay authority.

`kisa-retest`도 같은 receipt loader와 Restricted Reproducer 경계를 사용하지만 확인 목적은
분리한다. parent retest Run의 정상 기능 결과를 negative 증명으로 재해석하지 않고,
봉인된 baseline Candidate에 결박된 별도 replay Run만 `fixed`·`still-vulnerable` 판정에 사용한다.
retest assessment에는 baseline과 remediation lineage, replay Run/Outcome/request/evidence ID,
Oracle verdict와 receipt seal lineage가 포함된다. versioned projection과 기존 baseline seal
entry는 immutable하며, remediation plan append 후 확정된 current root가 retest receipt에
결박된다.

The Candidate and Decision snapshots preserve every Finding returned by the legacy Validator and
every observation admitted by an enabled trusted Candidate Producer, together with its
deterministic disposition. `validation-index.json` is an ID-only status view, while the legacy
flat `findings.json` remains the immutable pre-replay compatibility snapshot. New consumers prefer
the sealed `validation/v1alpha1/index.json`, whose Decision, Finding, and Markdown artifacts include
the confirmation basis, superseded source Decision, replay Run/Outcome, request IDs, artifact digest,
and receipt-seal lineage. Historical flat confirmations are read as legacy and are never promoted to
the reproduction-backed projection. The current trusted producer is limited to exact KISA AI chat
catalog contracts; it does not trust a generic `vulnerable` field and gives the Semantic Validator
no attack or replay Tools.
Its atomic production also reserves request and target/threat confirmation space so a Validator
cannot bypass a zero Candidate result through the legacy adapter.

Mode Pack extensions can add artifacts such as `ctf-result.json`, `ctf-writeup.md`, KISA assessment
files, or Bug Bounty triage drafts before appending a linked integrity seal.

## Evidence integrity verification

Every completed local Run writes `run-integrity.jsonl`. A built-in Local Campaign or Tool Loop run
that observes cancellation after its store is initialized seals `cancellation.json`; its trusted
Control Plane executor can append `quiescence.json` in a second integrity extension. Each seal binds
its new artifact paths,
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

The default suite keeps live infrastructure tests environment-gated. Set
`PAJIN_TEST_CONTROL_PLANE_URL` for the Control Plane and Worker-daemon live tests, and
`PAJIN_TEST_POSTGRES_URL` for the isolated PostgreSQL integration test. The Worker crash-recovery
test additionally requires `PAJIN_TEST_WORKER_CRASH_CONTAINER` naming its isolated test container.
Docker smoke checks and Mode Pack labs require a running Docker daemon and the documented local
images or Compose fixtures.

## Architecture rule

PydanticAI is an adapter for model-backed planning and validation. It does not own campaign state
or execute privileged tools directly. Every MCP, CLI, browser, and sandbox call must pass through
the PAJIN Tool Gateway and Policy Engine.

See [the product plan](docs/PAJIN_PRODUCT_PLAN.md),
[the KISA traceability matrix](docs/KISA_TRACEABILITY.md), and the complete
[ADR decision record](docs/adr/). The latest implementation decisions are
[ADR-0019](docs/adr/0019-bounded-ctf-suite-orchestration.md),
[ADR-0020](docs/adr/0020-specialist-call-budget-allocation.md),
[ADR-0021](docs/adr/0021-opt-in-specialist-concurrency.md),
[ADR-0022](docs/adr/0022-same-origin-control-plane-web-console.md),
[ADR-0023](docs/adr/0023-fenced-control-plane-actions.md),
[ADR-0024](docs/adr/0024-cooperative-execution-cancellation.md),
[ADR-0025](docs/adr/0025-candidate-validation-ledger-and-replay-boundary.md),
[ADR-0026](docs/adr/0026-trusted-kisa-candidate-admission.md),
[ADR-0027](docs/adr/0027-independent-reproduction-confirmation-boundary.md),
[ADR-0028](docs/adr/0028-durable-local-replay-ticket-ledger.md), and
[ADR-0029](docs/adr/0029-control-plane-replay-orchestration.md).
