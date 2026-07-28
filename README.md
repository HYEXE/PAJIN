# PAJIN

## Architecture v2 direction

PAJIN is transitioning incrementally to one policy-governed common attack engine, Campaign
Profiles, versioned registered Capabilities, and a Minimum Canonical Graph. AI remains a
first-class security surface instead of defining the entire product. Existing `ai-redteam`,
`bug-bounty`, and `ctf` inputs and their policy, evidence, validation, and replay boundaries remain
compatible during the strangler migration.

An Adaptive Supervisor is deliberately deferred until the graph and benchmark contracts exist.
When introduced, it will consume immutable snapshots and emit proposals only; deterministic code
continues to compile single-use execution permits and enforce Scope, risk, budget, and Capability.
See [ARCH-001](docs/rfc/0001-pajin-architecture-v2.md),
[ADR-0046](docs/adr/0046-common-engine-and-campaign-profiles.md),
[ADR-0047](docs/adr/0047-mission-envelope-and-action-permit-algebra.md), and
[ADR-0048](docs/adr/0048-minimum-graph-and-admission-consistency.md), and
[ADR-0049](docs/adr/0049-durable-single-campaign-sqlite-graph-store.md), and
[ADR-0050](docs/adr/0050-consumed-action-permit-dispatch-claim.md), and
[ADR-0051](docs/adr/0051-versioned-capability-definition-and-tool-binding.md), and
[ADR-0052](docs/adr/0052-code-backed-capability-authority-set.md), and
[ADR-0053](docs/adr/0053-inert-deterministic-capability-scaffolds.md), and
[ADR-0054](docs/adr/0054-signed-reviewed-capability-lifecycle.md).

The repository keeps code-coupled contracts and decisions only. Use the
[documentation index](docs/README.md) to navigate those records and the
[documentation authority policy](docs/DOCUMENTATION_POLICY.md) before adding a new document.
Current priorities, implementation status, and milestone tracking live in the
[PAJIN Notion roadmap](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a).

## B2.8g resumable multipart portable Artifact transport

Replay Runs above the existing 2 MiB inline ceiling now use a manifest-only multipart transport.
The first slice is bounded to 64 MiB total, 16 MiB per file, 256 files, depth 24, and fixed 1 MiB
parts. The Control Plane verifies the live lease, exact Replay authority, executor signature, and
manifest before accepting bytes into its owner-private local object-store namespace.

Upload begin and part PUT operations are idempotent for exact retries. A retry cannot replace an
existing part with different bytes. Finalization recomputes every file digest and the canonical
manifest, atomically publishes the staging tree, and then reuses the existing managed Artifact,
sealed Run, receipt, and projection checks. Small Runs keep the existing inline v1 transport.
External S3-compatible storage, pre-signed URLs, upload expiry/garbage collection, encryption, and
tenant isolation remain follow-up work. See
[ADR-0045](docs/adr/0045-resumable-multipart-portable-artifact-transport.md).

## B2.8f Target-signed TLS session binding

Signed Target registry v4 can now require `tls-unique-sha256` for each HTTPS exact URL. In the
bounded TLS 1.2 lab profile, the Target signs its channel-binding digest in receipt statement v2
while the Executor independently signs the Worker-observed digest, leaf SPKI, and CONNECT route in
TLS binding v3. The Control Plane requires an exact digest, type, version, and pin match; receipt
v1, binding v1/v2 downgrade, and cross-session proof assembly fail closed.

Python 3.12 does not expose RFC 9266 `tls-exporter`, so this slice deliberately limits the new
profile to TLS 1.2 `tls-unique` instead of overstating TLS 1.3 support. Registry v1-v3 and all
legacy receipt/binding versions retain their existing behavior. Production TLS 1.3 exporter
support, full handshake policy, and mTLS remain follow-up work. See
[ADR-0044](docs/adr/0044-target-signed-tls-session-binding.md).

## B2.8e signed Target registry distribution

Target registry v3 can now be distributed as a separately domain-signed Ed25519 bundle. The
statement binds a contiguous sequence, predecessor bundle digest, seven-day-or-shorter validity
window, and the complete exact-URL registry. Schema v14 records each activation in append-only
`cp_target_attestation_registry_versions`, so restarts and multiple Control Plane replicas reject
rollback, sequence gaps, predecessor mismatch, and same-sequence equivocation. An HTTPS entry may
carry one retiring SPKI pin for at most 24 hours; receipt issue time determines whether that old
pin is still accepted, and the verification summary records the pin actually observed.

The Control Plane accepts an inline bundle or fetches it once at startup from a redirect-free
absolute HTTPS URL, bounded to 512 KiB. The distribution trust anchor remains an out-of-band public
configuration. Runtime refresh, TLS 1.3 exporter binding, CT/revocation, and recovery of the
anti-rollback baseline after loss of the database and its backups remain outside this slice. See
[ADR-0043](docs/adr/0043-signed-target-registry-distribution-and-rotation.md).

PAJIN is a policy-governed multi-agent AI red-team and security validation platform.

The current implementation is a CLI-first backend approaching MVP. It validates typed campaign and
Mode Pack manifests, dynamically creates a bounded Supervisor/Planner/Specialist/Semantic
Validator/Reporter team, evaluates every tool request through the Tool Gateway, executes registered
mock, HTTP, or MCP tools through a simulated or isolated Docker Worker, admits Candidates, reviews
them through separate semantic and objective evidence gates, and writes audit evidence plus
structured JSON and Markdown reports. An optional FastAPI/PostgreSQL Control Plane and lease-aware
Worker daemon provide the first durable execution path without replacing the local CLI.

## Current implementation status

The implementation overview below is release-neutral. Consult the
[PAJIN Notion roadmap](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a)
for the current Git baseline and verification state.

| Area | Current scope |
| --- | --- |
| Core engine | Typed Campaigns, policy and capability enforcement, dynamic Specialists, budgets, retries, cancellation, Candidate admission, Candidate-aware Provider review, deterministic validity/impact/severity Atomic Claims, metadata-minimized Blind Evidence review and deterministic reconciliation, optional separate-Provider/model Blind Review plus proposed-label-free independent severity derivation, an opt-in code-registered M03/M06/A04 fresh-capability Baseline/Negative Control/Counterfactual Control Executor, semantic evidence review, versioned replay contracts, a deterministic Replay Compiler, single-use execution tickets, a local SQLite replay-ticket ledger, stateless and registered fresh-session Restricted Reproducer paths, receipt-reloading confirmation/retest gates, and tamper-evident evidence seals |
| Canonical Graph | Single-Campaign append-only SQLite Event, Projection, Snapshot, and consumed ActionPermit authority with exact retry, stale-decision rejection, crash reconciliation, content-addressed backup/restore, and subprocess hard-exit coverage for committed, uncommitted, backup-publication, Permit-commit, RunStore-claim, and external Gateway-side-effect boundaries. An additive retention format encrypts the verified database with externally supplied AES-256-GCM key material, signs its canonical manifest with an external Ed25519 key, never serializes either secret, and passes a detached fresh-process restore drill. A transport-neutral repository protocol now requires put-if-absent publication, exact version/digest reads, requested object-lock receipts, and a signed cumulative inventory pinned by an external anti-rollback anchor. The local backend is a contract fixture only; actual off-host scheduling/provider integration, independently persisted anchors, KMS/HSM, independent-host drills, HA, and exhaustive power-loss injection remain follow-up work. |
| Capability registry | Immutable definition and exact Tool binding, complete seven-role code authority sets, inert deterministic authoring scaffolds, an additive signed lifecycle registry, an explicit opt-in seven-Capability compatibility bundle, and content-addressed CAP-006 Registry/lead-time/Oracle/Replay/lifecycle measurement over an external denominator. The closed adapter inventory has seven exact benchmark mappings and admits only a complete externally reviewed seven-release set; it never generates keys or approvals. An additive opt-in Worker bridge activates an explicit signed subset, compiles exact CAP-002 requests, exposes only that subset to GRAPH-006, and enters the existing Tool Gateway from the Permit's first-consumption callback with sealed Permit/result audit linkage. Before the Permit claim it seals a content-addressed deployment/Run anchor; crash reconciliation then classifies `consumed-without-claim`, `claimed-outcome-unknown`, or an observed terminal stage and records an immutable no-redispatch decision. Real subprocess hard exits after Permit commit, after the claimed audit append, and after a durable external side-effect marker prove restart-time no-redispatch behavior. The Web + AI exit-gate verifier rebuilds CAP-006 from source hashes sealed in the same Run and requires exact successful Web and AI dispatch lifecycles with sealed Gateway evidence. Local fixtures verify only the structural contract. All adapters remain experimental and no existing Mode path auto-activates them; durable Registry storage, organization-issued releases, and an actual isolated operational Campaign remain follow-up work. |
| Discovery contracts | Versioned `SurfaceObservation`, `AttackSurface`, and `AttackSurfaceSet` artifacts; canonical HTTP-operation and schema-bound Tool-interface locators; deterministic domain-separated identities; exact request/result/evidence/root lineage; bounded canonical JSON; and fail-closed ordering, uniqueness, and lineage validation. DISC-001 adds a code-owned `DiscoveryAdapter` protocol and exact ID/version/digest Registry that binds implementation context and the full Tool contract, rejects duplicate selection, secret-like context, and live adapter/Tool drift, and records the selected adapter reference in admission authority and projection audit. The legacy producer remains compatible while the MCP Recon reference path opts into the Registry. A3 adds an explicit opt-in single-call MCP Recon wave. A4 re-verifies the sealed projection, compiles versioned Hypotheses through code-registered rules, and runs one fresh-Capability Specialist wave. A5 adds a separate explicit opt-in bounded replanning control Run: it re-verifies the sealed A4 wave, promotes exact registered result fields into append-only `ObservationGraphSnapshot` artifacts, records `supports`, `contradicts`, `enables`, `depends-on`, and `new-surface` relationship contracts, and permits at most one novel code-registered transition into a second fresh-Capability wave. Shared Campaign agent, Tool-call, cost, time, and rate limits still apply; repeated or sub-threshold plans stop before execution. HTTP/OpenAPI/GraphQL adapters and Planner integration remain follow-up work. |
| AI Red Team | KISA catalog for 19 threat classes and 52 checklist items; executable A01, A02, A04, M03, and M06 scenarios; separate Claim-bound validity/impact/severity fresh-session Replay authority for exact M03, M06, and A04 through `kisa-run` and an explicit Local path; opt-in information-only validation Controls with three fresh single-call Capabilities per Candidate, registered materializer identity, and separate request/evidence/receipt lineage; Claim replay projections; and baseline-bound negative replay that remains inconclusive without external remediation attestation |
| Bug Bounty | Program-policy review, canonical scope compilation, conservative duplicate triage, local report drafts, and one fixed Boolean SQL injection lab |
| CTF | Typed local Web backup and offline single-byte XOR challenges, plus a bounded Web + Crypto Suite |
| Control Plane | Optional authenticated FastAPI API, PostgreSQL Job queue, approval checkpoints, fenced cooperative cancellation, leases and crash recovery, a same-origin Web Console preview, owner-controlled managed Artifacts, opaque Operator Replay source/batch admission with role-scoped batch/item/ticket/finalization/projection reads, durable exact-KISA Replay finalization, fresh-identity retry issuance, and a dedicated `kisa-exact-v1` Replay Worker. Schema v11 publishes CAS-fenced multi-item projections; schema v12 binds a confirmed baseline to one parent Retest Artifact and publishes a server-reverified `kisa-retest.json`; schema v13 adds append-only exact Claim bindings and an opt-in v3 Claim-specific public projection; schema v14 adds the signed Target registry anti-rollback ledger. Additional opt-ins seal an Ed25519 Claim-receipt verifier bundle, carry an executor-attested portable Artifact inline or through a resumable 64 MiB local-object-store multipart path, bind a Target-issued receipt and host observation, pin HTTPS endpoint SPKI, support signed registry rotation, and bind the Target-signed application exchange to the Worker-observed TLS 1.2 channel. Only validity drives confirmation, while impact and severity remain information-only. |
| Primary gaps | Validation Controls and Claim-by-Claim Replay beyond the three registered KISA scenarios, live registry refresh and externally anchored transparency/federation, TLS 1.3 RFC 9266 exporter support, external object-store/pre-signed multipart transport above the 64 MiB local slice with expiry, encryption, and tenant isolation, attested operational Provider diversity, severity calibration and multi-Reviewer/Human consensus, broader HTTP/RAG/Admin discovery adapters and Hypothesis/Observation rules, trusted new-Surface admission from follow-up observations, ranking and information-value scoring, parallel-safe and more-than-two-wave execution, Finding/report review UI, distributed Workers, external integrations, and independently anchored production evidence |

The primary operator interface remains CLI + YAML. Generic public-target attack automation,
external Bug Bounty or CTF submission, and production multi-tenant deployment are not implemented.

> **Validation status:** PAJIN currently implements trusted Candidate admission, semantic review,
> a Candidate-aware Provider contract that evaluates exact Candidate and Atomic Claim digests
> without rewriting Findings, deterministic validity/impact/severity Claim decomposition, objective
> evidence gates, sealed Decision snapshots, and a separate Blind Evidence Reviewer. The blind role
> receives only opaque validity/impact Claim identity, statements, and allowlisted evidence; it does
> not receive Candidate identity, disposition, severity, or prior Decisions. Deterministic
> reconciliation records `corroborated`, `contested`, or `inconclusive` without changing Candidate
> state or confirmation eligibility. An optional diverse-review registration places Blind Review
> and independent Severity Derivation on a separate Agent, Provider Tool, endpoint, model,
> Capability budget, and Secret Lease. Its severity Packet excludes the proposed label and all
> Candidate identity and prior-decision context; reconciliation is information-only and cannot
> rewrite Candidate severity. An opt-in M03/M06/A04 Control Executor now resolves only
> code-registered materializers and binds their ID, version, and scenario digest into Plan v1alpha2.
> It binds Baseline, Negative Control, and Counterfactual observations to the validity Claim using
> three unique sessions, three fresh non-delegable single-call Capabilities, and separate
> request/evidence/receipt lineage. Its
> deterministic reconciliation is information-only and cannot change disposition, severity, or
> confirmation eligibility. Versioned `ValidationPacket`,
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
> These artifacts prove Candidate binding, internal consistency, and receipt lineage, but not that
> the intended target executed independently of the Worker trust domain. The current Local, CLI,
> and Control Plane Worker-only paths therefore write `verified-replay-evidence` projections and
> keep supporting claims at `needs-review` with
> `independent-execution-attestation-missing`; they do not produce product Confirmed Findings. The
> KISA M6-05 retest path still requires a previously and independently attested Confirmed baseline.
> Negative target responses, including the public deterministic-lab tuple, remain `inconclusive`
> until a separately verifiable remediation authority exists. Positive observations may still show
> that an already trusted baseline is `still-vulnerable`. The local KISA paths atomically record
> ticket issuance context, `issued → claimed → finalized` transitions, and an event journal in a
> stable SQLite ledger outside individual sealed replay Runs. The `mode=ro` verifier compares the
> compilation, source root, replay Run, artifact digest, and final seal root even after the process
> restarts. See [ADR 0028](docs/adr/0028-durable-local-replay-ticket-ledger.md) for the detailed
> trust boundary.

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
- Product-level confirmation requires the objective gate, Candidate-bound replay, and an
  independently verifiable execution/target attestation. The repository does not currently have
  that last authority, so Worker-only evidence cannot exceed `needs-review`.
- A KISA `fixed` determination additionally requires independently verifiable remediation
  attestation. Exact bindings, successful repetitions, a negative transcript, Worker flags, and
  local receipts are necessary consistency checks but are not sufficient proof; current negative
  replay remains `inconclusive`.
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
  off-host attestation, or the PostgreSQL Control Plane replay authority. Consequently it is not
  product-level Confirmed/FIXED authority either.
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
  `{"replay-worker-service":["kisa-exact-v1"]}` grants that one profile only to the
  separately authenticated Replay Worker subject. Route authorization is symmetric: that Replay
  subject is rejected from every generic Worker route, while the generic Worker and every
  non-allowlisted subject are rejected from all Replay routes. Claim and heartbeat return a
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
  exist, because those exact historical context bytes cannot be backfilled. The dedicated
  `kisa-exact-v1` daemon now claims only that profile, heartbeats its fenced lease, obtains one
  durable server permit immediately before every Tool dispatch, and seals output into the exact
  opaque staging slot. It submits no path, ArtifactRef, result, digest, or verdict. Schema v9
  finalization imports the slot into the server-owned repository, independently reopens the seals,
  checks compilation/ticket/source/permit lineage, derives the common Gate decision, and atomically
  finalizes the output Artifact, ticket, Job, item, batch, Run, and audit state after revalidating
  the permit-backed authority whose budget/rate units were already consumed at issuance. Once
  any permit exists, execution failure is terminal and automatic same-ticket dispatch retry is
  forbidden. Exact response-loss retries of the identical ordinal-bound permit request and the
  identical server finalization request are idempotent; neither retries a Tool dispatch.
  Opaque public source/batch admission and role-scoped state-read APIs are implemented. When Replay
  claim polling finds no issued Job, the Control Plane may issue a pending retry only after rereading
  the immutable source, proving an unchanged Candidate/contract plan, finding no permit, confirming
  fully released budget/rate reservations, removing an empty prior staging capability, and checking
  the item remains below its maximum attempts. It preserves the abandoned Job/ticket/Run as history
  and appends a fresh Replay Run, compilation, execution context, reservations, one-shot Job, ticket,
  staging capability, attempt, and fence. Any permit, staged output, missing capability, authority
  mismatch, or exhausted attempt count fails closed; the same Job or ticket is never redispatched.
  Schema v11/v12 aggregate projection now covers both confirmation and exact dual-source negative
  Control Plane retest; exact Claim receipts can optionally carry portable Ed25519 proof. A separate
  executor workload key now attests the exact permit set and bounded portable Artifact bytes across
  hosts. A further opt-in binds each permit-derived challenge to a Target-issued Ed25519 receipt,
  the host-observed proxy exchange, and that executor signature. HTTPS CONNECT and leaf-SPKI,
  signed registry-v3 anti-rollback and bounded pin rotation, and registry-v4 TLS 1.2 dual-observer
  session binding complete that exact confirmation chain. TLS 1.3 RFC 9266 exporter support and
  large object-store/multipart transfer remain incomplete.
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

The optional server processes are installed as `pajin-control-plane`, `pajin-worker-daemon`, and
`pajin-replay-worker-daemon`.
Run `pajin --help` or `pajin <command> --help` for the authoritative option list.

## Run the vertical slice

```powershell
.venv\Scripts\pajin validate examples\ai-redteam.yaml
.venv\Scripts\pajin run examples\ai-redteam.yaml

# Explicit development/test-only execution
.venv\Scripts\pajin run examples\ai-redteam.yaml --worker simulated
```

`run` and `multi-run` default to the Docker Worker. The simulated backend must be selected
explicitly and exists only for deterministic development and unit tests; it is not an isolation
boundary and does not produce real-target evidence. Every Local and Multi-Agent Run seals the
actual backend identity in `execution-context.json`, duplicates it in `run.json` and the start
event, and renders it in the report. Simulated CLI output and reports carry an explicit
`SIMULATED / NOT REAL TARGET EVIDENCE` warning.

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

Compilation also requires the approval to be active at compilation time. A concrete asset using
the generic `generic-http` profile remains review-only until PAJIN implements a bounded probe
profile for it; mixed manifests fail instead of silently skipping that target. Review and Campaign
artifacts are atomically replaced only when the destination is absent or a regular file, and any
symbolic-link parent or leaf is rejected.

Evidence retention remains an explicit manual control. Duplicate triage can consume a typed local
snapshot, but synchronizing that snapshot with a platform or issue tracker remains manual.

### Finding triage and submission drafts

After a completed Bug Bounty Campaign has a sealed validation snapshot, compare its reportable
Candidates and Findings with a program-specific known-finding index and generate local review
drafts:

```powershell
.venv\Scripts\pajin bug-bounty-report `
  examples\bug-bounty-program.yaml `
  <completed-run-directory> `
  --known-findings examples\bug-bounty-known-findings.yaml
```

The reporter loads the exact sealed Candidate/Decision snapshot, including a complete versioned
projection when one exists. It rechecks that the Run used the current program digest and exact
compiled scope policy, accepts only declared targets, and requires every cited evidence file to be
sealed under that Run's `evidence/` directory. A partial, substituted, or authority-mismatched
snapshot fails closed. The reporter writes an immutable-input report set under:

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

When the program declares `duplicateCheckRequired: true`, omitting `--known-findings` is not treated
as an authoritative empty index: affected items receive `duplicate-check-not-performed`, remain
`needs-review`, and are not submission-eligible. Supplying a typed index with `findings: []` records
that the check was performed and found no known matches. A finding whose concrete target belongs
only to an asset with `eligibleForBounty: false` likewise remains `needs-review` regardless of its
other fields.

A Candidate whose exact Decision records successful objective and semantic checks but lacks
independent reproduction is retained as `semantic-review-only`. It receives
`independent-reproduction-not-confirmed`, remains `needs-review` with
`submissionEligible: false`, and may produce a clearly marked operator-review draft. Unsupported,
inconclusive, rejected, or authority-mismatched Candidate claims do not become drafts. Only a
Finding from a sealed `verified-independent-replay` projection can become `ready` and
submission-eligible; Worker-only replay evidence without independently verifiable target-execution
attestation remains review-only.

The generated Markdown is a local draft only. PAJIN does not submit to a Bug Bounty platform or
claim that local evidence has production-grade external attestation.

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
submits a report externally. Generic public Bug Bounty assets remain reviewable, but compilation
rejects them until a separately bounded executable probe profile is implemented.

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
Trusted M03, M06, and A04 Candidates can receive a sealed `verified-replay-evidence` projection
through separate replay Runs and the common Gate, but remain `needs-review` without independent
execution attestation. Other requested threats remain a
coverage gap or `needs-review` until an executable target-linked scenario and explicit replay
contract are added.

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

Run the registered B2.2 M03, M06, and A04 Control slice explicitly:

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-controls-lab.yaml `
  --worker docker --repetitions 2 --validation-controls
```

This adds three information-only calls per eligible Candidate after Replay. Baseline, Negative
Control, and Counterfactual each receive a fresh one-call Capability and distinct request, session,
evidence, and receipt. M03 and M06 use a benign `READY` Counterfactual; A04 replaces only the
first-turn poison write while preserving the second memory query. Their result cannot confirm or
mutate the Candidate. The bundled three-scenario example reserves exactly 33 calls: 6 source,
18 Claim Replay calls (validity, impact, and severity per Candidate), and 9 Controls.

The six Specialist Tasks use unique session IDs and cover system-prompt disclosure, jailbreak
policy bypass, and persistent memory poisoning. The lab binds only to `127.0.0.1:8765`, runs as a
non-root user with a read-only filesystem and no Linux capabilities, and is not a production AI
service.

A completed `kisa-run` additionally reproduces eligible trusted M03, M06, and A04 Candidates in
separate replay Runs. It gives each exact validity, impact, and severity Atomic Claim a separate
compiled execution authority, single-use ticket, fresh session, evidence, Oracle, and receipt.
The live KISA Oracles verify the Mode-owned Claim statement and recompute the exact catalog checks
from the raw transcript. Only validity drives product confirmation; impact and severity remain
information-only assessments. The source/replay link is written to `kisa-replay-index.json`. The
current Worker-only path keeps
`confirmationMutationApplied` at `false`. The common gate reloads the receipts and appends a sealed
`validation/v1alpha1` Decision/evidence/report projection with
`verified-replay-evidence` semantics; the original flat artifacts remain the immutable pre-replay
snapshot and no product Finding is added.

The local positive replay-ticket ledger is stored at
`<output>/replay/replay-tickets.sqlite3` under the selected output root. A new read-only verifier
can recheck the issued compilation, source root, replay Run, final artifact digest, and receipt seal
root after the execution process exits.

The explicit Local `pajin run --kisa-replay` path uses the separate
`<output>/local-replay/replay-tickets.sqlite3` ledger. A single writer in the same process creates
the source Run, Candidate, SQLite ticket, and separate replay Run in sequence, after which the
common Gate rereads the canonical receipt. The Gate does not modify the flat `findings.json`; it
extends only the `validation/v1alpha1/` projection with Candidate-bound evidence and the
`independent-execution-attestation-missing` reason.

```powershell
.venv\Scripts\pajin replay-verify <replay-run-directory> `
  --ledger <output>\replay\replay-tickets.sqlite3

.venv\Scripts\pajin replay-verify <local-replay-run-directory> `
  --ledger <output>\local-replay\replay-tickets.sqlite3
```

`replay-verify` does not create the ledger or change ticket state. Missing files, incomplete
tickets, or context, digest, Run, or seal mismatches fail closed.

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

`kisa-retest` consumes only baseline Findings that were independently attested before entering the
sealed `validation/v1alpha1` Confirmed projection. Current Worker-only baselines do not qualify. It
does not accept legacy flat Findings, semantic-only Candidates, or unconfirmed baselines as retest
criteria. The ordinary parent retest Run performs
normal-function probes and regression, while the baseline-bound Restricted Replay compiles each
baseline Candidate's original request, scenario, threat, Tool, and target unchanged and executes
them in a separate attack replay Run. Results from the two paths are recorded separately, but their
calls consume the same Campaign budget, rate limits, and cancellation boundary.

The retest Gate reopens the canonical receipt from disk and verifies bindings among the Candidate,
source Decision, versioned Finding, remediation action, baseline and retest Runs and seal roots,
original and replay requests, scenario, threat, Tool, and target. These checks do not independently
prove that remediation ran on the intended target. Negative Worker transcripts therefore remain
`inconclusive` even when every repetition matches the deterministic-lab response. A verified
`ReplayOracleVerdict.SUPPORTS` produces `still-vulnerable`; mixed support and contradiction,
insufficient repetitions, execution failure, cancellation, timeout, an unavailable target, or the
absence of explicit defensive evidence produces `inconclusive`. The existing positive Oracle
continues to treat zero support as `inconclusive` and does not claim `fixed` from only
`vulnerable=false` from the Worker or the mere absence of a signal. A binding or integrity mismatch
is not reduced to a status; it fails the command closed.

The exact registered defensive responses for the deterministic KISA Lab are public test fixtures,
not trusted remediation predicates. Matching those strings, model metadata, `safety.blocked`, or
the absence of `toolCalls`, `memoryWrites`, and compromise markers cannot mark either the lab or a
general target `fixed`; all such negative observations remain `inconclusive` without external
attestation.

Normal-function regression is evaluated independently of Finding status. The scope-limited
`kisa-retest` Exit Gate opens only when every baseline Finding is `fixed`, both
`still-vulnerable` and `inconclusive` counts are zero, no new Confirmed Findings were observed
during execution, and regression is `pass`. Any other result exits non-zero after sealing its
artifacts. The current Worker-only implementation cannot satisfy the `fixed` prerequisite; the Gate
remains closed until an external attestation path is implemented. This command closes the baseline
loop; it is not a full rescan for new threat types. To
claim the absence of new vulnerabilities, run a separate fresh `pajin kisa-run` discovery Gate.
That discovery also covers only the currently executable scenario scope; the remaining KISA
threats are still `not assessed`.

`kisa-plan-remediation` appends `remediation-plan.json` and an event and creates a new current root
without overwriting the versioned baseline projection or any existing seal entry. `kisa-retest`
binds this finalized root to every baseline-bound receipt; any later baseline change hard-fails.
The retest Run protects `remediation-plan.json`, `kisa-retest.json`, `kisa-retest-index.json`,
`kisa-checklist-overlay.json`, `kisa-retest-report.md`, and the baseline-bound replay/receipt lineage
with an append-only seal. The overlay supersedes only the five KISA items verified by evidence;
ownership, deadlines, and operational rollout remain human-review items.

Negative replay tickets record the same atomic state transitions and issuance context in the
`<output>/retest-replay/replay-tickets.sqlite3` ledger. The post-restart verification command is the
same as above, with this retest ledger path supplied to `--ledger`. This local ledger does not
replace the existing in-memory API's unit-test compatibility boundary, nor does it provide
PostgreSQL Control Plane replay or an externally verifiable signed proof.

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

### Provider-backed Planner, Validators, and Reporter

`provider-agent-run` connects the registered Provider Gateway to four default reasoning calls
without giving them offensive execution authority. Each role receives a distinct developer prompt, a
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

To place Blind Review and independent Severity Derivation behind a separate Provider/model boundary,
register all four review settings together:

```powershell
$env:PAJIN_PROVIDER_API_KEY='<primary-provider-secret>'
$env:PAJIN_REVIEW_PROVIDER_API_KEY='<review-provider-secret>'
.venv\Scripts\pajin provider-agent-run examples\provider-agent-lab.yaml `
  --review-provider-endpoint https://review-provider.example/v1 `
  --review-provider-id independent-review `
  --review-model review-model-v1 `
  --review-secret-env PAJIN_REVIEW_PROVIDER_API_KEY
```

The review Provider ID, endpoint, and model must all differ from the Primary registration. PAJIN
fails closed before execution if any value is equal.

The implemented flow is Provider Planner → isolated `ai.chat-probe` Specialist → trusted Candidate
Producer → Candidate-aware Provider Semantic Validator → Blind Evidence Reviewer → deterministic
reconciliation → objective gate → Provider Reporter. The
Validator receives immutable Candidate IDs, Candidate digests, and deterministic `validity`,
`impact`, and `severity` Atomic Claims. It returns only `supports`, `contradicts`, or `insufficient`
Claim Decisions with Candidate-owned evidence references; it does not recreate a Finding. The
validity Decision feeds the existing Candidate semantic gate, while impact and severity remain
separate sealed judgments and cannot mutate the Candidate. A second role receives only opaque
validity/impact Claim identity, statements, and allowlisted evidence. It cannot see Candidate
identity, disposition, severity, or the first review, and its result is reconciled as
`corroborated`, `contested`, or `inconclusive`. Blind-review failure seals as insufficient; neither
blind review nor reconciliation can mutate disposition or confirm a Finding. Product confirmation
still requires the Restricted Reproducer and independent execution attestation. Reporter output is stored separately
in `model-narrative.json` and is appended as a clearly subordinate section; it cannot alter
canonical findings or execution state.

With diverse review enabled, the Blind Reviewer and Severity Deriver share a dedicated reviewer
Agent and review Provider Capability that has no Primary Provider Tool authority. Severity Derivation
receives only an opaque severity Claim ID and the already minimized validity/optional impact Packets;
it does not receive the Candidate, proposed severity, disposition, Primary Decisions, or report
context. Its `corroborated`, `contested`, or `inconclusive` comparison is sealed in
`validator-output.json` v1alpha2 as an information-only signal. This local Provider/model distinction
is a configuration assertion, not cryptographic proof of separate organizations or infrastructure.

The exact Claim identity, evidence, fallback, blind-review, Control, and confirmation boundaries are recorded
in [ADR 0030](docs/adr/0030-candidate-aware-atomic-claim-validation.md),
[ADR 0031](docs/adr/0031-blind-evidence-review-boundary.md),
[ADR 0032](docs/adr/0032-fresh-capability-validation-controls.md),
[ADR 0033](docs/adr/0033-registered-validation-control-materializers.md), and
[ADR 0034](docs/adr/0034-diverse-independent-severity-review.md). Claim-bound replay lineage and
the public partial-validation projection are recorded in
[ADR 0035](docs/adr/0035-claim-replay-public-state-projection.md). Separate Claim execution
authority and KISA validity/impact/severity Oracles are recorded in
[ADR 0036](docs/adr/0036-claim-bound-replay-execution-authority.md).

`maxModelCalls` and `maxModelTokens` bound Campaign-side model usage independently, while
`maxCostUsd` applies registration-supplied per-million token rates to the same conservative
reservation. Provider-reported token usage and its derived reported cost are retained only as
untrusted audit observations; they neither reduce the Campaign enforcement charge nor settle an
external Provider invoice. Before dispatch, PAJIN reserves a conservative prompt bound: four tokens
for every canonical request UTF-8 byte, plus explicit base, per-message, per-tool,
per-assistant-tool-call, and response-format framing allowances. It also reserves the request's
declared `max_completion_tokens` and its configured maximum cost. Once dispatch is proven, success,
failure, cancellation, or missing, inconsistent, or above-reservation reported usage commits the
entire conservative reservation. Only proven non-execution releases it. A Campaign must therefore
budget enough `maxModelTokens` for at least one complete in-flight reservation. This is an internal
Campaign guard, not external billing reconciliation.

Provider failures, refusals, and schema errors retry at most twice before deterministic fallback.
Duration, Capability, token, and cost exhaustion never activate fallback and terminate the campaign
instead. Bearer-authenticated public Provider endpoints require HTTPS. Plain HTTP is accepted only
for fixed loopback/local-lab hosts with an explicit private-network opt-in; private Provider
destinations are denied unless `--allow-private-provider` is supplied. For billable Providers,
configure
`--input-cost-per-million` and `--output-cost-per-million` from the Provider's trusted pricing
configuration.

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

Schema v10 makes submission and lease authority durable across SQLite and PostgreSQL. A canonical
digest binds the authenticated actor, Campaign, input, idempotency key, Job kind, and retry limit;
an exact retry returns the existing Run, while any changed field fails closed. The v9-to-v10
forward migration reconstructs only an exact public submission graph and marks ambiguous legacy
Runs non-replayable. A separate Job digest binds the Job and Run IDs, kind, payload, retry limit,
and idempotency key; migration, startup validation, and claim all recompute that binding. Database
guards reject late v9 inserts, core-row delete/replace and identity rewrites, invalid lifecycle
transitions, terminal-history mutation, malformed JSON authority, and lease deadline extensions.
Each lease has an absolute server deadline no later than 24 hours after claim, heartbeats cannot
move that deadline, and audit heartbeat events are coalesced to at most one per 60 seconds while
lease renewal remains independently durable.

Mutation endpoints reject request bodies above 4 MiB before authentication or parsing. Submit
input, completion result, and checkpoint state then use operation-specific canonical JSON limits
(at most 1,000,000 UTF-8 bytes plus bounded depth, nodes, keys, key length, and string length).
Duplicate object names at any depth—including escaped spellings that decode to the same name—are
rejected as 422; a wire-size violation is 413. Persisted input, result, and checkpoint state are
owned snapshots, so caller mutation cannot alter stored authority, digests, or signatures.

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
$env:PAJIN_CP_WORKER_SUBJECT='worker-service'
$env:PAJIN_CP_REPLAY_WORKER_TOKEN='<distinct-random-replay-worker-token>'
$env:PAJIN_CP_REPLAY_WORKER_SUBJECT='replay-worker-service'
$env:PAJIN_CP_REPLAY_EXECUTOR_PROFILES='{"replay-worker-service":["kisa-exact-v1"]}'
$env:PAJIN_CP_CHECKPOINT_KEY='<random-signing-key-at-least-32-bytes>'
# Optional, required together only for portable_attestation batches:
$env:PAJIN_CP_REPLAY_ATTESTATION_KEY_ID='<active-key-id>'
$env:PAJIN_CP_REPLAY_ATTESTATION_PRIVATE_KEY='<base64url-raw-32-byte-ed25519-seed>'
$env:PAJIN_CP_REPLAY_ATTESTATION_TRUST_ANCHOR='<one-line-trust-anchor-json>'
# Optional B2.8a executor transport; the Control Plane receives public trust only:
$env:PAJIN_CP_EXECUTOR_ATTESTATION_TRUST_ANCHOR='<one-line-executor-trust-anchor-json>'
# Optional B2.8b target execution proof; the Control Plane receives public trust only:
$env:PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR='<one-line-target-trust-anchor-json>'
# B2.8d alternative for exact Target URLs; registry v2 HTTPS entries require a leaf SPKI pin:
$env:PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY='<one-line-versioned-target-registry-json>'
# B2.8e signed registry v3 alternative. Configure exactly one bundle source:
$env:PAJIN_CP_TARGET_ATTESTATION_REGISTRY_TRUST_ANCHOR='<one-line-registry-distribution-anchor-json>'
$env:PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE='<one-line-signed-registry-bundle-json>'
# Or, instead of the inline bundle:
# $env:PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_URL='https://registry.example/bundle.json'
# B2.8f: use a signed registry v4 HTTPS entry with
# "tls_session_binding":"tls-unique-sha256" and configure the lab Target:
# $env:PAJIN_TARGET_TLS_SESSION_BINDING='tls-unique-sha256'
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

When the executor signer and Control Plane public anchor are configured, Replay finalization carries
a content-addressed bundle instead of depending on a shared staging volume. This first transport is
bounded to 2 MiB raw total, 1 MiB per file, 256 files, and depth 24. The Control Plane verifies the
external signature before copying bytes and then reverifies the normal Run, receipt, and seals.
By itself this remains executor observation evidence and does not lift the `needs-review`
confirmation ceiling. B2.8b additionally configures the Target process with
`PAJIN_TARGET_ATTESTATION_KEY_ID`, `PAJIN_TARGET_ATTESTATION_PRIVATE_KEY`,
`PAJIN_TARGET_ATTESTATION_TRUST_DOMAIN`, `PAJIN_TARGET_ATTESTATION_ISSUER`, and
`PAJIN_TARGET_ATTESTATION_PROFILE`. Keep that private key out of the Control Plane. The Control
Plane receives only the matching anchor above and validates its key lifecycle.
For multiple Targets, configure the versioned registry instead of the single anchor. Routes are
canonical exact URLs with no wildcard or fallback. Registry v2 requires
`tls_leaf_spki_sha256` on each HTTPS entry. After normal PKIX and hostname validation, the Worker
observes the peer leaf SPKI digest; the Executor signs it with the opaque CONNECT route and Target
receipt, and the Control Plane rejects pin mismatches and TLS binding v1 downgrade. This does not
claim TLS session binding, revocation, or Certificate Transparency proof.
Registry v3 is accepted only inside a separately signed distribution bundle. Its sequence starts
at one and must bind the immediately preceding bundle digest. The append-only schema-v14 ledger
rejects rollback, gaps, and equivocation across restarts and replicas. A v3 HTTPS entry may include
one retiring pin with a deadline no more than 24 hours after bundle issuance; only receipts issued
before that deadline may use it. The inline bundle and HTTPS bundle URL are mutually exclusive,
and HTTPS fetch is redirect-free, bounded to 512 KiB, and performed once at startup. The development
Target can optionally enable TLS with `PAJIN_TARGET_TLS_CERTIFICATE` and
`PAJIN_TARGET_TLS_PRIVATE_KEY`. See
[ADR-0042](docs/adr/0042-worker-observed-tls-leaf-spki-binding.md) and
[ADR-0043](docs/adr/0043-signed-target-registry-distribution-and-rotation.md).
Registry v4 additionally requires `tls_session_binding: tls-unique-sha256` on every HTTPS route.
When the Target also sets `PAJIN_TARGET_TLS_SESSION_BINDING=tls-unique-sha256`, the lab caps TLS at
1.2 and signs the server-side channel-binding digest in receipt statement v2. The Worker records
the same connection's digest, and Executor TLS binding v3 seals it with the SPKI and CONNECT route.
The Control Plane rejects missing, downgraded, or cross-session evidence. See
[ADR-0044](docs/adr/0044-target-signed-tls-session-binding.md).

An Operator credential can use the public Replay admission surface:

- `POST /v1/replay/source-artifacts` accepts only an opaque staging ID plus completed producer
  Run/Job IDs and lets the server import the sealed source as a managed Artifact. A trusted producer
  must already have placed the sealed Run in the configured server-controlled staging handoff; this
  endpoint is not a file-upload or path-import API.
- `POST /v1/replay/batches` accepts the confirmed baseline's exact
  `(artifact_id, repository_version)` locator, an optional parent Retest locator, and an idempotency
  key. Omitting the parent selects confirmation; providing it derives baseline-bound
  `remediation-retest` Candidate, contract, and Replay compilation authority in the `planned`
  state. For confirmation only, explicit `claim_projection: true` derives separate validity,
  impact, and severity items for exact KISA M03/M06/A04 and publishes v3 Claim-specific projection
  authority plus `claim-replays.json`; it cannot be combined with a parent Retest locator.
  Adding `portable_attestation: true` selects policy `pajin.kisa-claim-attestation:v3` and seals an
  Ed25519 bundle over the complete Claim receipt authority. It fails closed unless all three
  attestation settings are present and mutually consistent.
  Adding `target_attestation: true` requires both Claim projection and portable attestation, selects
  `pajin.kisa-target-attestation:v4`, and requires a separately configured executor anchor plus
  either the legacy Target anchor or the versioned exact-URL registry. The Target receipt, host
  proxy observation, and executor proof must bind the exact permit-derived challenge before
  validity can reach `VERIFIED_INDEPENDENT_REPLAY`. HTTPS uses an opaque CONNECT route receipt plus
  the Target-signed application exchange.

Operator, Approver, and Auditor credentials can read
`GET /v1/replay/batches/{batch_id}`, `/items/{item_id}`, `/tickets/{ticket_id}`,
`/tickets/{ticket_id}/finalization`, `/batches/{batch_id}/projection`,
`/batches/{batch_id}/attestation`, and `/v1/replay/attestation/trust-anchor`. Responses omit staging
IDs, repository storage keys, and lease
tokens. This public surface never accepts a raw path or URL, caller-authored Candidate, contract,
Capability, Tool request, verdict, or internal Replay Job kind. First-attempt Job/ticket issuance
remains a trusted internal service operation, so public admission does not implicitly dispatch a
Tool.

The trust-anchor endpoint distributes public material but does not establish trust. Export and pin
the anchor through a separate administrative channel, then verify a downloaded bundle off-host:

```powershell
.venv\Scripts\pajin replay-attestation-verify .\bundle.json `
  --trust-anchor .\pinned-trust-anchor.json
```

Rotation marks the previous public key `retired` and adds exactly one new `active` key. A
`retired` key can verify historical bundles within its validity window; `revoked` keys always fail
closed. This proves that the selected Control Plane trust domain signed the exact Claim receipts,
not that an independent organization, Worker, or target executed or attested them.

SQLite is a local compatibility store, not a production multi-Worker queue. SQLite mutation
transactions take an immediate writer reservation so claim and completion state machines remain
serializable across processes; pure get/list operations use rollback-only snapshot reads and do not
take that writer reservation. Run the PostgreSQL lab on loopback instead:

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

These built-in adapters are explicit verification profiles, not real target or provider execution.
Their completed Job result includes `executionProfile` and the canonical `executionContext`; the
same context is sealed as `execution-context.json` and bound by `run.json` before completion is
accepted. The default profiles therefore report `simulated: true` and
`evidenceScope: simulated-development-only`. A Docker-backed adapter reports
`worker-observed-execution`, while any other custom backend remains
`custom-backend-unclassified` rather than being promoted to real-target evidence.

| Worker setting | Default and accepted range | Boundary |
| --- | --- | --- |
| `PAJIN_CP_URL` | HTTPS origin URL | Bearer-authenticated transport is HTTPS-only by default; credentials, paths, queries, fragments, malformed authorities, and non-HTTP(S) schemes are rejected |
| `PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB` | `false`; literal `true` only in the bundled Compose lab | Explicitly permits HTTP only for loopback or the `control-plane` Compose service name; never enable it for remote or production transport |
| `PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS` | 2 seconds; 0.05-30 | Cooperative return before the daemon calls `task.cancel()` |
| `PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS` | 5 seconds; 0.05-30 | Bounded wait after forced task cancellation and for each final drain |
| `PAJIN_DAEMON_STATUS_PATH` | `~/.pajin/status/worker-status.json` | Host default is below the user's non-shared home; custom parents must be daemon-owned and non-writable by group/others |

Server lease timestamps are conservatively anchored to the local monotonic request-start time. A
stalled heartbeat can never extend authority: at the local deadline both daemons cancel heartbeat
I/O, force executor quiescence without a grace delay, and reject stale finalization. Status updates
use the shared dirfd-anchored, exclusive-random-temp, fsync, atomic-replace writer.
The status writer and Tool Loop continuation-checkpoint writer require POSIX
dirfd/`O_NOFOLLOW` semantics; native Windows daemons fail closed before either write and must run
through the Linux container or WSL (PowerShell-driven Compose remains supported).

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

The Control Plane Compose stack starts PostgreSQL, the API, one generic non-root Worker daemon, and
the dedicated Replay daemon described in the next section:

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
$env:PAJIN_TEST_WORKER_CRASH_CONTAINER='pajin-control-plane-lab-worker-daemon-1'
.venv\Scripts\pytest -q tests/test_worker_daemon_crash_live.py
Remove-Item Env:PAJIN_TEST_WORKER_CRASH_CONTAINER
Remove-Item Env:PAJIN_TEST_CONTROL_PLANE_URL
```

Job delivery is at least once. A crash after an external Tool side effect but before durable
completion can replay that Tool, so production adapters must propagate destination idempotency keys
or make replay risk an explicit policy/approval decision. The generic daemon's Compose Run output
uses tmpfs and is not a durable evidence store. See
[`ADR 0012`](docs/adr/0012-lease-aware-worker-daemon.md).

### Dedicated Control Plane Replay Worker

`pajin-replay-worker-daemon` (equivalently,
`python -m pajin.control_plane.replay_worker_main`) is a separate, single-job daemon. It does not
register the generic Campaign or Tool Loop executors. Its authority flow is deliberately narrow:

1. claim only a server-issued `replay` Job whose authenticated Worker subject is allowlisted for
   exactly `kisa-exact-v1`, then heartbeat the ticket-bound lease and fence;
2. reconstruct the exact KISA Campaign/Scenario/Tool context from the canonical claim and request a
   durable, ordinal-bound Tool permit immediately before every Gateway dispatch;
3. write and twice seal the Replay Run only inside the server-reserved opaque staging slot; and
4. finalize with only profile, lease token, ticket, fence, and staging ID. The Control Plane imports
   that slot, reopens the immutable copy, verifies both seals and every permit/request binding,
   derives the common confirmation Gate, and atomically commits the Artifact and schema-v9
   append-only finalization after revalidating the permit-backed authority whose budget/rate units
   were already consumed at issuance. Finalized items remain `verified` until every batch item is
   ready; the server then copies—not mutates—the managed source, reopens all Replay Artifacts,
   creates a sealed `validation/v1alpha1` projection, and publishes schema-v11 projection authority
   only if the source root, batch CAS, and sorted finalization set are unchanged.

The Worker cannot submit a filesystem path, `ArtifactRef`, result, digest, Oracle verdict, or
`confirmed` disposition. A permit is durably consumed before dispatch and is not a bearer token. If
execution fails after any permit exists, the attempt is terminal and the same Job/ticket is not
automatically dispatched again; the external destination still provides no exactly-once guarantee
or rollback. Exact response-loss retries of an identical ordinal-bound permit request and the
server-side finalize request are idempotent; neither path redispatches a Tool.
The current executor is limited to the explicit M03, M06, and A04 `ai.chat-probe` confirmation
contracts, forbids Secret Leases, and uses one host's Docker daemon. The legacy path uses shared
POSIX staging; with the separate executor workload key configured, the bounded portable path signs
the exact permit set and sealed Run bytes from Worker-local staging and sends them to a Control
Plane on another host. It is not a generic Replay executor, negative-retest worker, target-issued
response proof, or large object-store transport.

The Compose lab now builds the fixed Tool Worker and egress-proxy images, starts an owner-only volume
initializer, the API, the generic daemon, and the dedicated Replay daemon. The API and Replay daemon
both run as `10001:10001` and share only `/var/lib/pajin/artifact-staging`; the managed repository
volume is mounted only into the API. The initializer requires both roots to be owned by that identity
and sets mode `0700`, failing closed on symlinks or invalid roots. Docker presents fresh named-volume
roots as root-owned, so this one-shot initializer runs as root with only `CHOWN`. It performs a
no-follow ownership handoff on each fixed mount path, opens and verifies the same inode, then applies
the private mode and final ownership through that descriptor before fsyncing and exiting. Every
long-running PAJIN service remains `10001:10001`. Named Artifact
volumes survive a normal restart but remain local-lab storage; `down --volumes` removes them.

The Replay daemon needs the Docker CLI and a read/write bind mount of `/var/run/docker.sock`. Set the
socket's group when the host does not expose it to group 0:

```bash
export PAJIN_DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
docker compose -f containers/compose.control-plane.yaml up --build --detach --wait
```

Before the Replay daemon starts, a networkless one-shot preflight runs with the same UID, socket
mount, and supplemental group. It must reach the Docker server and inspect both fixed images and the
configured proxy uplink; otherwise Compose blocks daemon startup. This validates the current lab
wiring but does not reduce the Docker socket's authority.

On Docker Desktop the lab default, supplemental group 0, commonly matches the VM socket. A Docker
socket is effectively host-root authority: the non-root UID, dropped capabilities, read-only root
filesystem, and `no-new-privileges` setting do not constrain what an authorized Docker API client can
start or mount. Do not expose this daemon to untrusted code or a remote unauthenticated daemon; use a
dedicated Docker host or a separately designed restricted broker in production. Bundled Compose
creates the dedicated `pajin-replay-uplink-lab` network; a different
`PAJIN_REPLAY_EXTERNAL_NETWORK` override must already exist. Only the proxy-image preflight and
per-execution egress proxies join that uplink; execution Workers remain on the per-call internal
network.

| Replay Worker setting | Compose value | Boundary |
| --- | --- | --- |
| `PAJIN_CP_URL`, `PAJIN_CP_REPLAY_WORKER_TOKEN` | HTTPS API origin and distinct Replay Worker secret | Required authenticated Replay transport; the token must differ from Operator, Approver, and generic Worker credentials; Replay and generic Worker routes reject each other's subjects; production requires managed secrets |
| `PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB` | `true` only in bundled Compose; default `false` | Narrow local-lab exception for `http://control-plane:8090`; remote HTTP remains rejected and production must use HTTPS |
| `PAJIN_REPLAY_WORKER_ID` | `pajin-compose-replay-worker-1` | Status identity only; the Bearer principal is the authorization identity |
| `PAJIN_REPLAY_EXECUTOR_PROFILE` | `kisa-exact-v1` | Literal-only, matching `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` |
| `PAJIN_REPLAY_STAGING_ROOT` | `/var/lib/pajin/artifact-staging` | Owner-only root; shared by the legacy path, or Worker-local when portable executor attestation is configured; claims carry only an opaque `stage_<uuid>` |
| `PAJIN_REPLAY_EXECUTOR_ATTESTATION_KEY_ID`, `PAJIN_REPLAY_EXECUTOR_ATTESTATION_PRIVATE_KEY`, `PAJIN_REPLAY_EXECUTOR_ATTESTATION_TRUST_ANCHOR`, `PAJIN_CP_EXECUTOR_ATTESTATION_TRUST_ANCHOR` | unset | All three Worker values are required together for the bounded portable transport; only the public anchor is configured on the Control Plane, and it must match the Worker key without exposing the private seed |
| `PAJIN_REPLAY_LEASE_SECONDS`, `PAJIN_REPLAY_HEARTBEAT_SECONDS`, `PAJIN_REPLAY_LONG_POLL_SECONDS` | 30, 5, 10 | Lease is 5-300 seconds; heartbeat must be less than half of it; long poll is at most 20 seconds |
| `PAJIN_REPLAY_IDLE_DELAY_SECONDS` | 0.2 | Bounds empty-queue polling between long polls |
| `PAJIN_REPLAY_RETRY_BASE_SECONDS`, `PAJIN_REPLAY_RETRY_MAX_SECONDS` | 0.25, 5 | Bounded identical permit/finalize response-loss backoff, never Tool redispatch authority |
| `PAJIN_REPLAY_FINALIZE_ATTEMPTS` | 3 | Exact finalize calls only; differing authority is a conflict |
| `PAJIN_REPLAY_CANCELLATION_GRACE_SECONDS`, `PAJIN_REPLAY_CANCELLATION_FORCE_SECONDS` | 2, 25 | Cooperative then forced drain; 25 seconds exceeds the Docker backend's 20-second cleanup cap |
| `PAJIN_REPLAY_STATUS_PATH`, `PAJIN_REPLAY_HEALTH_MAX_AGE_SECONDS` | `~/.pajin/status/replay-worker-status.json`, 30 | Host default uses a private parent; Compose explicitly uses its UID-owned mode-0750 tmpfs; health bounds input to 64 KiB and does not attest target success or physical quiescence |
| `PAJIN_REPLAY_DOCKER_EXECUTABLE`, `PAJIN_REPLAY_WORKER_IMAGE`, `PAJIN_REPLAY_EGRESS_PROXY_IMAGE`, `PAJIN_REPLAY_EXTERNAL_NETWORK` | pinned CLI path, two fixed `:dev` image names, `pajin-replay-uplink-lab` | Images are allowlisted and never pulled implicitly; bundled Compose creates the dedicated proxy uplink, while an override must be pre-created |

The Compose `stop_grace_period` is 65 seconds, exceeding the configured
`grace + (2 * force)` drain bound plus scheduling margin. `SIGKILL`, Docker-daemon loss, host loss,
or a blocking kernel operation can bypass in-process cleanup; lease fencing and conservative permit
consumption remain the authority boundary in those cases. See
[`ADR 0029`](docs/adr/0029-control-plane-replay-orchestration.md).

## Dynamic multi-agent engine

Run the deterministic five-role team through the default Docker Worker. Select the simulated
Worker only for explicit development or unit-test exercises:

```powershell
.venv\Scripts\pajin multi-run examples\multi-agent.yaml

# Explicit development/test-only execution
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker simulated
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
verdict fields. The exact Validator Agent/Task identity, Findings, and Candidate-bound assessments
are persisted as `validator-output.json` in the same sealed Run snapshot. Durable Control Plane
derivation reloads that artifact and replays the gate; it never reconstructs semantic support from
the Candidate itself. This semantic authority binding does not establish independent reproduction,
product confirmation, or remediation. A semantic Validator that returns no Finding therefore leaves a
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
.venv\Scripts\pajin multi-cancel-check examples\multi-agent-cancel.yaml --worker docker
```

For operator-driven runs, `multi-run` also accepts `--kill-file <path>`. Creating that file activates
the one-way Kill Switch, cancels the active operation, marks pending graph tasks as cancelled,
revokes the complete Capability lineage, and records the reason. Docker cancellation forcibly
removes the running container and any per-execution egress resources.

## Docker Worker

Build both development images directly from their checked-in, hash-locked inputs:

```powershell
docker build --tag pajin-worker:dev containers/worker
docker build --tag pajin-egress-proxy:dev containers/egress-proxy
docker build --tag pajin-ai-target:dev containers/ai-target
```

`containers/worker/requirements.lock` pins the MCP v1 SDK and every transitive dependency with
distribution hashes. `containers/ai-target/requirements.lock` does the same for the Target receipt
signer's cryptography runtime. Their Dockerfiles install those locks with `--require-hashes` and
`--only-binary`, so a generated or ignored `vendor/` tree is not required. All checked-in
Dockerfiles also pin their base image by multi-platform manifest digest. The build downloads the
selected binary wheels from the configured package index unless they are already cached; hash
locking makes it reproducible but does not make it an offline build.

After an intentional change to either container input, refresh its checked-in lock:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/prepare-worker-dependencies.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/prepare-ai-target-dependencies.ps1
```

The script performs a marker-preserving universal resolution. Linux Docker builds ignore the
non-Linux branches while amd64 and arm64 use the same checked-in hash lock. It updates only the
lock and does not create a vendor tree.

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

The target-lab and host-facing Control Plane/PostgreSQL networks are ordinary Docker bridges so
their loopback-published ports remain usable. They segment service attachment but do not deny
container outbound traffic; production deployment needs host firewall or equivalent egress
controls in addition to PAJIN's per-execution proxy boundary.

The Worker is attached only to a per-execution `--internal` network. The dedicated proxy is attached
to that network and the external Docker bridge, validates the destination again after DNS
resolution, and records allow/deny decisions in the execution evidence. HTTP paths and methods are
enforced directly. HTTPS uses CONNECT, so the proxy enforces only authority-wide rules: only
host-wide allows are accepted and any deny rule for that authority rejects the entire tunnel. The
exact encrypted method and path remain bound to the Gateway-selected fixed Worker action, not proxy
inspection. CONNECT events state `receiptEligible=false`,
`methodEnforcement=trusted-worker-only`, and `pathEnforcement=authority-only`; they are not HTTP
request/response receipts. Policy input and response buffering are bounded, and the fixed 64 MiB
proxy rejects configured response limits above 8 MiB before execution rather than relying on OOM.

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
  claim-replays.json    # exact validity/impact/severity Claim ↔ replay lineage and outcome
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

`kisa-retest` uses the same receipt loader and Restricted Reproducer boundary, but for a distinct
confirmation purpose. It does not reinterpret normal-function results from the parent retest Run as
negative proof; only separate replay Runs bound to sealed baseline Candidates determine `fixed` or
`still-vulnerable`. The retest assessment includes the baseline and remediation lineage, replay
Run, Outcome, request and evidence IDs, Oracle verdict, and receipt-seal lineage. The versioned
projection and existing baseline seal entries are immutable, and the current root finalized after
the remediation plan is appended is bound to the retest receipt.

The Candidate and Decision snapshots preserve every Finding returned by the legacy Validator and
every observation admitted by an enabled trusted Candidate Producer, together with its
deterministic disposition. `validation-index.json` is an ID-only status view, while the legacy
flat `findings.json` remains the immutable pre-replay compatibility snapshot. New consumers prefer
the sealed `validation/v1alpha1/index.json`, whose Decision, Finding, and Markdown artifacts include
the confirmation basis, superseded source Decision, replay Run/Outcome, request IDs, artifact digest,
and receipt-seal lineage. Historical flat confirmations are read as legacy and are never promoted to
the reproduction-backed projection. New projections also seal `claim-replays.json`, binding each
replayed Candidate's exact validity, impact, and severity Claim ID and digest to its own Replay Run,
Outcome, request, evidence, Oracle, and receipt lineage. The KISA path rejects incomplete Claim
coverage or cross-Claim receipt substitution. Only validity controls the internal confirmation
Decision; impact and severity are information-only. The index exposes a separate public state map:
`partially-confirmed` means a Claim was reproduced but the full confirmation invariant was not
satisfied, while `not-reproduced` requires a successful typed Oracle contradiction. Neither state
enters `findings.json`; failed, cancelled, timed-out, unavailable, or inconclusive execution remains
`inconclusive`. The current trusted producer is limited to exact KISA AI chat
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

The SHA-pinned [Linux CI workflow](.github/workflows/ci.yml) installs the locked dependency set and
runs Ruff, mypy, and the complete default pytest suite on Ubuntu 24.04 with Python 3.12 for every
pull request and push to `main`.

The default suite keeps live infrastructure tests environment-gated. Set
`PAJIN_TEST_CONTROL_PLANE_URL` for the Control Plane and Worker-daemon live tests, and
`PAJIN_TEST_POSTGRES_URL` for the isolated PostgreSQL integration test. The Worker crash-recovery
test additionally requires `PAJIN_TEST_WORKER_CRASH_CONTAINER` naming its isolated test container.
Docker smoke checks and Mode Pack labs require a running Docker daemon and the documented local
images or Compose fixtures.

## Architecture rule

`ProviderAgentRuntime` is the governed production path for network-backed planning and validation.
It binds every model call to `PolicyBoundProviderPort`, the Tool Gateway, Campaign budgets, and
run-scoped Secret Leases. `PydanticAIAgentRuntime` is limited to PydanticAI's exact local
`TestModel` for deterministic tests and rejects model names, general models, and subclasses before
Agent construction. Every MCP, CLI, browser, sandbox, and network-backed model call must cross its
PAJIN policy boundary.

See the [live product roadmap in Notion](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a),
the [documentation index](docs/README.md),
the [KISA traceability matrix](docs/KISA_TRACEABILITY.md), and the complete
[ADR decision record](docs/adr/). Selected implementation decisions are
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
