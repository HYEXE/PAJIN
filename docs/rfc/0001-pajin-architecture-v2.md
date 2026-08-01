# ARCH-001: PAJIN Architecture v2

- Status: Accepted
- Date: 2026-07-26
- Code baseline: `main@a4d0582`
- Implementation status: Phase 0 contract in progress

## 1. Purpose

PAJIN will transition incrementally from Mode-specific silos to:

1. one policy-governed common attack engine;
2. Campaign Profiles that define operating rules and result semantics;
3. code-registered, version-pinned Capabilities;
4. a Canonical Graph and append-only Event Log connecting exploration across surfaces; and
5. an optional Bounded Supervisor that can propose work only from a verified snapshot.

AI remains a first-class Capability domain with distinct prompt, RAG, memory, and tool-authorization
surfaces. It no longer defines the entire product as one AI-red-team Mode.

## 2. Baseline and problem

The current code already provides valuable safety assets:

- Campaign authorization, Scope, Rules of Engagement, and budgets;
- attenuating `CapabilityGrant` lineage and mandatory Policy/Tool Gateway evaluation;
- isolated Workers and registered Tool execution;
- Candidate preservation, Atomic Claims, Blind Review, independent Replay, and Confirmation;
- append-only Control Plane projections, portable receipts, and execution attestation; and
- bounded A3-A5 discovery with at most two execution waves.

However, `ai-redteam`, `bug-bounty`, and `ctf` each own parts of execution, discovery, and reporting.
That prevents a common cross-surface attack chain. The A5 observation snapshot supports a limited
follow-up plan, but it is not canonical campaign memory shared by every Specialist. Dynamic
Specialist creation and post-wave result merging do not provide peer-to-peer messaging or an
admitted shared-fact store.

## 3. Accepted invariants

| ID | Invariant |
| --- | --- |
| I-01 | Every execution is bounded by a Capability and Permit issued within Campaign authority. |
| I-02 | Exploration is auditable and every confirmed Finding is independently reproducible. |
| I-03 | Migration uses a strangler approach and avoids large rename-only changes. |
| I-04 | Discovery, Agents, and Supervisors cannot expand Scope, risk, budget, or Capability. |
| I-05 | One Graph Admission Authority is the only canonical graph writer. |
| I-06 | The Supervisor is optional, emits proposals only, and is never an authority root. |

Existing Policy, Capability, Worker isolation, Evidence, Validation, and Replay boundaries remain
the foundation of the common engine.

## 4. Target architecture

```text
legacy Mode/API input
        |
        v
Campaign Profile Adapter ---> MissionEnvelope
                                  |
registered Capability <-----------+
                                  v
                          Common Attack Engine
                                  |
Specialist/Supervisor ---> typed Proposal
                                  |
                 deterministic Compiler + Policy Gate
                                  |
                                  v
                      single-use ActionPermit
                                  |
                                  v
                         Worker / Tool Gateway
                                  |
                                  v
                Observation/Evidence/Fact Proposal
                                  |
                                  v
                 single Graph Admission Authority
                                  |
                   append-only Canonical Event Log
                                  |
                    Graph Projection + Snapshot
```

A Campaign Profile expresses operating semantics such as pentest, bug bounty, AI red team, or CTF.
It adds no authority. It is an input to compiling Campaign authorization into a `MissionEnvelope`.
The existing `ai-redteam`, `bug-bounty`, and `ctf` values and current CLI/API remain supported as
compatibility inputs throughout migration.

## 5. Minimum Canonical Graph

Only the following vocabulary is canonical before Phase 3.

### 5.1 Nodes

| Node | Meaning |
| --- | --- |
| `Surface` | An observable, testable attack surface |
| `Hypothesis` | A proposition to test against a Surface |
| `Action` | A Permit-authorized executed operation |
| `Observation` | A result from an Action or trusted import |
| `Evidence` | Preserved material supporting an Observation |
| `CampaignFact` | A shared campaign fact with provenance and validation state |

### 5.2 Edges

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports/contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

`Asset`, `Identity`, `Session`, `CredentialHandle`, `PrivilegeState`, `TrustBoundary`,
`DataObject`, `DataFlow`, `Pivot`, `Candidate`, and `Finding` are added only when benchmarks or a
walking skeleton prove that they are necessary.

### 5.3 Write path

```text
Specialist
-> ObservationProposal / SurfaceProposal / CampaignFactProposal
-> Admission Queue
-> single Graph Admission Authority
-> Append-only Canonical Event Log
-> Graph Projection
-> Immutable Checkpoint Snapshot
-> Supervisor or deterministic Planner
```

- Agents never write the canonical graph directly.
- A Proposal is bound to campaign, run, agent, task, request, and evidence lineage.
- Retrying the same proposal digest is idempotent.
- Reusing an ID with another digest is rejected as equivocation.
- Contradictory Observations coexist; neither silently overwrites the other.
- A Snapshot has a revision and canonical digest, and every consuming decision binds both.
- If the graph revision changes after a decision, execution re-verifies the decision first.

The Canonical Graph is distinct from the existing `TaskGraph`: the latter models execution
dependencies, while the former models admitted campaign knowledge and provenance.

## 6. Bounded Supervisor

The Supervisor is not activated before the Minimum Graph and benchmark exist. It later starts in
`shadow` mode and must pass an explicit activation gate.

Its inputs are limited to a verified Mission, immutable snapshot, admitted facts/artifacts, and
remaining budget. Its outputs are typed proposals such as `TaskAssignmentProposal`,
`ReplanProposal`, `VetoProposal`, and `EscalationRequest`.

The Supervisor cannot:

- expand Scope, risk tier, budget, rate, Capability, or egress;
- create credentials or receive secret material directly;
- execute an unregistered Capability or arbitrary shell command;
- confirm a Finding or bypass validation/replay gates; or
- write the Canonical Graph directly.

It runs only at defined checkpoints, not on every Tool call. Disabling it must retain a minimum
deterministic planner path.

## 7. B2.9 reinterpretation

Structured collaboration memory is not a separate free-form Collaboration Store.

- shared facts are admitted `CampaignFact` nodes;
- handoffs are projections bound to a snapshot and lineage; and
- team state is a Snapshot projection rebuilt from the Canonical Event Log.

B2.9 facts/snapshot/handoff therefore become Graph/Event-Log projections, never a second authority
ledger.

## 8. Compatibility and migration

1. Existing `CampaignMode`, manifests, CLI commands, API routes, and Artifact schemas are not
   deleted immediately.
2. An adapter first compiles legacy Mode inputs into Campaign Profiles.
3. Common-engine and legacy paths run the same fixtures to prove policy and result parity.
4. Capability and Graph features connect one opt-in or feature-flagged vertical slice at a time.
5. A failed parity or negative test rolls back by disabling the adapter and retaining the legacy
   Mode path.
6. Directory moves occur only after consumers migrate and parity is proven.

CTF can be represented as a Profile/benchmark, while its existing fixed-lab validator boundary
remains. Existing Target-signed lab attestation and the B2.8g local multipart work are not
Architecture v2 prerequisites; they are reused where operational value is demonstrated.

## 9. Delivery order

1. **P0-A Architecture Contract**
   - this ARCH-001 RFC;
   - ADR-0046 Common Engine + Campaign Profiles;
   - ADR-0047 MissionEnvelope + ActionPermit Algebra; and
   - ADR-0048 Minimum Graph + Admission Consistency.
2. **P0-B Benchmark Contract**
   - BENCH-001 benchmark manifest/result schema;
   - deterministic target factory and core metrics.
3. **Phase 1**
   - legacy Mode-to-Profile adapter;
   - common-engine walking parity.
4. **Phase 2**
   - Versioned Capability Registry and deterministic proposal compiler.
5. **Phase 3**
   - GRAPH-001 model;
   - GRAPH-002 admission/event-log spike;
   - projection, revision, snapshot, and stale-decision tests; and
   - durable Graph Store plus atomic consumed ActionPermit dispatch claims.
6. **Phase 4**
   - first hybrid web-and-AI walking skeleton.
7. **Phase 5 and later**
   - B2.9 projections;
   - Supervisor shadow, evaluation, and bounded activation.

The initial storage choice left open by this RFC is resolved by
[ADR-0049](../adr/0049-durable-single-campaign-sqlite-graph-store.md): the first backend is a
separate, single-Campaign SQLite Graph Store rather than an extension of the one-Run `RunStore`.
It passes the ADR-0048 durable conformance slice while preserving the same storage-neutral
protocols for a future Control Plane/PostgreSQL adapter. The final revision check and consumed
dispatch claim are specified by
[ADR-0050](../adr/0050-consumed-action-permit-dispatch-claim.md) and
[GRAPH-006](../graph/GRAPH-006-atomic-action-permit-authority.md).
The first Phase 2 versioned Capability contract is specified by
[ADR-0051](../adr/0051-versioned-capability-definition-and-tool-binding.md) and
[CAP-001](../capability/CAP-001-versioned-capability-definition.md) through exact ToolSpec
binding, a definition digest, and a Registry with no latest-version fallback.
The Phase 2 code-backed authority boundary is specified by
[ADR-0052](../adr/0052-code-backed-capability-authority-set.md) and
[CAP-002](../capability/CAP-002-metadata-code-backed-authority-interfaces.md) through an exact
seven-role authority set, explicit stable-context digests, and identity-checking wrappers.
The Capability authoring foundation is specified by
[ADR-0053](../adr/0053-inert-deterministic-capability-scaffolds.md) and
[CAP-003](../capability/CAP-003-capability-authoring-sdk-scaffold.md) through a strict-JSON spec,
inert abstract role templates, deterministic artifact digests, and a write-once scaffold CLI.
The signed lifecycle boundary is specified by
[ADR-0054](../adr/0054-signed-reviewed-capability-lifecycle.md) and
[CAP-004](../capability/CAP-004-maturity-signing-review-deprecation.md) through exact Ed25519
publisher/reviewer authority, immutable predecessor chains, conservative maturity transitions, and
profile-specific activation.
The existing-mode compatibility boundary is specified by
[ADR-0055](../adr/0055-explicit-existing-mode-capability-adapters.md) and
[CAP-005](../capability/CAP-005-existing-mode-tool-replay-adapters.md) through a closed seven-item
inventory, exact Tool and scenario contracts, independently recomputed semantic Oracles, and a
non-executable binding to the existing KISA M03/M06/A04 fresh-session Replay path. Registration is
explicit, every definition remains experimental, and existing runtimes are not replaced.
The Phase 2 measurement boundary is specified by
[ADR-0056](../adr/0056-external-denominator-capability-metrics.md) and
[CAP-006](../capability/CAP-006-registry-quality-metrics.md). It measures exact external scope,
lead time, Oracle, Replay, and signed lifecycle evidence without deriving its denominator from the
Registry or inventing zero-valued results for missing samples. Its CAP-005 baseline records
implemented structure and explicit evidence gaps; it does not activate the adapters or complete
the Web + AI runtime exit gate.
The closed CAP-005 inventory also provides seven exact benchmark mappings and an opt-in rollout
verifier that accepts only a complete externally reviewed seven-release CAP-004 set. The verifier
binds full signed-bundle and mapping digests but creates no signing authority and does not treat
test fixtures as operational releases. An additive opt-in bridge now selects an explicit signed
release subset, compiles exact CAP-002 requests, exposes only that subset to GRAPH-006, and invokes
the existing Tool Gateway from the first-consumption callback. A sealed exit-gate verifier now
rebuilds CAP-006 from source hashes present in one integrity-verified Run and requires exact
successful Web + AI `claimed → completed` lifecycles with sealed Gateway evidence. The local
fixture closes the structural admission gate only; an organization-issued release set and actual
isolated Campaign run remain required to produce the production runtime exit-gate artifact.
The Worker bridge also seals a deployment/Run anchor before the Permit claim and reconciles the two
non-atomic crash windows without redispatch: no `claimed` event is
`consumed-without-claim`, while a lone `claimed` event is `claimed-outcome-unknown`. Incomplete
states are content-addressed to the consumed Permit and the earliest seal covering their evidence,
recorded once, and require manual review.
Real child-process hard exits now cover the Permit-commit/no-claim boundary, the
claimed-append/pre-Gateway boundary, and the durable external-side-effect/pre-terminal boundary.
Restart preserves one consumed Permit, records one reconciliation, and never invokes the retry
Worker.
The single-Campaign Graph Store now also emits a content-addressed backup manifest, verifies the
full Event/Node/Projection/Snapshot/Permit state before backup and restore, restores only to a new
path, and has subprocess hard-exit coverage for committed, uncommitted, and backup-publication
boundaries. An additive retained format encrypts that verified database with externally supplied
AES-256-GCM key material and signs a canonical ciphertext statement with an external Ed25519 key.
A detached fresh-process drill verifies signature, AEAD, plaintext identity, and complete logical
state before a new-path restore. A transport-neutral backend contract now binds put-if-absent
publication, version-pinned reads, requested object-lock receipts, and a signed cumulative
inventory to an external anti-rollback anchor. The local backend proves only that contract; actual
provider transport/scheduling, independent-host drills, managed key services, authoritative
object-lock evidence, and independent anchor persistence remain deployment work.
The first unified-discovery boundary is specified by
[ADR-0059](../adr/0059-versioned-discovery-adapter-authority.md) and
[DISC-001](../discovery/DISC-001-versioned-discovery-adapter-registry.md). It introduces a
code-owned common adapter protocol, immutable exact-version references, full Tool and stable
execution-context binding, and live drift detection. Registry-backed Surface admission records
the exact adapter reference and any trusted-network-receipt requirement, while existing Scope,
Authorization, sealed-evidence, and Tool-risk gates remain authoritative. DISC-002 now provides
the first HTTP/OpenAPI adapter over exact bounded `HTTPGetTool` evidence. Admission replays its
host-trusted Worker HTTP receipt before extraction. The adapter preserves OpenAPI path parameters
and content types in non-executable `http-route` locators, accepts same-origin inline JSON only,
performs no `$ref` or YAML expansion, and reuses Campaign Scope and method admission before
publication. DISC-003A now adds a separate exact-version OpenAPI authentication adapter whose
non-executable locator preserves route-bound scheme identities, OR/AND requirements, declared
scope names, and optional anonymous access. Authentication URLs and material are neither retained
nor fetched, and the nested route reuses DISC-002 admission authority. DISC-003B adds a cumulative
exact-version file-upload adapter for direct raw binary/base64 bodies and multipart file fields.
It preserves only route-bound shape and declared media types, resolves no `$ref`, retains no file
bytes or destinations, and reuses the same route admission. DISC-003C adds a cumulative
exact-version RAG adapter that reads only versioned operation-level `x-pajin-rag` declarations,
preserves route-bound corpus/index identifiers and boundary type, performs no prose/schema
inference, and retains no corpus content, queries, retrieved chunks, embeddings, vectors, or
destinations. DISC-003D adds a separate registered MCP discovery Tool and exact adapter. Its fixed
Worker action accepts only a sealed server ID, performs bounded capability-aware pagination, and
publishes non-executable server/resource/resource-template/prompt/tool Surfaces containing only
portable names, required flags, URI schemes, protocol/capability identity, and SHA-256 schema or
URI digests. It does not retain descriptions, raw schemas/URIs, resource content, prompt content
or values, server process commands, or discovered execution authority. One argument-free Planner
uses the existing sealed single-Recon-wave path. ORCH-001 now adds an immutable revision-1 Surface
Snapshot authority and additive Plan/Task digests over its exact projection/source roots, sealed
artifact SHA-256, Surface Set, Hypothesis authority, and complete Specialist steps. The dynamic
Hypothesis runner reconstructs that binding before capability issuance and every Tool dispatch,
while existing Discovery Hypothesis v1alpha1 wire shapes remain unchanged. ORCH-002 now extends
the A5 control path to an exact two- or three-wave deterministic authority. It binds the complete
Campaign, ORCH-001 Snapshot, Compiler states, Observation rules, and transitions; selects only
from the current wave's admitted Observations; binds every wave's ORCH-001 Plan digest into the
append-only graph; and stops repeated state or `A -> B -> A` cycles before another dispatch.
WALK-001 now adds the first Phase 4 executable segment: one Campaign-bound HTTP Recon request is
bound to the exact DISC-003B adapter and must admit an `http-file-upload` Surface before an
immutable projection can be published. It performs no upload and grants no route authority.
WALK-002 adds an exact DISC-003C Recon plan requiring upload and explicit RAG Surfaces, then binds
a deterministic H-17 RAG-injection Hypothesis to the complete Campaign digest, ORCH-001 Snapshot,
registered rule, and co-located `corpus-ingest` plus file-upload Surface identities and locators.
The Hypothesis is persisted in a separate sealed Run with fixed `not-authorized` state and creates
no Tool request, Capability, payload, corpus write, or Worker dispatch. WALK-003 adds a separate
exact DISC-003D Recon Snapshot and binds its MCP server/tool Surface, input-schema digest, immutable
Capability definition, registered local/remote Tool identity, independent-user-approval rule, and
the complete sealed WALK-002 lineage into a content-addressed `registered-not-authorized`
Hypothesis. It creates no activation, Grant, Permit, request, argument, or Worker dispatch.
WALK-004 re-verifies that sealed authority, admits only its exact state as a content-addressed
Observation, and selects a `proposed-not-authorized` independent-approval request Plan. Its immutable
Graph records typed support, enablement, and dependency edges; expected-state and bounded-history
checks reject stale, repeated, or cyclic state, while complete Campaign, Snapshot, Capability, rule,
and approval bindings prevent authority expansion. It creates no activation, approval receipt,
Permit, request, argument, or dispatch. WALK-005A now reopens that sealed Plan plus a separate
execution Run and admits an unconfirmed Candidate only when an explicit approval receipt binds the
exact canonical CapabilityGrant and precedes a consumed ActionPermit claim, claimed and terminal
audit events bind that same Grant digest, the existing reconciliation path proves a completed
Gateway lifecycle, and sealed target output explicitly reports missing independent authorization enforcement and
internal-data access. It reuses deterministic Atomic Claims but creates no semantic decision,
ReplayOutcome, confirmation, report eligibility, or Retest result. The default demo inspector does
not synthesize these target observables. WALK-005B1 now reopens that sealed Candidate authority and
binds its exact validity Claim, original execution/request semantics, and seven mandatory freshness
identities into a content-addressed `planned-not-authorized` MCP Replay Plan. It creates no approval,
Grant, Permit, request, ticket, dispatch, ReplayOutcome, or confirmation, and does not relabel the
Candidate as an implemented KISA Replay scenario. WALK-005B2 adds a separate Plan-bound approval
receipt that must be sealed before the fresh Permit's dispatch claim, reuses the exact WALK-005A
Gateway verifier, rejects reuse of all seven original execution identities, and requires exact
request semantics plus a freshly derived matching validity Claim statement. Its sealed public
projection is only `reproduced` with confirmation eligibility fixed to false. Multi-adapter
scheduling remains separate future work. WALK-005C1 then applies an MCP-specific confirmation
policy: only the Plan-bound fresh validity replay drives product confirmation, while impact and
severity remain source-bound information-only. It seals the validated Finding, typed report and
exact Markdown rendering, and a `planned-not-applied` remediation baseline without inventing KISA
ReplayOutcome, Oracle, ticket, external-host attestation, remediation application, or Retest
authority. WALK-005C2 baseline-bound remediation Retest remains separate future work.

## 10. Definition of Done

Each vertical slice requires:

- code, schema, tests, README/plan/ADR aligned in the same change;
- Ruff, strict mypy, focused/full pytest, and Linux CI;
- negative tests for authority expansion, duplicate, contradiction, stale snapshot, and race;
- canonical digests and audit events for material decisions and admissions;
- reproducible execution from a clean clone;
- benchmark results and regression metrics; and
- updated repository plan/handoff state, compatibility, migration, and rollback boundaries.

Current priority and remaining milestone work are maintained in the root
[repository plan](../../PLAN.md). The Git baseline, verification state, and next executable action
are maintained in the root [handoff](../../HANDOFF.md).

## 11. Related decisions

- [ADR-0046: Common Engine and Campaign Profiles](../adr/0046-common-engine-and-campaign-profiles.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](../adr/0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0048: Minimum Graph and Admission Consistency](../adr/0048-minimum-graph-and-admission-consistency.md)
- [ADR-0049: Durable Single-Campaign SQLite Graph Store](../adr/0049-durable-single-campaign-sqlite-graph-store.md)
- [ADR-0050: Consumed ActionPermit Dispatch Claim](../adr/0050-consumed-action-permit-dispatch-claim.md)
- [ADR-0051: Versioned Capability Definition and Tool Binding](../adr/0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052: Code-backed Capability Authority Set](../adr/0052-code-backed-capability-authority-set.md)
- [ADR-0053: Inert Deterministic Capability Scaffolds](../adr/0053-inert-deterministic-capability-scaffolds.md)
- [ADR-0054: Signed Reviewed Capability Lifecycle](../adr/0054-signed-reviewed-capability-lifecycle.md)
- [ADR-0055: Explicit Existing Mode Capability Adapters](../adr/0055-explicit-existing-mode-capability-adapters.md)
- [ADR-0057: Signed and Encrypted Graph Backup Retention Objects](../adr/0057-signed-encrypted-graph-backup-retention.md)
- [ADR-0058: Immutable Graph Backup Repository and Anti-Rollback Inventory](../adr/0058-immutable-graph-backup-repository-inventory.md)
- [ADR-0059: Versioned Discovery Adapter Authority](../adr/0059-versioned-discovery-adapter-authority.md)
- [ADR-0060: Bounded HTTP and OpenAPI Route Discovery](../adr/0060-bounded-http-openapi-route-discovery.md)
- [ADR-0061: Bounded OpenAPI Authentication Boundary Discovery](../adr/0061-bounded-openapi-authentication-boundary-discovery.md)
- [ADR-0062: Bounded OpenAPI File Upload Boundary Discovery](../adr/0062-bounded-openapi-file-upload-boundary-discovery.md)
- [ADR-0063: Bounded Explicit RAG Boundary Discovery](../adr/0063-bounded-explicit-rag-boundary-discovery.md)
- [ADR-0068: Snapshot-Bound RAG Injection Hypothesis](../adr/0068-snapshot-bound-rag-injection-hypothesis.md)
- [ADR-0064: Bounded Registered MCP Boundary Discovery](../adr/0064-bounded-registered-mcp-boundary-discovery.md)
- [ADR-0065: Surface Snapshot-Bound Orchestration](../adr/0065-surface-snapshot-bound-orchestration.md)
- [ADR-0066: Deterministic Two-to-Three-Wave Orchestration](../adr/0066-deterministic-two-three-wave-orchestration.md)
- [ADR-0067: File Upload Surface Walking Slice](../adr/0067-file-upload-surface-walking-slice.md)
- [ADR-0069: Snapshot-Bound MCP Tool Authorization Hypothesis](../adr/0069-snapshot-bound-mcp-tool-authorization-hypothesis.md)
- [ADR-0071: Evidence-Bound Walking Observation Replan](../adr/0071-evidence-bound-walking-observation-replan.md)
