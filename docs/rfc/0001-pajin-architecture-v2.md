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
The single-Campaign Graph Store now also emits a content-addressed backup manifest, verifies the
full Event/Node/Projection/Snapshot/Permit state before backup and restore, restores only to a new
path, and has subprocess hard-exit coverage for committed, uncommitted, and backup-publication
boundaries. This remains host-local self-consistency rather than signed off-host disaster recovery.

## 10. Definition of Done

Each vertical slice requires:

- code, schema, tests, README/plan/ADR aligned in the same change;
- Ruff, strict mypy, focused/full pytest, and Linux CI;
- negative tests for authority expansion, duplicate, contradiction, stale snapshot, and race;
- canonical digests and audit events for material decisions and admissions;
- reproducible execution from a clean clone;
- benchmark results and regression metrics; and
- updated Notion status, compatibility, migration, and rollback boundaries.

Current Git baseline, verification state, and remaining milestone work are maintained in the
[PAJIN Notion roadmap](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a).

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
