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

MEM-001 realizes the first part without adding a record type: an existing
`CampaignFactProposal` reaches the existing Graph Admission Authority only after an additive
adapter verifies its exact sealed Campaign, Run, current root, and evidence digests. The resulting
`GraphAdmissionEvent` and admitted `CampaignFact` are the record. Producer and full request/
Capability lineage remain separate Graph gates, and Fact text grants no command, prompt relay,
Scope, or execution authority.

MEM-002 realizes the artifact-reference part as a non-authoritative projection over existing
`GraphEvidence` and `RunStore` seal records. The content-addressed reference binds one Campaign,
Evidence node, source Run/current root, normalized path, SHA-256, media type, and bounded size.
Verification returns no bytes or filesystem path and does not imply Graph admission, receiver
authority, prompt relay, Scope, Capability, or execution authority. Snapshot membership remains
MEM-003 work and receiver-bound content access remains HANDOFF-004 work.

MEM-003 realizes the minimal team-state projection without another ledger. It resolves one exact
current GRAPH-003 Snapshot, derives every admitted Campaign Fact reference, and admits only
MEM-002 Artifact references whose complete Evidence nodes are members of that projection. The
collaboration wire contains references rather than Fact or Artifact content, is invalidated by an
advancing Graph head, and grants no sender, receiver, read, prompt, Scope, Capability, or execution
authority.

HANDOFF-001 adds the first receiver context without message passing. A process-local Supervisor
admits one enum-purpose transition from an existing completed Agent/Task to a distinct dependent
waiting Agent/Task, bound to the exact current MEM-003 identity. It carries no content or command
and grants no read, Scope, Capability, Permit, or execution authority.

HANDOFF-002 records the bounded terminal outcome of that destination without creating a result
content store. It resolves the historical HANDOFF-001 admission, proves a later current MEM-003
Snapshot belongs to the same contiguous Graph Snapshot chain, reverifies one exact MEM-002 sealed
Artifact member, and derives success, failure, or cancellation from the existing terminal Agent/Task
lifecycle pair. Lifecycle success is not Finding confirmation, and the record grants no read,
prompt, Scope, Capability, Permit, or execution authority.

HANDOFF-003 adds a non-executing urgent decision over that exact terminal-result Snapshot. A
code-owned policy accepts one trusted-core or operator Observation only when the current Graph
proves its Action production, exact result-Evidence support edge, and sealed Artifact value digest.
The sole disposition is `stop-and-escalate`, bounded to one Observation, one decision, and one local
budget unit per handoff. It is admitted but not automatically applied and grants no replanning,
Scope, Capability, Permit, or execution authority.

HANDOFF-004 permits one bounded in-process content delivery without introducing a content store.
It requires an existing delegated `maxCalls=1` Capability Grant for the exact terminal receiver,
Campaign, read tool, and Shared Artifact, then consumes that Grant lineage and uses the sealed Run
loader. The current Snapshot and urgent-stop state are checked before and after the read. Delivery
is limited to 60 seconds and 64 KiB; the receipt contains no bytes or path and grants no prompt,
Scope, Capability, Permit, or execution authority.

The Phase 5 exit regression composes MEM-001 through HANDOFF-004 with an admitted prompt-shaped Fact
and prompt-shaped Artifact payload. Wires retain references and false authority markers rather than
commands. Independently valid cross-Run, cross-Campaign, Snapshot/source, and Capability-ledger
substitutions fail before Grant consumption or byte delivery; the required urgent authority cannot
be omitted from reader construction.

## 8. Compatibility and migration

1. Existing `CampaignMode`, manifests, CLI commands, API routes, and Artifact schemas are not
   deleted immediately.
2. An adapter first compiles legacy Mode inputs into Campaign Profiles.
3. Common-engine and legacy paths run the same fixtures to prove policy and result parity.
4. Capability and Graph features connect one opt-in or feature-flagged vertical slice at a time.
5. A failed parity or negative test rolls back by disabling the adapter and retaining the legacy
   Mode path.
6. Directory moves occur only after consumers migrate and parity is proven.

ENG-001 implements the first migration checkpoint as a non-executable, content-addressed contract
over the shared `MultiAgentCampaignRunner` boundary. It binds each legacy Campaign and source Mode
to the registered boundary while fixing Profile, MissionEnvelope, parity evidence, and Common
Engine execution authority to false. This checkpoint does not change a legacy default path; the
Profile and compatibility adapters remain subsequent Phase 1 work. See
[ADR-0101](../adr/0101-register-common-engine-boundary-before-profile-activation.md) and the
[ENG-001 contract](../orchestration/ENG-001-common-campaign-engine-contract.md).

PROF-001 adds the next non-executable checkpoint: four code-owned Profile identities bind their
operating, reporting, benchmark-expectation, and restrictive control semantics to the ENG-001
contract. Profile resolution does not select a Profile for a Campaign; all compatibility,
MissionEnvelope, measurement, submission, and execution authority remains false. See
[ADR-0102](../adr/0102-separate-profile-semantics-from-campaign-compilation.md) and the
[PROF-001 contract](../orchestration/PROF-001-campaign-profile-authority.md).

PROF-002 adds deterministic direct-call compatibility compilation for the three current legacy
Modes. It preserves the complete Campaign as input and emits only an exact PROF-001 semantic
projection, with compiler/catalog/Profile and input/output digests in one portable audit authority.
It applies no ROE default, never auto-selects pentest, and keeps Envelope and execution authority
false. See [ADR-0103](../adr/0103-compile-legacy-modes-to-profile-semantics-only.md) and the
[PROF-002 contract](../orchestration/PROF-002-legacy-mode-profile-compatibility.md).

ENG-002A registers exact Mode-specific Planner/Validator identities and the shared runner,
scheduler, and projector before runtime parity. Adapter selection records all four required parity
dimensions, but its evidence is structural identity only: fixture measurement, parity proof,
runtime construction, Envelope compilation, and Common execution remain false. See
[ADR-0104](../adr/0104-register-implementation-identity-before-runtime-parity.md) and the
[ENG-002A contract](../orchestration/ENG-002A-common-engine-implementation-adapter.md).

ENG-002B1 measures the first behavioral subset: legacy-direct and Profile adapter Planners receive
the same Campaign and typed constructor inputs, then compare the complete Plan after replacing only
fresh step/request identities with ordered fixture ordinals. Scope and ToolRequest Planner parity
are proven, while Capability, Worker receipt, Outcome, Envelope, Common runtime, and execution
remain unmeasured or false. See [ADR-0105](../adr/0105-measure-planner-parity-before-runtime-parity.md)
and the [ENG-002B1 contract](../orchestration/ENG-002B1-common-engine-planner-fixture-parity.md).

ENG-002B2A constructs the exact runtime coordinate for both paths and executes two independent
completed sealed Runs. ToolSpec and Tool implementation context, Policy, Worker, Validator, AI
candidate producer, runner, and semantic output role must match, while Run/request/evidence
identities remain disjoint. The resulting authority is source evidence only: behavioral parity,
Envelope compilation, and Common execution remain false until Capability, receipt, Outcome, and
Mode post-processing are normalized and compared. See
[ADR-0106](../adr/0106-seal-dual-runtime-sources-before-behavioral-parity.md) and the
[ENG-002B2A contract](../orchestration/ENG-002B2A-common-engine-dual-runtime-fixture.md).

ENG-002B2B runs the existing Mode processors over both exact B2A roots and compares normalized
Scope, Capability attenuation, ToolRequest, Policy/Worker receipt, Outcome, and Mode artifact
semantics. Only typed fresh identities, allowlisted execution timestamps, and schema-defined sets
are canonicalized; missing evidence and all remaining drift fail closed. The result admits the
Profile adapter for the measured fixture but does not compile a MissionEnvelope or authorize
Common execution. See
[ADR-0107](../adr/0107-admit-parity-only-from-sealed-semantic-behavior.md) and the
[ENG-002B2B contract](../orchestration/ENG-002B2B-common-engine-behavioral-parity.md).

ENG-002C1 compiles the existing GRAPH-006 MissionEnvelope from the intersection of the exact
PROF-002 compilation embedded in B2B, successful trusted measured receipts, verified CAP-005
activations, and source Campaign ceilings. It narrows Capability, target, count/unit/rate, risk,
and time authority to the measured Plan and rejects recurring testing-window semantics that the
Envelope cannot preserve. This checkpoint issues no Permit and authorizes no Common dispatch or
execution. See
[ADR-0108](../adr/0108-compile-mission-authority-by-predecessor-intersection.md) and the
[ENG-002C1 contract](../orchestration/ENG-002C1-parity-bound-mission-envelope-compilation.md).

ENG-002C2 leaves the C1 compiler's execution flags false and activates a separate code-owned gate
compiler whose MissionEnvelope differs only by compiler identity. A fresh deterministic request
intent, exact latest Graph Decision, current signed activation, and Capability Grant must intersect
before the existing GRAPH-006 Permit transaction and CAP-005 Gateway dispatcher are called. The
gate is explicit module-only wiring; exact retry does not redispatch and no legacy default changes.
See [ADR-0109](../adr/0109-activate-common-execution-with-a-separate-compiler.md) and the
[ENG-002C2 contract](../orchestration/ENG-002C2-explicit-common-execution-gate.md).

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
authority. WALK-005C2 reopens that C1 baseline and accepts only another B2 authority approved and executed
after confirmation with the exact same Plan and Claim but seven fresh execution identities. It
binds both publication roots and emits only a sealed `still-vulnerable` assessment, with fixed
eligibility false, remediation application unattested, and regression not measured. Failed or
negative evidence is not converted into remediation success. WALK-006 Shadow Supervisor recording
adds a separate snapshot-only, code-registered policy over the sealed C2 lifecycle. It records a
human-only remediation-review Task with no Capability and an autonomous Stop/escalation Decision,
while fixing the result to shadow-only, baseline-unmodified, and not applied. It does not activate
the existing execution Supervisor or claim Phase 6 model binding and benchmark gates. Measured
BENCH-003 baseline-versus-Shadow comparison remains separate. BENCH-003A first binds the exact
WALK-006 publication to a baseline-only BENCH-001 Manifest and records only a structural terminal
Decision delta. It preserves the ordered twelve-metric contract but supplies no values or deltas,
and fixes canonical BenchmarkComparison and Supervisor activation eligibility to false.

SUP-001 begins Phase 6 without invoking a model. It binds the exact Campaign Profile/Common Engine
contract, Supervisor role, WALK-006 policy, secret-free Provider/model identity with immutable
revision, bounded structured-output configuration, and code-owned Walking/Collaboration input plus
untrusted proposal output schema digests. The binding requires exact consumer-side runtime
verification, contains no prompt or Tool request, and fixes model invocation, Capability, Permit,
execution, and activation eligibility to false. SUP-002 and SUP-003 now add the actual Snapshot
taint projection and typed proposal compiler without changing those false authority markers.

SUP-002 materializes the first such input from one exact current MEM-003 Snapshot. It reopens the
Graph only through the existing Snapshot store, projects every admitted Fact statement with exact
origin and digest provenance, conservatively retains agent- and target-derived text as target
tainted, and keeps Artifact bytes behind their reader as content-free tainted references. Complete
membership, current head, SUP-001 schema, and runtime identity are exact; no prompt, model call,
draft, proposal, Capability, Permit, execution, or activation is created.

SUP-003 re-verifies that complete current input and accepts only an exact source-Snapshot-bound
SUP-001 draft. A separate code-owned compiler policy pins the actual `SupervisorSnapshotInput`
wrapper schema, the draft schema, the typed output schema, and the exact ordered four-kind
allowlist. The output contains only code-owned Task, Replan, Stop, or escalation advisory literals;
Snapshot text and model rationale remain digest-only sources. Provider response, model output,
scheduling, Plan or TaskGraph mutation, Scope expansion, Stop application, notification,
Capability, Permit, execution, and activation are all false. This compiler schema binding does not
authorize a model call; the actual invocation request must be versioned and bound before SUP-004
can invoke a Provider.

SUP-004A closes the pre-invocation half of that gap without pretending a Provider ran. It rebuilds
the current SUP-002 input when its canonical JSON fits the existing 65,536-character Provider
message bound, resolves the exact current Graph checkpoint, constructs the fixed developer plus
canonical Snapshot user request, and binds ordered content digests, exact request/schema digests,
Provider/model/configuration identity, and a conservative usage bound. A dedicated
call/token/time/cost ceiling must be narrower than the Campaign, but affordability is not usage and
no budget is reserved. One process-local scheduler exact-idempotently seals the digest-only plan in
a separate Run. Model invocation, receipt, Task/Plan mutation, Scope, Capability, Permit,
execution, and activation remain false. SUP-004B must atomically enforce Campaign and Supervisor
budgets while returning a bound request/Gateway/Provider receipt before any draft reaches SUP-003.

SUP-004B1 supplies the atomic process-local budget half of that runtime boundary. Each Campaign
usage ledger owns a reentrant lock, and the dual model budget acquires the Campaign and dedicated
locks in stable order before checking or changing either. Provider dispatch success or uncertainty
commits the same conservative call/token/cost bound to both; only proven non-execution releases
both. Existing Campaign-only Provider sessions are unchanged. Stable Provider request identity,
secret-free bound outcome, durable at-most-once claim, and the sealed Supervisor draft receipt are
separate SUP-004B2/B3 boundaries.

SUP-004B2 supplies the stable request and successful outcome half. An additive Provider API puts
one caller-owned portable ID into the actual Gateway `ToolRequest` and returns the ephemeral raw
Provider result separately from a content-addressed secret-free projection. One shared canonical
request digest and domain-separated component digests bind the exact registration, grant, chat,
Tool request, Policy decision, Tool and successful Worker results, Gateway outcome, Provider
result, evidence reference, reported usage, and conservative Campaign or dual charge. Prompt,
response, Tool arguments, endpoint, secret reference, and Worker transcripts are not projection
fields; the pre-existing sensitive Gateway evidence artifact is unchanged. Existing Provider calls
are unchanged, and all Task/Plan/Scope/Capability/Permit/execution authority remains false. The
Gateway reservation is still Run-local; SUP-004B3 must claim the
intent durably and seal the exact Supervisor request/outcome/draft receipt before SUP-003 sees a
model-backed draft.

SUP-004B3 closes that durable admission boundary with one strict host-local SQLite journal and one
dedicated two-seal Provider Run. The journal binds the exact current checkpoint to a deterministic
stable request ID and preplanned Run, records dispatch-started before any Provider-side operation,
and never returns automatic redispatch authority. Recovery can finalize only an already complete
sealed receipt. The first seal freezes the Gateway reservation, sensitive evidence, and runtime
event prefix; the second adds the complete B2 outcome, strict untrusted draft, receipt, and audit
event. The public consumer re-verifies the current schedule, terminal journal, both seals, all raw
Provider/Gateway sources, and Campaign-and-dedicated charge before passing the draft directly to
SUP-003. This is a single-host journal and process-local budget boundary, not distributed
exactly-once execution or durable ledger reconstruction, and all mutation, execution, redispatch,
and activation authority remains false.

SUP-005A adds the first source-bound bridge from that actual B3 proposal to BENCH-003B2 while
explicitly refusing causal metric attribution. Both predecessors are reopened through their
existing readers, their exact Run/root/artifact and shared WALK-006 policy lineage are bound, and
only the content-free SUP-003 proposal is copied. BENCH-003 metric values remain in their original
authority. Because B3 still has no Manifest arm, seed, repetition, or `BenchmarkTargetCoordinate`,
the new state is `structural-source-bound-not-model-measured`; model-backed comparison, threshold
evaluation, execution, and activation remain false. SUP-005B must bind those coordinates before
dispatch and admit B3-backed observations before reusing the canonical numeric Comparison.

SUP-005B1 closes the request-lineage half of that boundary. It derives a fresh two-arm Manifest
from the exact structural baseline, binds the static model-backed implementation, complete
arm/seed/repetition set, and one sealed SUP-004A schedule per candidate coordinate in a
non-dispatch Plan. A typed Plan/coordinate assertion is stored in explicit B3 intent/receipt
`v1alpha2` wires and contributes to the stable ID used by the actual Gateway ToolRequest. The
benchmark candidate verifier independently reloads the Plan, predecessor sources, journal,
two-seal receipt, and SUP-003 proposal. Legacy context-free B3 remains `v1alpha1`. No numeric value
or causal effect is admitted; SUP-005B2 still requires externally adjudicated registry-governed
observations for both arms before the existing BENCH-003B1 Comparison can be reused.

SUP-005B2 closes the measured-source half. The Target adapter invokes the exact context-bound B3
candidate inside its signed execution interval and commits a typed relation over the Plan,
coordinate, journal, Provider receipt/outcome, proposal, and raw Target evidence into the execution
receipt's provider-evidence digest. Existing measurement attestation, registry admission, and
Harness authorities bind that relation transitively. After every Plan coordinate re-verifies, the
unchanged BENCH-003B1 runner alone aggregates the externally adjudicated Observations and seals the
two Results and canonical Comparison. The additive Supervisor authority records only source
lineage; proposal causality, threshold eligibility, execution, and activation remain false.

SUP-006 treats prompt injection as an authority-containment regression rather than a claim that a
model will ignore hostile text. The same role-injection, taint-downgrade, Scope, ToolRequest,
Capability, Permit, execution, threshold, and activation corpus crosses the target-tainted Snapshot,
fixed no-Tool Provider request, B3 receipt, content-free typed proposal, sealed benchmark Plan, and
externally measured Comparison. Raw Provider output must use only the camelCase aliases advertised
by its strict JSON Schema. Schema-valid hostile rationale is retained only in its untrusted draft
receipt and becomes digest-only in the typed proposal and final measurement lineage. Invalid output
remains outcome-unknown and non-retriable; cross-Plan publication replay fails closed. No threshold,
activation, Permit, or execution authority is introduced.

PERMIT-001 introduces a separate `GeneralAttackActionProposal` before deterministic action
compilation. It does not widen the existing GRAPH-006 `ActionProposal`, which remains the
Permit-adjacent request binding. The new predecessor exact-matches the current Campaign, ORCH-001
Surface Snapshot carrying the complete Campaign digest, Plan, Task, Hypothesis, Target, and one
registry-resolved CAP-001 definition.
Action identity, risk, expected evidence, side-effect, and cleanup metadata come from that static
definition; target, method, and arguments come from the exact code-owned Plan. SUP-003 output is not
accepted as lineage without its complete external-verification sources. The Target reference keeps
only the endpoint digest, while exact ORCH arguments remain inert data. No request identity,
`ToolRequest`, activated Capability, Grant, Permit, compiler call, dispatch, or execution authority
is created. PERMIT-002 must perform the first deterministic request compilation, and PERMIT-003
must reuse GRAPH-006 atomic single-use Permit consumption.

PERMIT-002 exact-rebuilds that predecessor and resolves one caller-supplied complete CAP-002
authority-set reference. It invokes only the registered Materializer and Action Compiler, derives
a fresh request identity from the source proposal and selected authority digests, and requires both
the materialized arguments and the compiled request to equal code-owned source semantics as
canonical JSON bytes. It re-resolves the complete seven-role set after both calls, rejecting JSON
scalar-type substitution and cross-role identity drift before publishing output. CAP-002 resolution
uses two consecutive full observations, rejects identity mutation during stable-context capture,
and ends with a context-free declared-identity sweep. Registered context providers remain
side-effect-free code-owned trusted computing-base components, not sandboxed untrusted code.
The additive `GeneralAttackCompiledIntent` binds the complete predecessor, authority-set and role
bindings, canonical `ToolRequest`, Gateway request digest, normalized-parameter digest, and Target
digest. It remains `compiled-not-permitted`: release, activation, Grant, Envelope, Graph Decision,
reservation, GRAPH proposal, Permit, dispatch, and execution are absent and false. PERMIT-003 must
intersect the current intent with those later authorities before using GRAPH-006.

PERMIT-003 performs that intersection as a direct-call bridge without defining another execution
wire. It exact-rebuilds PERMIT-002, matches one current signed CAP-005 activation by complete
code-backed identity, and re-runs the existing CAP-002 preparation path. Because no generic
general-attack Envelope producer, Decision provenance registry, or pricing service exists yet, an
injected external input authority must authenticate one pre-existing run-level MissionEnvelope,
the current action-proposal Decision and actor, and a trusted strict-integer fixed-point cost. The
provider receives canonical deep-detached predecessor copies so it cannot mutate the gate-owned
intent, prepared action, Campaign, or Definition. The bridge independently requires current
Campaign authorization/testing window and attenuates Envelope duration, autonomy, risk, Tool-call,
cost, and rolling-rate ceilings. It derives request units from the activated Definition,
revalidates activation after the external call, and requires the exact Capability, Target,
Decision payload, and Envelope budget. It derives only the existing
GRAPH-006 ActionProposal and uses the existing SQLite atomic Permit authority and first-consumption
dispatcher. A Campaign-aware final claim clock checks authorization and testing-window currency at
the same time used by SQLite. Only an async callback is accepted before claim. One gate pins one
Envelope and activation set; exact retry never calls the consumer twice, while stale Graph and
cross-Envelope request replay fail in the existing transaction. No default workflow, Gateway,
Worker, Oracle, cleanup, or execution path is added; PERMIT-004 and SUP-007 retain those boundaries.

BENCH-003B1 next admits only complete sealed raw observations from one exact measurement authority
over both arms and every Manifest seed/repetition coordinate. It deterministically aggregates all
twelve metrics, seals two completed Results and the canonical numeric Comparison, and still fixes
Supervisor activation eligibility to false. The external producer remains the semantic measurement
trust root. BENCH-003B2 exact WALK-006 policy/configuration and source-publication binding is an
additive final layer: it preserves B1 values, requires the measured Manifest envelope and
baseline arm to equal A, binds the adaptive candidate implementation ID/version/configuration
digest to the exact sealed WALK-006 policy, and retains activation eligibility false. P0-C1 through
P0-C2B2B now provide the lifecycle, attestation, registry governance, and first live local Docker
Target adapter; broader Target Factory families remain future work.
P0-C1 establishes the provider-neutral boundary for that work: exact Manifest coordinates drive
ordered reset, isolation, execution, and cleanup receipts; foreign evidence is rejected before
further dispatch; cleanup remains mandatory after a valid isolation; and an external Ed25519
measurement signature binds every receipt plus the final B1-compatible Observation in one sealed
Run. The deterministic adapter remains a contract fixture; P0-C2 supplies durable recovery, key
governance, and the first real local Docker provider.
P0-C2A adds the provider-neutral crash boundary: every operation carries an idempotency ID and
monotonic fence, intent is durably journaled before dispatch, open attempts are reconciled before
new work, cleanup has a bounded retry, and the exact recovery journal is sealed as a
measurement-ineligible failure authority. This is additive to P0-C1 and does not convert recovery
evidence into benchmark metrics. The local provider implementation and measurement-key governance
are completed by P0-C2B.
P0-C2B1 introduces that Benchmark-specific key lifecycle as an additive out-of-band registry.
Fresh measurement requires the active key before reset, retired keys are historical-only, and
revoked keys invalidate all verification. Contiguous registry revisions and exact predecessor
digests prevent a caller from silently skipping transition validation inside sealed admission. The
admission binds the source Run/root/artifact/signature without changing P0-C1 or BENCH-003B wire
formats. Signed durable registry distribution and mandatory governed admission are supplied by
P0-C2B2A1/A2; P0-C2B2B supplies the live local provider boundary.
P0-C2B2A1 signs the complete registry transition under a separate Benchmark distribution authority
and persists accepted bundles in an append-only SQLite activation checkpoint. Revision-one-only
bootstrap and exact durable-head comparison reject restart rollback, gaps, equivocation, and
predecessor substitution. P0-C2B2A2 binds that activation to mandatory sealed Harness admission.
P0-C2B2A2 closes that integration gap with a mandatory registry-governed Harness. It activates the
signed bundle before reset, then binds the exact activation, Target Run, and registry Admission Run
in one sealed authority. Only its reader returns a governed Observation after reopening all sources,
checking the durable exact revision, and applying the current distribution Trust Anchor.

P0-C2B2B completes the first concrete provider slice for the fixed synthetic Bug Bounty
Boolean-SQLi lab. A content-addressed profile binds exact Target and Worker image IDs and an
internal Docker bridge. Provider-owned SQLite state enforces operation idempotency, stage order,
and monotonic fences, while a separate SQLite operation lock prevents a live lower-fence mutation
from racing higher-fence cleanup on the same host. The adapter verifies non-root, read-only,
capability-dropped containers, no published ports, actual network probe semantics, final resource
absence, and receipt-bound provider evidence. It integrates with the existing registry-governed
Harness without changing earlier wire contracts. Cross-host providers and the broader P0-D Target
Factory families remain future work.

P0-D1 establishes the first Target catalog boundary without generalizing that provider. The public
registration carries the exact profile/factory/provider identities, empty mutation allowlist,
network policy, and only a private Ground Truth digest. A separate private binding retains the
complete seeded case and code-owned matcher identity. The additive catalog wrapper validates the
Manifest, adapter, Docker profile, catalog, and private binding before provider mutation and checks
receipt-bound execution evidence plus registered counts before returning the Observation. Catalog
selection remains content-addressed but non-executable; registry activation and governed Harness
admission retain their existing authority.

P0-D2 adds the walking File Upload/RAG/MCP authorization chain as a second catalogued family while
preserving its actual fixture boundary. The profile binds exact WALK-002/003/005A/005B2/005C1
contract versions and a private seeded chain matcher, but declares contract-only availability,
untrusted network evidence, no provider execution authorization, and no measurement eligibility.
It creates neither a Target adapter nor a Benchmark Observation; runnable AI/RAG/MCP measurement
still requires a separate P0-C lifecycle implementation.

P0-D2B supplies that lifecycle as a separate local-Docker profile rather than revising the
contract-only fixture. It reuses the P0-C2B2B durable fence, resource hardening, receipt evidence,
and cleanup machinery through fixed scenario hooks. A synthetic Target exposes document upload,
deterministic RAG query, and MCP HTTP boundaries on one internal-only container; a fixed Worker
performs the real network chain and the host independently validates exact decoded bodies and
hashes. The runnable catalog binds the adapter and image IDs to the private seeded chain. This is a
zero-model-call benchmark and not a claim of separate MCP deployment or production RAG behavior.

P0-D3 records an ordered structural composition of the exact Traditional Web/API and local
AI/RAG/MCP selections. A content-addressed bridge declares the intended synthetic SQLi-output-to-
document-upload flow but remains `declared-not-executed`. Private component Ground Truth stays out
of the public composition and is re-bound during final selection. Because the current Manifest and
provider lifecycle each name one Factory, P0-D3 creates no combined Factory, Manifest, receipt,
Observation, metric, or execution authority. Runnable Hybrid measurement requires a coordinated
multi-provider lifecycle and explicit transfer evidence in a successor contract.

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
