# PERMIT-001: General Attack Action Proposal

- Status: Implemented
- Contract version: `pajin.dev/general-attack-action-proposal/v1alpha1`
- Decision: [ADR-0128](../adr/0128-bind-general-attack-semantics-before-action-compilation.md)

## Scope

PERMIT-001 adds a content-addressed predecessor to the existing GRAPH-006 `ActionProposal`. It
records complete general attack semantics before a deterministic action compiler creates a
`ToolRequest`, execution-ready GRAPH proposal, Capability grant, or Permit.

The predecessor is named `GeneralAttackActionProposal` to avoid colliding with the established
`pajin.graph.ActionProposal`. The latter remains the Permit-adjacent object consumed by the
GRAPH-006 authority and is unchanged.

## Trusted inputs and derivation

`build_general_attack_action_proposal()` accepts only canonical existing authorities:

1. the current `CampaignManifest` and its complete canonical digest;
2. one ORCH-001 `SurfaceBoundPlan` whose `SurfaceSnapshotAuthority` carries that exact Campaign
   digest after sealed Recon Campaign/Plan revalidation, plus one task digest;
3. the matching `AttackHypothesisSet` and Hypothesis;
4. one exact `CapabilityDefinitionRef` resolved through the immutable definition registry.

Action meaning is derived from code-owned sources, never model text:

- action kind, version, evidence types, side-effect class, cleanup requirement, and risk tier come
  from the exact registered Capability definition;
- target identity comes from the Hypothesis and is reopened from the current Campaign;
- target endpoint is checked against deny-first Campaign Scope, while the Target reference retains
  only its SHA-256 digest;
- method and arguments come from the exact ORCH task and enter the action-semantics digest; and
- Supervisor rationale, model-visible target text, and draft fields never populate action fields.

The builder exact-matches Campaign, Surface Snapshot, Hypothesis Set, Plan, Task, Surface,
Hypothesis, Target, Tool ID/version, threat class, risk, method, Capability domain, and Scope. The
external verifier rebuilds the complete proposal from caller-supplied current authorities and
requires exact equality.

## Authority boundary

The proposal carries both an action-semantics digest and a full proposal digest. Its local
`sourcePlanId` is derived exactly from the ORCH `SurfaceBoundPlan.planDigest`, while the original
`sourceWavePlanId` is retained separately. SUP-003 output is deliberately not accepted as proposal
lineage because PERMIT-001 does not receive the complete source set needed by the SUP-003 external
verifier. The Target reference contains no endpoint text; exact ORCH arguments remain inert data
and may themselves contain endpoint-shaped strings. The wire contains no request identity,
`ToolRequest`, active Capability reference, Grant, Envelope, Graph Decision, budget reservation,
Permit, dispatch, Worker job, or callable.

The following fields are literal and immutable:

- `proposalState="proposed-not-compiled"`;
- `supervisorActionFieldsAuthoritative=false`;
- `actionCompilerApplied=false`;
- `toolRequestCompiled=false`;
- `capabilityGranted=false`;
- `permitGranted=false`;
- `executionAuthorized=false`; and
- `scopeExpansionAuthorized=false`.

The `actionDefinition` field is static reviewed metadata, not an activated Capability or a Grant.
Expected evidence and cleanup are metadata-only. A write-class definition without a cleanup
requirement is rejected. Success Oracle binding, cleanup handler binding, cleanup planning, and any
cleanup Permit remain later compiler and execution-gate responsibilities.

## Negative boundaries

Construction or verification fails closed for:

- a missing Surface Snapshot Campaign digest, or a foreign or altered Campaign, Surface Snapshot,
  Hypothesis Set, Plan, Task, Hypothesis, or Surface lineage;
- a Target absent from the Campaign, an ambiguous Target ID, deny-Scope match, missing allow-Scope
  match, or malformed Scope URL;
- Tool ID/version, domain, target type, threat class, method, or risk drift between Plan,
  Hypothesis, Campaign, and Capability definition;
- a definition above the Campaign risk ceiling or a write definition without cleanup metadata;
- stale or foreign Capability definition ID/version/digest;
- self-consistent action method, argument, evidence, cleanup, target, or risk substitution when
  checked against the expected sources;
- boolean, float, or string risk coercion; non-canonical methods; non-literal authority booleans;
  duplicate or unsorted evidence types; and
- top-level `ToolRequest`, Capability Grant, Permit, command, argv, shell, or other extra-field
  injection.

Prompt-shaped strings may remain inside the already planned argument object as inert data. They
affect the canonical argument and proposal digests but cannot create an executable field or invoke
a compiler, Gateway, or Worker.

## Compatibility, migration, and rollback

The module and `pajin.supervision` exports are additive and direct-call opt-in. The ORCH Snapshot
reader gains an optional `campaignDigest`; field-absent historical records preserve their original
wire and all transitive parent digests, while new records use the strengthened digest domain.
Existing Hypothesis, Supervisor, Capability, GRAPH-006, Common Engine, Tool Gateway, and artifact
contracts remain compatible. No stored data migration is required.

Rollback removes the new proposal module, exports, tests, and documentation but must retain the
compatible ORCH Snapshot reader for already sealed strengthened records. Otherwise those records
must remain non-executable historical artifacts. Serialized PERMIT-001 records remain historical
non-executable proposals and cannot be consumed by GRAPH-006.

## Remaining boundary

PERMIT-001 does not invoke a Capability materializer or action compiler and does not create a
`ToolRequest`. PERMIT-002 consumes it only after exact source rebuild and compiles a non-expanding
request through the exact code-backed Materializer and Action Compiler. PERMIT-003 must then reuse
the existing GRAPH-006 atomic single-use Permit rather than introducing another Permit store or
dispatcher.

## Related documents

- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](../adr/0047-mission-envelope-and-action-permit-algebra.md)
- [ORCH-001 contract](ORCH-001-surface-snapshot-plan-task-binding.md)
- [PERMIT-002 contract](PERMIT-002-deterministic-action-compiler.md)
- [SUP-003 contract](SUP-003-typed-non-executable-supervisor-proposal.md)
- [SUP-006 contract](SUP-006-adversarial-prompt-injection-regression.md)
- [CAP-001 contract](../capability/CAP-001-versioned-capability-definition.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
