# ADR-0128: Bind General Attack Semantics Before Action Compilation

- Status: Accepted
- Date: 2026-08-05

## Context

SUP-006 proves that prompt-shaped target content and model rationale cannot mint execution
authority, but Phase 7 still needs a typed action meaning before any Supervisor-selected work can
reach deterministic compilation. PAJIN already exposes `pajin.graph.ActionProposal`; however, that
object includes an Envelope, Graph Decision, registered execution Capability, exact request and
parameter digests, and a budget reservation. GRAPH-006 can immediately consume it into a
single-use Permit. Reusing or widening that wire for model-adjacent semantics would collapse the
proposal/compiler/Permit separation.

Existing ORCH-001 plans already bind the Surface Snapshot, complete task, and exact planned
`ToolRequest`. CAP-001 definitions already own action identity, Tool binding, risk, evidence,
side-effect, and cleanup metadata. SUP-003 already provides content-addressed, content-free advisory
output, but proving that lineage requires its complete external-verification source set. A new
parallel authority for any of these concepts would be redundant.

## Decision

Add a distinct `GeneralAttackActionProposal` predecessor with the following rules:

1. Require the ORCH Surface Snapshot's additive full Campaign digest and bind the complete
   Campaign, Snapshot, Plan, Task, Hypothesis Set, Hypothesis, and Surface identities. Historical
   name-only Snapshots remain readable but are not PERMIT-001 inputs.
2. Resolve one exact CAP-001 definition from the immutable registry. Copy only its static action
   identity, risk, expected evidence, side-effect, and cleanup metadata.
3. Reopen the target from the current Campaign, require exact Hypothesis and task endpoint equality,
   evaluate deny-first Scope, and retain a content-free target reference plus endpoint digest.
4. Copy method and arguments only from the exact ORCH task. Bind both into action semantics and
   give arguments a distinct pre-materialization digest; do not call it the normalized Capability
   parameter digest.
5. Do not accept SUP-003 output as trusted lineage without the complete sources required by its
   external verifier. Supervisor rationale and proposal fields remain outside this predecessor.
6. Reject write-class definitions without cleanup metadata, but do not bind a cleanup handler,
   create a cleanup plan, or issue a cleanup Permit in this checkpoint.
7. Keep compiler, `ToolRequest`, Grant, Permit, execution, and Scope-expansion flags literally
   false. Require an external exact-rebuild verifier for current-source admission.
8. Leave the existing GRAPH-006 `ActionProposal`, Permit store, and Gateway dispatcher unchanged.

## Consequences

- Phase 7 gains a complete, reviewable action meaning without creating an execution path.
- Model rationale and Supervisor proposal fields cannot alter action semantics derived from ORCH
  and CAP-001 or create unverified audit lineage.
- Campaign, Snapshot, Plan, Task, Capability definition, target, risk, evidence, cleanup, and
  argument substitution fail closed under exact verification.
- Static Capability metadata is selected before compilation, but no activation, Grant, code-backed
  adapter, request, or Permit is selected.
- PERMIT-002 has one narrow job: resolve the code-backed compiler and translate this predecessor to
  exact request/GRAPH authority without expansion.
- PERMIT-003 can reuse GRAPH-006 atomic single-use consumption rather than creating a competing
  Permit implementation.

## Rejected alternatives

### Extend `pajin.graph.ActionProposal`

Rejected because it would change an existing digest and SQLite Permit identity and blur the point
at which a proposal becomes immediately Permit-eligible.

### Copy Supervisor rationale into action fields

Rejected because prompt-shaped target content and model output are untrusted. SUP-006 permits them
only inside their independently verified, non-executable Supervisor authority chain; PERMIT-001
does not duplicate or partially verify that chain.

### Add a second Capability, Scope, evidence, or cleanup registry

Rejected because CAP-001/CAP-002 and the Campaign already own those authorities. PERMIT-001
references and revalidates them rather than duplicating them.

### Create a `ToolRequest` but mark it non-executable

Rejected because request creation is deterministic compiler work and would make PERMIT-002 an
empty naming layer. PERMIT-001 retains only bounded arguments and source task lineage.

## Compatibility and rollback

The proposal schema, builder, verifier, exports, tests, contract, and decision are additive. No
existing runtime path calls the proposal API. The ORCH Snapshot reader accepts an additive optional
Campaign digest; field-absent v1 records retain their original wire and transitive parent digests,
while new records use the strengthened digest domain. No stored migration is required. Rollback may
remove the proposal API but must retain the compatible ORCH reader or treat strengthened Snapshot
runs as non-executable historical data. Existing PERMIT-001 records always remain non-executable.

## Related documents

- [PERMIT-001 contract](../orchestration/PERMIT-001-general-attack-action-proposal.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0051: Versioned Capability Definition and Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052: Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.md)
- [ADR-0065: Surface Snapshot-Bound Orchestration](0065-surface-snapshot-bound-orchestration.md)
- [ADR-0119: Compile Untrusted Supervisor Drafts](0119-compile-untrusted-supervisor-drafts.md)
- [ADR-0127: Enforce the Advertised Supervisor Draft Wire](0127-enforce-the-advertised-supervisor-draft-wire.md)
