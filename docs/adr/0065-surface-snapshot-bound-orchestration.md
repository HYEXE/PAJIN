# ADR-0065: Surface Snapshot-Bound Orchestration

- Status: Accepted
- Date: 2026-07-29

## Context

The A4 Hypothesis compiler already re-verifies a sealed Surface projection and embeds Surface
identity in Hypotheses. Its follow-up Wave Plan, however, identifies only the Hypothesis Set and
Specialist steps. Auditors and dispatch gates therefore lack a first-class statement that the
complete Plan and every executable Task consume the same exact Surface projection revision and
digest.

Changing the existing Discovery Hypothesis v1alpha1 wire shape would break sealed-artifact
compatibility. Treating an in-memory `ReconWaveOutcome` as sufficient would also permit stale or
replaced projection authority between compilation and execution.

## Decision

1. Add an immutable `SurfaceSnapshotAuthority` with revision `1`, exact projection/source Run
   roots, sealed artifact path and SHA-256, Surface Set ID, and domain-separated identity digest.
2. Add an additive `SurfaceBoundTask` digest over the Snapshot ID/revision/digest, Hypothesis Set
   and Wave Plan IDs, Hypothesis and Surface IDs, and complete Specialist step.
3. Add a `SurfaceBoundPlan` digest over the complete Snapshot authority and canonically ordered
   full Task set.
4. Persist the bound Plan as `surface-bound-plan.json`; retain the existing Hypothesis Set, Wave
   Plan, and Specialist-step wire contracts unchanged.
5. Re-verify and reconstruct the complete binding before capability issuance and immediately
   before every Tool dispatch. Any drift fails before dispatch.
6. Record Snapshot, Plan, and Task digests in the sealed audit trail without treating those
   digests as Capability grants.

## Consequences

- A Plan or Task can be traced to one exact immutable Surface projection without relying on
  transitive inference through a Hypothesis ID.
- Snapshot replacement, artifact mutation, cross-Plan Task substitution, and retained-digest
  payload mutation fail closed.
- Re-verification adds bounded local integrity reads before capability issuance and Tool dispatch.
- ORCH-001 does not schedule multiple adapters or waves and does not modify the existing
  one-time Campaign Planner; those remain separate orchestration work.

## Compatibility and rollback

The new models, artifact, outcome field, and event fields are additive. Discovery Hypothesis
v1alpha1 identities and sealed artifacts keep their existing shape. New execution requires the
Surface-bound authority, while existing readers may ignore it.

Rollback stops new bound execution and may ignore the additive artifact. Already sealed runs are
immutable and remain readable; an unbound legacy Plan must not be upgraded implicitly.

## Related documents

- [ORCH-001 contract](../orchestration/ORCH-001-surface-snapshot-plan-task-binding.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [DISC-001: Versioned Discovery Adapter Registry](../discovery/DISC-001-versioned-discovery-adapter-registry.md)
