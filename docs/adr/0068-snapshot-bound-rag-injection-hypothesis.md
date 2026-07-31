# ADR-0068: Snapshot-Bound RAG Injection Hypothesis

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-001 publishes an exact file-upload Surface through DISC-003B, while DISC-003C can publish
explicit RAG boundaries. The existing dynamic Hypothesis compiler is intentionally specialized for
registered Tool-interface Surfaces and emits executable Specialist requests. Reusing it for a RAG
ingestion claim would either infer RAG semantics from a file upload or invent an executable Tool
before the walking skeleton has established MCP Tool authorization.

The Phase 4 H-17 baseline instead needs a deterministic, auditable claim that an untrusted document
can enter an explicitly declared RAG corpus-ingestion boundary, with execution deferred.

## Decision

1. Add `HTTPRAGInjectionReconPlanner` and bind it to the exact cumulative DISC-003C adapter and
   required `http-file-upload` plus `http-rag` Surface kinds.
2. Add a code-registered H-17 rule containing threat, rationale, observable, required future Tool,
   Risk Tier, side effect, four-call ceiling, success condition, and stop condition.
3. Compile only explicit `corpus-ingest` RAG Surfaces with exactly one file-upload Surface on the
   same Campaign target and complete route locator.
4. Bind the resulting authority to the complete Campaign digest, ORCH-001 Surface Snapshot, rule
   digest, both Surface identities and locators, and fixed `not-authorized` execution state.
5. Re-read and compare the sealed source Campaign and Recon Plan and re-verify the sealed Surface
   projection before compilation.
6. Persist the authority in a separate sealed audit Run without generating a Tool request,
   Capability, payload, corpus mutation, or Worker dispatch.
7. Keep the existing executable Hypothesis v1alpha1 and ORCH-001 Plan/Task contracts unchanged.

## Consequences

- H-17 is reproducible from one exact Snapshot and cannot be recreated from upload prose or a RAG
  boundary on another route.
- Campaign, Plan, Snapshot, rule, Surface, and artifact substitution fail closed.
- The required `rag-document-probe` semantic is visible for planning but grants no authority.
- WALK-003 can add the MCP Tool Authorization dependency without retrofitting execution into this
  slice.
- The extra Recon path uses DISC-003C because the Registry permits only one interpreter per Tool;
  multi-adapter Snapshot scheduling remains future work.

## Compatibility and rollback

All models and exports are additive. Existing WALK-001, A4/A5, ORCH-001/002, Campaign, Recon, and
Hypothesis readers retain their current wire shapes. Rollback removes the WALK-002 planner/compiler
from composition and leaves sealed artifacts readable.

## Related documents

- [WALK-002 contract](../orchestration/WALK-002-rag-injection-hypothesis.md)
- [WALK-001 contract](../orchestration/WALK-001-file-upload-surface-discovery.md)
- [ADR-0063: Bounded Explicit RAG Boundary Discovery](0063-bounded-explicit-rag-boundary-discovery.md)
- [ORCH-001 contract](../orchestration/ORCH-001-surface-snapshot-plan-task-binding.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
