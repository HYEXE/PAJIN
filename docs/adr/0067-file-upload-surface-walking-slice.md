# ADR-0067: File Upload Surface Walking Slice

- Status: Accepted
- Date: 2026-07-31

## Context

DISC-003B defines a bounded file-upload Surface interpreter and verifies it through isolated
adapter and manually sealed admission tests. The generic single-Recon runner can execute an
arbitrary code-owned planner, but no production planner binds `HTTPGetTool` to the DISC-003B
adapter and no execution contract requires a file-upload Surface before publication.

Therefore the repository can classify file-upload topology but does not yet provide the first
explicit Thin Walking Skeleton step promised by WALK-001.

## Decision

1. Add `HTTPFileUploadReconPlanner` for one `GET` request to an exact Campaign-declared target.
2. Require the planner to carry an exact DISC-003B `DiscoveryAdapterReference`.
3. Add optional `adapterReference` and `requiredSurfaceKinds` fields to `ReconWavePlan`.
4. Bind the adapter reference and required `http-file-upload` kind into the deterministic request
   identity and sealed Recon audit.
5. After trusted admission and before projection, require exact adapter-reference equality and
   the presence of every required Surface kind.
6. Reuse the existing Tool Gateway, host-trusted Docker receipt, DISC-003B admission, immutable
   projection, shared budget, rate limit, cancellation, and ORCH-001 Snapshot boundaries.
7. Perform no file upload, crawl, redirect follow, `$ref` resolution, Hypothesis activation, or
   authority expansion.

## Consequences

- The first Phase 4 step can execute from a Campaign target through sealed Recon and publish an
  exact file-upload Surface projection.
- Empty OpenAPI upload topology and cross-adapter substitution fail before projection.
- The successful source Tool Run remains an immutable evidence record even when admission does
  not meet the walking-slice requirement.
- Existing MCP Recon planners and legacy Recon plan payloads remain supported.
- WALK-002 can consume the same projection through ORCH-001 rather than introducing another
  Surface authority.

## Compatibility and rollback

The new plan fields are optional and default to the legacy behavior when absent. Rollback removes
the WALK-001 planner from composition while retaining the generic Recon runner and all sealed
artifacts. No existing Mode, CLI, Campaign planner, or reader is removed.

## Related documents

- [WALK-001 contract](../orchestration/WALK-001-file-upload-surface-discovery.md)
- [ADR-0062: Bounded OpenAPI File Upload Boundary Discovery](0062-bounded-openapi-file-upload-boundary-discovery.md)
- [ORCH-001 contract](../orchestration/ORCH-001-surface-snapshot-plan-task-binding.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
