# ADR-0210: Project Red Team Product Flow without Finding Authority

## Status

Accepted

## Context

REDTEAM-001A/B/C/D produce bounded executable profiles, and REDTEAM-002 measures their sealed raw
Observations. Operators need one product-facing structure that separates what was in scope, what
Evidence exists, whether a Finding was confirmed, and what metrics are available.

The REDTEAM-002 source contract does not retain a complete Campaign Scope. Its REDTEAM product
Profile IDs are also not PROF-001 Campaign Profile IDs, and no code-owned mapping binds them. A UI
or report adapter that inferred a PROF-001 Profile from labels such as `web`, `llm`, or `mcp` could
incorrectly claim a VAL-003 floor and then present detections as Findings.

## Decision

Add an additive sealed UX-008 projection with four explicit sections:

1. Profile-bound Scope summaries that expose exact Profile and CAP-002 identities while stating
   that Campaign Scope is unavailable and no Scope authority is created.
2. Content-free Evidence references rebuilt from every sealed REDTEAM-002 source Observation.
3. Per-Profile Finding states fixed to unconfirmed with zero confirmed Findings and an unevaluated
   Campaign Profile floor.
4. The exact REDTEAM-002 aggregate retained only as a measurement report.

Require publication and loading to use the existing REDTEAM-002 verified loader and rebuild the
complete projection from the aggregate and every source Run. Publish it in a separate sealed Run
with a content-addressed identity.

Do not infer a Campaign Profile, Campaign Scope, VAL-003 floor, Security Domain, Finding, report
delivery permission, or execution permission. Fix all related authority markers to false. Keep the
initial adapter direct-call and content-redacted.

## Consequences

- Product consumers can distinguish Profile boundary, sealed Evidence availability, explicit
  no-Finding state, and measurement results in one typed artifact.
- A successful detection, Oracle result, Replay, or favorable metric remains visibly different
  from a confirmed Finding.
- The missing REDTEAM-to-PROF-001 mapping and missing Campaign Scope remain explicit instead of
  being guessed.
- Post-seal mutation or predecessor substitution fails when the projection is reopened.
- A later Control Plane or Web Console adapter can consume this projection without redefining its
  authority semantics.
- The current slice does not itself provide that HTTP or rendered UI adapter.

## Rejected alternatives

### Treat REDTEAM product Profiles as PROF-001 Campaign Profiles by name

Rejected because the identifiers, semantics, and authority roles differ and no registered mapping
exists.

### Treat a positive detection or Oracle result as a confirmed Finding

Rejected because REDTEAM-001/002 do not satisfy a Campaign Profile validation floor or produce a
Finding authority.

### Display zero Findings as proof that no vulnerability exists

Rejected because zero here means the Finding path is unavailable, not that an independently
validated negative result exists.

### Expose raw Evidence content in the initial projection

Rejected because the product flow needs lineage and status, while raw target content requires a
separate read-authority and redaction decision.

## Compatibility and rollback

The new module, artifact, tests, contract, and ADR are additive. Existing REDTEAM, BENCH, Profile,
Validation, Finding, report, Graph, Control Plane, and execution APIs remain unchanged. Rollback
removes UX-008 publication while leaving all previously sealed Runs self-describing and without
rewriting any predecessor.

## Related documents

- [UX-008 contract](../orchestration/UX-008-redteam-product-flow-projection.md)
- [REDTEAM-002 contract](../benchmark/REDTEAM-002-initial-profile-benchmark.md)
- [ADR-0209](0209-measure-redteam-profiles-without-finding-authority.md)
- [VAL-003 contract](../orchestration/VAL-003-profile-assurance-floor.md)
- [ADR-0149](0149-bind-profile-assurance-floors-without-campaign-selection.md)
