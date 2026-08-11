# ADR-0161: Compare Replay Lineage without Cross-Authority Composition

## Status

Accepted

## Context

Phase 9 calls for an Original, Replay, Control, and Retest comparison. PAJIN does not have one
authority that owns all four stages. The durable Control Plane Replay projection binds Original or
remediation-baseline, Replay results, and optionally a Retest source and derived assessment.
VAL-004A and VAL-004C own Control evidence under different Claim, request, Tool, and session
semantics. Combining those records by matching Campaign text or display labels would manufacture a
relationship that no existing sealed authority proves.

The first UX slice needs to make useful lineage differences visible while keeping absent authority
visible and refusing to treat coordinate comparison as semantic validation.

## Decision

### 1. Project only one durable Replay batch authority

UX-004A reads one existing completed `ReplayProjectionView` through the Control Plane's durable
reader. It supports confirmation and remediation-Retest projections. The new view does not open a
second Campaign, Claim, Control, or WALK authority and does not join records by mutable names.

The response carries the exact batch and projection identities, input-authority digest, projection
artifact digest, and four canonical lanes. Original, Replay, and—only for a remediation-Retest
batch—Retest contain opaque Run, integrity-root, and evidence-result digests already bound by that
projection.

### 2. Keep Control explicitly unavailable

The Control lane is always `not-in-authority` with no coordinates. A confirmation projection also
marks Retest `not-applicable`. The view rejects substituted lane order, purpose/role disagreement,
duplicate execution coordinates, and cross-lane Run or root reuse.

VAL-004A/VAL-004C Controls can be added only through a later UX-004B reader that reopens their exact
sealed predecessors and preserves their own Claim and session boundaries.

### 3. Compare coordinates, not evidence meaning

`comparisonMode=exact-coordinates-no-semantic-diff` is literal. The response excludes Candidate and
Claim content, artifact and repository IDs, creator/publisher identities, Tool arguments, paths,
evidence bodies, verdict text, approval material, Capabilities, and Permits.

Authority markers state that durable projection binding and exact lineage coordinates were
verified. They also state that Controls and semantic comparison are absent and that the view cannot
evaluate validation, attest remediation, confirm a Finding, or authorize execution.

### 4. Restrict the product view to Operators

The route is query-only and requires the Operator role:

`GET /v1/replay-comparisons/batches/{batch_id}`

Approver, Auditor, and Worker credentials are denied. The existing generic Replay projection route
is unchanged.

## Consequences

- Operators can see which durable execution lineages differ without receiving sensitive artifact
  content.
- Missing Control authority is visible instead of being silently inferred.
- A Retest batch can show baseline, fresh Replay, and Retest assessment coordinates while making no
  remediation-success claim.
- The view relies on the existing durable database projection binding. It does not re-open managed
  artifact bytes on every request and therefore does not claim live artifact-content verification.
- UX-004B completes the Control slice in a separate VAL-004C view without mixing KISA and WALK
  semantics; neither view claims a unified four-stage authority.

## Rejected alternatives

### Join Control and Retest records by Campaign or Claim text

Rejected because display-level equality is not sealed cross-authority lineage.

### Return raw projection and artifact objects

Rejected because they expose operator, publisher, repository, and artifact metadata beyond the
comparison need.

### Parse the Retest assessment as a semantic verdict in UX-004A

Rejected because the first slice verifies projection coordinates, not current managed artifact
bytes or the complete predecessor graph needed for a new semantic claim.

## Compatibility and rollback

The response model, reader, route, and Web Console panel are additive. No database, Replay wire,
Artifact repository, VAL-004A, VAL-004C, or WALK schema changes. Rollback removes the route and panel
without rewriting any Replay projection or sealed evidence.

## Related documents

- [UX-004A contract](../orchestration/UX-004A-replay-lineage-coordinate-comparison.md)
- [VAL-004A contract](../orchestration/VAL-004A-kisa-profile-validation-evidence.md)
- [VAL-004C contract](../orchestration/VAL-004C-mode-neutral-repeated-walking-profile-evidence.md)
- [ADR-0150](0150-evaluate-kisa-profile-floors-from-sealed-evidence.md)
- [ADR-0152](0152-bind-repeated-walking-replays-without-new-execution-authority.md)
