# ADR-0162: Reopen VAL-004C without Retest Authority

## Status

Accepted

## Context

UX-004A exposes exact Original, Replay, and optional Retest coordinates from one durable KISA
Replay projection, but that authority owns no Control evidence. VAL-004C already binds one WALK
source execution, two repeated validity Replays, and three ordered Control executions under one
sealed assessment. It does not bind remediation Retest evidence. Display-level Campaign or Claim
similarity cannot safely compose the two authorities.

## Decision

### Reopen one exact VAL-004C authority

UX-004B uses VAL-004C, not VAL-004A, because VAL-004C owns all six required execution lineages in a
single assessment: source, primary Replay, additional Replay, Baseline, Negative Control, and
Counterfactual. The reader reopens every sealed predecessor and invokes the existing VAL-004C
verifier on each request. It does not reinterpret embedded assessment fields as sufficient proof.

### Persist only a content-addressed locator

A producer-side helper may write a verified locator below a server-configured evidence root. The
locator stores exact root-relative Run and artifact paths and the existing assessment so the reader
can recover the closed predecessor graph. It creates no validation or execution authority. Canonical
path, no-link, root containment, bounded strict JSON, content-addressed ID, and atomic no-follow
write rules apply.

### Keep Retest unavailable and redact content

The view has the stable Original, Replay, Control, Retest order with counts `[1, 2, 3, 0]`. Retest is
`not-in-authority`; KISA UX-004A data is not joined. The response includes opaque execution
coordinates and existing aggregate Profile/contrast state, while excluding Claim content and IDs,
request, approval, Grant, Permit, worker, artifact, evidence references, and paths.

The route is Operator-only and query-only. Authority markers deny new assessment creation, Profile
selection, remediation attestation, Finding confirmation, and execution authorization.

## Consequences

- Operators can inspect exact repeated and controlled WALK lineages without receiving evidence
  content.
- Baseline, Negative Control, and Counterfactual order and contrast are reverified rather than
  inferred.
- Product coverage is honest but split: UX-004A shows KISA Retest without Control, while UX-004B
  shows WALK Control without Retest.
- Local filesystem and service-account control remain part of the trust boundary; there is no
  off-host locator authenticity or multi-root registry.
- Each request reopens several sealed Runs, trading read cost for a current integrity decision.

## Rejected alternatives

### Join UX-004A and VAL-004C by Campaign or Claim display fields

Rejected because no sealed authority proves the cross-system lineage.

### Select VAL-004A

Rejected for this slice because VAL-004C provides repeated Replay plus Control lineages in one
mode-neutral authority, making the comparison depth and independence checks explicit.

### Treat the locator as a new assessment

Rejected because it would duplicate or expand VAL-004C authority. The locator only makes existing
sealed dependencies recoverable.

## Compatibility and rollback

The module, environment setting, GET route, locator artifact, and Web Console panel are additive.
There is no database, VAL-004C, KISA Replay, or sealed Run schema migration. Rollback removes the
reader, route, and panel; existing evidence remains unchanged.

## Related documents

- [UX-004B contract](../orchestration/UX-004B-val004c-control-comparison.md)
- [UX-004A contract](../orchestration/UX-004A-replay-lineage-coordinate-comparison.md)
- [VAL-004C contract](../orchestration/VAL-004C-mode-neutral-repeated-walking-profile-evidence.md)
- [ADR-0152](0152-bind-repeated-walking-replays-without-new-execution-authority.md)
- [ADR-0161](0161-compare-replay-lineage-without-cross-authority-composition.md)
