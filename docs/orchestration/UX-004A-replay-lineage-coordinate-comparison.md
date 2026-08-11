# UX-004A: Replay Lineage Coordinate Comparison

- Status: Implemented and verified
- Decision: [ADR-0161](../adr/0161-compare-replay-lineage-without-cross-authority-composition.md)
- Predecessors: Control Plane Replay projection v1/v2/v3, VAL-004A, VAL-004C
- Response schema: `pajin.control-plane/verified-replay-evidence-comparison-view/v1alpha1`

## Scope

UX-004A is the first bounded slice of Original, Replay, Control, and Retest Diff. It maps one exact
completed durable Replay projection to a four-lane coordinate view:

`GET /v1/replay-comparisons/batches/{batch_id}`

The endpoint is query-only and Operator-only. It does not create a batch, resolve a pending
projection, open a second authority, execute a Replay or Control, evaluate evidence, attest a
remediation, confirm a Finding, or grant approval, Capability, Permit, or dispatch authority.

## Projection and lineage verification

The reader delegates to the existing Control Plane Replay reader and revalidates the complete typed
`ReplayProjectionView`. It then requires the projection purpose and authority version to agree and
requires all available Run IDs and root digests to be pairwise distinct across lanes.

For confirmation batches:

- Original is the exact source Artifact coordinate;
- Replay enumerates every finalized Replay input coordinate;
- Control is `not-in-authority`; and
- Retest is `not-applicable`.

For remediation-Retest batches:

- Original is explicitly labelled `remediation-baseline`;
- Replay enumerates every finalized remediation Replay input;
- Control is `not-in-authority`; and
- Retest binds the exact Retest source Run/root and derived projection artifact digest.

The four lanes are always ordered Original, Replay, Control, Retest. No unavailable lane may carry a
Run or digest.

## Redaction and authority ceiling

The view returns opaque Run IDs, root digests, result/evidence digests, bounded counts, purpose, and
projection identities. It excludes Campaign content, Candidate/Claim identity or statements,
artifact and repository IDs, creator/publisher IDs, Tool arguments, paths, evidence content,
verdicts, approval records, Grants, and Permits.

Every response fixes:

- durable projection binding verified: `true`;
- exact lineage coordinates verified: `true`;
- identifiers and content redacted: `true`;
- Control evidence included and semantic evidence compared: `false`; and
- validation evaluation, remediation attestation, Finding confirmation, and execution authority:
  `false`.

The comparison mode is exactly `exact-coordinates-no-semantic-diff`.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Approver-, Auditor-, or Worker-only credential | `403` |
| Non-canonical Replay Batch ID | `422` |
| Batch absent or completed projection unavailable | `404` |
| Projection, purpose, lane, or lineage disagreement | `409` |

Responses retain the existing `/v1` no-store and no-referrer headers. Database and parser details
are not reflected.

## Web Console

The same-origin panel accepts one exact completed Replay Batch ID. JavaScript exact-checks the
schema, batch/projection identities, purpose-specific role and availability matrix, four-lane
order, cardinality, Run/root/evidence digest shapes, pairwise lineage separation, redaction, and all
authority literals before replacing the DOM. Rendering uses created nodes and `textContent` only.

## Completion criteria

- confirmation and remediation-Retest lane shapes are deterministic;
- cross-lane Run/root reuse, false Control authority, semantic-authority escalation, and raw
  identifiers fail closed;
- endpoint role isolation, missing projection, and malformed Batch IDs are tested;
- Web Console protocol and rendering tests pass; and
- desktop/mobile Browser QA shows the four-stage relationship without horizontal overflow or
  console errors.

## Companion slice

[UX-004B](UX-004B-val004c-control-comparison.md) separately exposes Original, repeated Replay, and
Control by reopening exact VAL-004C authority and all sealed predecessors. It keeps Retest
unavailable and does not compose this KISA projection by Campaign or Claim display equality.
