# UX-004B: VAL-004C Control Comparison

- Status: Implemented and verified
- Decision: [ADR-0162](../adr/0162-reopen-val004c-without-retest-authority.md)
- Predecessor: [VAL-004C](VAL-004C-mode-neutral-repeated-walking-profile-evidence.md)
- Response schema: `pajin.control-plane/verified-walking-control-comparison-view/v1alpha1`

## Scope

UX-004B reopens one exact sealed VAL-004C assessment and all of its source, repeated Replay, and
Control execution predecessors:

`GET /v1/validation-comparisons/walking/{comparison_id}`

The Operator-only endpoint returns four fixed lanes: Original has one source coordinate, Replay has
the primary and additional coordinates, Control has Baseline, Negative Control, and Counterfactual
coordinates in canonical order, and Retest is `not-in-authority`. It does not join KISA evidence,
execute work, create an assessment, select a Profile, attest remediation, or confirm a Finding.

## Locator and verification

`PAJIN_CP_VALIDATION_EVIDENCE_ROOT` is the server-owned evidence root. A writer first verifies the
complete VAL-004C assessment, requires every referenced sealed Run to remain under that canonical
root, and stores a content-addressed locator at:

`comparisons/{comparison_id}/comparison.json`

The locator contains root-relative paths plus the existing assessment; it is not new evidence. On
every read, the reader rejects links and path escape, reopens every sealed Run, reconstructs the
typed source, both Replays, the Control publication, and all three Control executions, and delegates
to the existing VAL-004C verifier. Locator identity, assessment equality, lane order, Control order,
six coordinate ordinals, and pairwise-distinct Run/root/execution digests must agree.

## Redaction and authority ceiling

The response exposes only content-addressed comparison and assessment digests, Campaign and Claim
digests, Profile identity/version, achieved depth, validation state, Control contrast, and opaque
Run/root/execution digests. Claim text and IDs, request, approval, Grant, Permit, worker, artifact,
evidence reference, and filesystem paths remain absent.

The comparison mode is
`exact-execution-coordinates-with-verified-control-contrast`. Authority literals verify sealed
predecessors, exact lineage, Control contrast, and redaction. They fix Retest inclusion, new
assessment creation, Profile selection, remediation attestation, Finding confirmation, and
execution authority to `false`.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Approver-, Auditor-, or Worker-only credential | `403` |
| Non-canonical comparison ID | `422` |
| Evidence root unconfigured | `503` |
| Locator absent | `404` |
| Locator or any predecessor disagrees or fails integrity | `409` |

## Web Console and completion criteria

The same-origin panel accepts one exact comparison ID and checks the exact schema, content-addressed
identity, Profile and state, four lanes, `[1, 2, 3, 0]` cardinality, all six ordered coordinates,
canonical Control kinds, digest separation, and every authority literal before rendering with DOM
nodes and `textContent`.

Completion requires writer/read-back tests over real VAL-004C fixtures, mutation rejection after
publication, role and configuration isolation, strict browser protocol tests, and desktop/mobile
rendering without horizontal overflow or console errors.
