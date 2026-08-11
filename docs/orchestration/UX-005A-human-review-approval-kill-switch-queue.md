# UX-005A: Human Review, Approval, and Kill Switch Queue

- Status: Implemented and verified
- Decision: [ADR-0163](../adr/0163-project-human-attention-without-action-authority.md)
- Response schema: `pajin.control-plane.human-review-queue/v1`
- Endpoint: `GET /v1/review-queue?limit=50`

## Scope

UX-005A projects one bounded priority queue from existing Control Plane Run, signed Checkpoint, and
Approval authority. It does not create or persist queue records. Operator, Approver, and Auditor
roles may read the same minimized snapshot; Worker-only credentials are denied.

The queue contains only active `queued`, `running`, and `awaiting-approval` Runs. One Run appears at
most once with one attention class:

| Attention | Canonical source condition |
| --- | --- |
| `approval-expired` | pending or approved current Approval whose expiry is at or before snapshot time |
| `approval-required` | unexpired pending current Approval |
| `resume-required` | unexpired approved current Approval |
| `execution-active` | queued or running Run with no current Approval boundary |

All four classes are kill-switch candidates because the existing cancellation service accepts those
three active Run states. The marker does not grant cancellation authority.

## Verification and ordering

The endpoint opens one rollback-only transaction and orders rows by attention priority: expired or
invalid approval context first, pending approval, approved resume, running, then queued. Approval
rows are secondarily ordered by risk tier descending, expiry ascending, Run update descending, and
Run ID ascending. It reads at most `limit + 1` rows so `has_more` is bounded; `limit` is 1 through
100.

Awaiting-approval rows must prove:

- the Run's current Checkpoint exists and belongs to that Run;
- exactly one Approval belongs to the same Checkpoint and Run;
- the Checkpoint signature and payload digest pass the existing verifier;
- the stored Approval fields exactly match the signed pending intent;
- the Checkpoint has not been claimed and has no continuation Job;
- the Approval is `pending` or `approved`.

Any mismatch returns the existing `409` integrity conflict instead of partially rendering the
queue. The GET does not call approval expiry, append an Event, or mutate database state.

## Response and redaction

Each item includes Run ID, Campaign name, Run state, update time, attention, current Checkpoint ID
when applicable, and a minimized Approval summary with ID, state, requester, request time, Tool ID,
target, risk tier, and expiry. It excludes Run input, Checkpoint state and signature, call
fingerprint, Approval decision reason, Job state and payload, Event payload, leases, secrets, Grant,
Permit, execution evidence, and results.

The authority object requires:

- `queue_snapshot_only=true`;
- `approval_decision_authority=false`;
- `checkpoint_resume_authority=false`;
- `cancellation_authority=false`;
- `execution_authority=false`.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or invalid bearer credential | `401` |
| Worker-only credential | `403` |
| `limit` outside 1 through 100 | `422` |
| Missing or inconsistent active Checkpoint/Approval authority | `409` |
| Tampered signed Checkpoint or Approval-to-intent binding | `409` |

## Web Console

The same-origin panel auto-loads with the authenticated Run list, participates in manual and
five-second refresh, and renders only after strict schema, exact-key, ordering, lifecycle, expiry,
uniqueness, and authority-marker validation. Rendering uses DOM nodes and `textContent`.

`Inspect controls` selects the existing Run detail. It does not submit an action from queue data.
The detail path reloads current Run, Event, and Approval state, then the existing endpoints recheck
role and lifecycle authority for approve, deny, resume, or cancel.

## Threat model and compatibility

The main threats are stale queue action, forged action eligibility, approval-field substitution,
self-approval confusion, unbounded listing, sensitive input disclosure, and GET-triggered mutation.
The design counters them with navigation-only rows, fixed false authority markers, existing mutation
endpoints, signed intent verification, a bounded query, minimized fields, and rollback-only reads.

The slice is additive, changes no database or existing API schema, and requires no migration. It has
no Benchmark effect because it creates no execution, Decision, or evidence authority. Rollback
removes the endpoint and panel without altering durable state.

## Completion criteria

Completion requires positive ordering and role tests, bounded pagination, no-Event/no-state-change
expiry tests, tampered Approval rejection, strict JavaScript protocol and stale-session tests, Ruff,
strict mypy, related Control Plane regression, and desktop/mobile browser inspection without console
errors or horizontal overflow.
