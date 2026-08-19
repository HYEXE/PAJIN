# UX-007J Non-Mutating Current Approval Read

## Status

Implemented as a security correction to the Phase 9 Identity and ABAC boundary.

## Purpose

Make `GET /v1/runs/{run_id}/approval` a rollback-only projection. Before this correction, reading
an elapsed pending or approved Approval expired it, cancelled its Run, and appended events. Because
Operator, Approver, and Auditor roles can read this endpoint, observation alone could bypass the
explicit maintenance authority introduced by UX-007I.

## Read contract

The service opens one rollback-only read transaction and verifies:

- the Run and its current Checkpoint relationship;
- Checkpoint and Approval ownership of the same Run;
- the signed Checkpoint integrity;
- exact Approval-to-signed-intent equality;
- the allowed durable Approval state for the Run state.

It returns the durable `ApprovalView` without capturing the server clock, locking mutation rows,
calling approval expiry, cancelling the Run, or appending an event. A past `intent.expires_at` may
therefore coexist with durable `pending` or `approved` until an authorized reconciliation path
commits the expiry. This is a stale-safe projection, not action authority.

## Mutation ownership

Approval expiry remains available only through an independently authorized mutation:

- exact-authorized `POST /v1/maintenance/requeue-expired` performs the broad server-selected sweep;
- an exact-authorized approval decision attempt may atomically persist that exact intent's expiry;
- an exact-authorized checkpoint resume attempt may atomically persist that exact continuation
  authority's expiry.

The GET route cannot authorize or initiate any of those mutations. URL Run ID, read role, request
timing, refresh, auto-refresh, and observed expiry are not mutation authority.

## Web Console interaction

The Web Console treats the server response as the durable state and compares its verified
`expires_at` with the client clock only to disable stale decision and resume controls. It renders
`pending · expired` or `approved · expired` and explains that an authorized maintenance or action
request must reconcile the durable state.

Native disabled buttons preserve keyboard, pointer, touch, and assistive-technology behavior. The
client does not mutate the response, synthesize terminal state, send an automatic maintenance
request, or claim that local time changed server authority. Server mutation paths recheck their own
current clock and locked state.

## Compatibility

- HTTP method, path, request, response schema, roles, and redaction remain unchanged.
- Clients must not assume an elapsed Approval has already been persisted as `expired` merely because
  the GET was called.
- No database or wire migration is required.
- Reintroducing GET-triggered expiry would reopen the authority bypass and is not a safe rollback.

## Validation

- Operator, Approver, and Auditor reads of an elapsed pending Approval return the durable pending
  state without cancelling the Run or appending expiry/cancellation events.
- Approval decision, checkpoint resume, and explicit maintenance retain their existing atomic
  expiry behavior.
- The repository's rollback-only transaction rejects accidental ORM mutation.
- Web Console source and runtime coverage require elapsed active Approvals to disable decision and
  resume controls while keeping cancellation subject to its separate Operator authority.

## Related documents

- [ADR-0186](../adr/0186-make-current-approval-observation-non-mutating.md)
- [ADR-0023 fenced Control Plane actions](../adr/0023-fenced-control-plane-actions.md)
- [ADR-0163 Human attention projection](../adr/0163-project-human-attention-without-action-authority.md)
- [UX-007I maintenance ABAC](UX-007I-exact-maintenance-requeue-expired-abac.md)
