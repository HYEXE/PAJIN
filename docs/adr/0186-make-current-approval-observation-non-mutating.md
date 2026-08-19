# ADR-0186: Make Current Approval Observation Non-Mutating

## Status

Accepted

## Context

ADR-0023 made `GET /v1/runs/{run_id}/approval` expire an elapsed Approval and cancel its Run before
return. Operator, Approver, and Auditor roles can all call that read endpoint. After Phase 9 added
separate exact policies for approval decisions, checkpoint resume, Run cancellation, and explicit
maintenance, the GET behavior remained a hidden mutation that required no corresponding action
authority.

The Human Review queue already demonstrates the desired projection model: it reports an elapsed
Approval as attention without changing durable state. UX-007I now provides an explicit, exact-
authorized maintenance operation for broad server-selected expiry. Decision and resume paths also
hold their own exact intent or continuation authority before they reconcile expiry.

## Decision

### Supersede GET-triggered expiry from ADR-0023

`GET /v1/runs/{run_id}/approval` uses one rollback-only transaction. It verifies the current
Run/Checkpoint/Approval graph, signed Checkpoint, exact Approval intent, and state consistency, then
returns the durable Approval state. It does not capture current time, take mutation locks, expire an
Approval, cancel a Run, or append events.

An elapsed `expires_at` with durable state `pending` or `approved` is a valid read projection until
an authorized mutation reconciles it. Reads may be stale immediately after their snapshot; every
mutation continues to lock and reverify current authority.

This decision supersedes only ADR-0023's `observed expired` GET transition. Its cancellation,
decision, resume, locking, fencing, event, and redaction decisions remain active.

### Keep expiry under explicit action authority

The exact-authorized maintenance endpoint remains the broad expiry owner. Approval decision and
checkpoint resume may persist expiry only after their respective exact ABAC checks and existing
signed-intent verification. A read role, URL Run ID, refresh time, or local clock never grants
expiry or cancellation authority.

### Fail stale controls closed without synthesizing server state

The Web Console recognizes a verified active Approval whose timestamp has elapsed and disables its
native decision and resume buttons. It labels the projection as elapsed and directs the user to an
authorized reconciliation path. Client time affects only local control availability; it does not
change the returned durable state or trigger a request automatically.

## Consequences

- Auditor, Approver, and Operator observation cannot cancel a Run.
- Auto-refresh and concurrent readers remain rollback-only.
- Explicit maintenance becomes the only broad server-selected expiry trigger.
- Existing decision and resume attempts retain exact, atomic expiry reconciliation.
- The response wire and read roles do not change, but clients that relied on GET side effects must
  invoke an authorized mutation instead.
- No database migration or new dependency is required.

## Rejected alternatives

### Apply maintenance ABAC to the GET

Rejected because reading an Approval should not require or imply mutation authority. It would also
either deny legitimate readers or keep observation-dependent lifecycle behavior.

### Return a synthesized `expired` state without persistence

Rejected because it would make the same response state mean both durable and projected facts and
could conflict with subsequent locked action results.

### Automatically call maintenance from the Web Console

Rejected because refresh and navigation are not authorization to initiate a broad state mutation.

## Compatibility and rollback

The route, schema, authentication, roles, and redaction are unchanged. The semantic change is
intentional security hardening: GET no longer has durable side effects. A safe operational rollback
is to retain the pure read and omit only the optional client-side elapsed label; restoring
GET-triggered mutation would reopen the Phase 9 authority bypass.

## Related documents

- [UX-007J contract](../orchestration/UX-007J-non-mutating-current-approval-read.md)
- [ADR-0023 fenced Control Plane actions](0023-fenced-control-plane-actions.md)
- [ADR-0163 Human attention projection](0163-project-human-attention-without-action-authority.md)
- [ADR-0185 explicit maintenance ABAC](0185-authorize-explicit-maintenance-by-exact-action.md)
