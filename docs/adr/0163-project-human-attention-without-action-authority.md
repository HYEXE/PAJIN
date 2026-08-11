# ADR-0163: Project Human Attention without Action Authority

## Status

Accepted

## Context

The Control Plane already owns durable Run, signed Checkpoint, Approval, resume, and cooperative
cancellation state. Its Web Console can operate those boundaries after a user selects one Run, but
the generic recent-Run list does not distinguish a pending decision, an approved checkpoint waiting
for resume, an expired approval that needs reconciliation, or an actively executing Run. Building a
second approval or cancellation state machine for a product queue would create conflicting
authority and unsafe stale actions.

## Decision

### Derive one bounded attention snapshot from existing records

UX-005A adds `GET /v1/review-queue`. One rollback-only database transaction selects only `queued`,
`running`, and `awaiting-approval` Runs. Every Run appears at most once and is classified as
`approval-expired`, `approval-required`, `resume-required`, or `execution-active`. Ordering is
deterministic and favors invalid or elapsed approval attention, then pending decisions, approved
checkpoint resumes, running Runs, and queued Runs.

For an awaiting-approval Run, the reader verifies exact Run/Checkpoint/Approval ownership, the
signed Checkpoint, the Approval-to-intent binding, unclaimed continuation state, and the only two
active Approval states. Missing, substituted, terminal, or inconsistent authority fails the whole
response closed. The query never expires or decides an Approval, resumes a Checkpoint, cancels a
Run, appends an Event, or creates a Job.

### Keep queue actions as navigation

The response exposes minimized lifecycle and approval context but omits submitted input, signed
Checkpoint payload and signature, call fingerprint, decision reason, Job payload, event payload,
lease, Grant, Permit, and execution result. Every returned active Run is marked only as a kill-switch
candidate. This marker is not authorization.

The Web Console queue row navigates to the existing Run detail. Approval, denial, resume, and
cancellation continue to use their existing role-gated endpoints, current-state checks, and atomic
transactions. The queue response fixes approval-decision, resume, cancellation, and execution
authority markers to `false`.

### Preserve existing read roles

Operator, Approver, and Auditor credentials may read the snapshot because those roles can already
read Run summaries and current Approval intent. Worker-only credentials remain denied. Mutation
roles are unchanged: only Approvers decide, and only Operators resume or cancel.

## Consequences

- Humans see the most urgent workflow boundary before opening a Run.
- An expired Approval is visible without turning a GET request into a lifecycle mutation; the
  existing detail/action path performs canonical reconciliation.
- Queue rows may become stale immediately after the snapshot. Every mutation therefore rechecks
  canonical authority and can reject the action.
- The first slice is host-local and single-Control-Plane-database. It is not a fleet-wide or
  multi-tenant queue and provides no push notification or assignment workflow.
- The `limit` is bounded to 100; `has_more` reports that additional active Runs exist without
  exposing an unbounded count.

## Rejected alternatives

### Persist a separate queue table

Rejected because it would duplicate lifecycle state, require reconciliation, and risk authorizing
actions from stale projection rows.

### Execute approval, resume, or cancellation from the GET response

Rejected because a read projection cannot carry current mutation authority. The existing endpoints
already own actor roles, self-approval prevention, expiry, fencing, and idempotency.

### Expire approvals while listing the queue

Rejected because a read refresh must not append Events or rewrite Run state. Expiry is represented
as attention and canonical lifecycle reconciliation remains in the existing service path.

## Compatibility and rollback

The response model, GET route, service query, and Web Console panel are additive. There is no
database migration or change to existing Run, Checkpoint, Approval, resume, or cancellation wire
formats. Rollback removes the route and panel; all durable workflow authority remains unchanged.

## Related documents

- [UX-005A contract](../orchestration/UX-005A-human-review-approval-kill-switch-queue.md)
- [ADR-0023](0023-fenced-control-plane-actions.md)
- [ADR-0024](0024-cooperative-execution-cancellation.md)
