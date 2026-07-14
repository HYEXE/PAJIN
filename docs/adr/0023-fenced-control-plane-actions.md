# ADR 0023: Fenced Control Plane approval and cancellation actions

- Status: Accepted
- Date: 2026-07-14
- Extended by: [ADR 0024](0024-cooperative-execution-cancellation.md)

## Context

ADR 0011 introduced durable approval checkpoints and ADR 0022 exposed read-only Run monitoring in
the Web Console. Operators could not discover the Approval attached to the current checkpoint from
a resource endpoint, and approval decision, resume, and cancellation still required hand-written
API calls.

`RunState.CANCELLED` existed without a transition. Changing only the Run row would be unsafe: a
queued Job could still be claimed, a leased Job could still complete, lease recovery could requeue
it, and an approved checkpoint could recreate a continuation Job. Approval denial also left the Run
permanently in `awaiting-approval`. Expiry changed an Approval row and then raised inside the same
transaction, so the change was rolled back.

Cancellation cannot promise to undo a Tool side effect that already happened. It must instead have
a precise durable meaning that Workers and operators can observe.

## Decision

The Control Plane adds these authenticated contracts:

- `GET /v1/runs/{run_id}/approval` returns the Approval for the Run's current checkpoint, or `null`.
  Operator, Approver, and Auditor may read it; Worker may not. It returns `ApprovalView` and does not
  expose checkpoint execution state, signature material, Run input, or Job payload. Before return,
  the service verifies checkpoint integrity, Run ownership, and exact intent-field equality.
- `POST /v1/runs/{run_id}/cancel` is Operator-only and requires a non-blank reason of at most 1,000
  characters. The response states whether cancellation was newly applied and identifies fenced Jobs
  and revoked Approvals.
- The existing decision endpoint remains Approver-only and the resume endpoint remains
  Operator-only. The Console enables controls from the authenticated role, but API authorization is
  authoritative.

The state transitions are:

| Initial state | Action | Durable result |
| --- | --- | --- |
| Run `queued` | cancel | Run and queued Job `cancelled` |
| Run `running`, Job `leased` | cancel | Run and Job `cancelled`; lease material cleared |
| Run `awaiting-approval` | cancel | Run `cancelled`; pending or approved Approval `revoked` |
| Run `cancelled` | cancel again | 200 no-op; no new event or reason replacement |
| Run `completed` or `failed` | cancel | 409 conflict |
| Approval `pending` | deny | Approval `denied`; Run `cancelled` |
| Approval `pending` or `approved` | observed expired | Approval `expired`; Run `cancelled` |
| Approval `approved` at current checkpoint | resume | Approval `consumed`; one continuation Job `queued` |

`JobState.CANCELLED` and `ApprovalState.REVOKED` distinguish operational cancellation from execution
failure and an Approver's denial. `run.cancelled`, `job.cancelled`, `approval.revoked`,
`approval.denied`, and `approval.expired` events retain actor, bounded reason, and affected IDs.
The current checkpoint pointer is preserved for denied, expired, or cancelled review and cleared
after successful resume.

Every state-changing Worker path rechecks the Run state while holding its row locks. Claim requires
`queued`; heartbeat, failure, and checkpoint creation require `running`; completion is fenced when
the Run is cancelled. Resume and decision require `awaiting-approval` and an exact match with
`current_checkpoint_id`. Lease recovery cannot requeue or fail a cancelled Run.

Mutations preserve the existing dependent-to-Run lock order. Worker paths lock Job then Run;
decision and resume lock Checkpoint, Approval, then Run. Cancellation locks active Jobs in stable
order, revocable Approvals in stable order, re-reads active Jobs to capture a concurrent continuation
insertion, and locks the Run last. This avoids adding a Run-to-Job lock inversion while making
cancellation atomic with dependent fencing.

Approval expiry is committed before the API returns a conflict. Denial and expiry terminate the Run
because no re-planning or replacement-approval transition exists in this version.

The Web Console renders the current intent with `textContent`, requires a reason for decision or
cancellation, disables duplicate actions while a request is active, encodes all resource IDs, and
reloads Run, Approval, and event state after success or conflict. No change is made to the
memory-only credential or same-origin security model from ADR 0022.

## Cancellation boundary

Clearing a lease makes the next Worker heartbeat or finalization call return a lease conflict. With
default settings this fence is normally observed within one heartbeat interval. Every mutation for
an already claimed Job (heartbeat, completion, failure, or checkpoint creation) returns structured
`run_cancelled` when this Run fence wins; ADR 0024 connects that code to a typed, first-write-wins
cancellation context without disclosing the Operator's reason to the Worker credential. The daemon
allows a bounded
cooperative cleanup grace period and then forcibly cancels an execution task that has not returned.
The Local Campaign and Tool Loop runners can seal a local cancellation receipt before returning.

The durable `cancelled` state means that the Control Plane will not dispatch the fenced Job or accept
its result. A runner receipt states only that one local execution path observed cancellation and
completed its registered cleanup; the Control Plane does not acknowledge it or treat it as
authoritative physical-quiescence evidence. Neither the fence nor the receipt rolls back completed
external side effects, guarantees that an executor which suppresses cancellation has stopped, or
replaces destination-level idempotency.

## Consequences

- Approvers and Operators can complete the approval lifecycle without parsing audit-event payloads.
- A cancelled Run cannot be revived by claim, completion, lease expiry, decision, or checkpoint
  resume through the supported service paths.
- First cancellation reason wins and repeated cancellation is safe to retry.
- Revocation metadata is represented by append-only events rather than new nullable columns on the
  Approval row; future query/report requirements may justify a forward-only schema migration.
- SQLite tests validate functional state contracts, but PostgreSQL remains the required backend for
  production row-lock semantics and concurrency validation.
- Fleet-wide approval queues, managed identity, tenant ownership, a `cancelling` state and cleanup
  acknowledgement protocol, Control Plane-authoritative physical-quiescence attestation, and
  cancellation of arbitrary external systems remain out of scope.

## Validation

Automated tests cover read-role separation and minimized Approval responses, queued and leased Job
cancellation, lease-secret removal, stale Worker rejection, approved-then-cancelled resume fencing,
denial termination, expiry persistence, current-checkpoint invariants, terminal-state conflicts,
reason bounds, idempotent repeat cancellation, read-only queries, and Console source safety. Existing
Worker tests verify typed cooperative cancellation and forced fallback when a lost lease interrupts
in-flight async execution. Runner tests verify sealed local cancellation receipts. Integrity tests
also reject unsigned Approval-field drift and cross-Run ownership drift before review, decision, or
resume.
Opt-in PostgreSQL tests race cancellation against completion and checkpoint resume to verify the
row-lock contract on the production database backend.

## References

- [ADR 0011: PostgreSQL durable Control Plane](0011-durable-control-plane.md)
- [ADR 0012: Lease-aware Worker daemon](0012-lease-aware-worker-daemon.md)
- [ADR 0022: Same-origin Control Plane Web Console](0022-same-origin-control-plane-web-console.md)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
