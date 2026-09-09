# ADR-0264: Preserve Conservative Budgets in the Supervisor Journal

- Status: Accepted
- Date: 2026-09-08

## Context

The Supervisor invocation journal prevents redispatch of a started request, but replacement
Campaign and dedicated budget controllers initially contain zero usage. Summing successful
Supervisor receipts would omit other Campaign work and uncertain calls. Several ordinary Tool
paths also recorded usage only after awaiting the Gateway, leaving a crash window before recording.

## Decision

Extend the existing journal to schema v2 with append-only, canonical budget checkpoint histories.
Pin the Campaign digest, accounting role, complete limits and dedicated policy digest. Record all
controller mutations after binding, including ordinary Tool, agent and cost usage. Reserve both
model budgets in one SQLite transaction before dispatch. A dedicated denial rolls back both
in-memory charges within that transaction. Persistence uncertainty fences the attached controllers.

Verify complete histories when binding fresh controllers, retain conservative in-flight charges,
and preserve the original duration origin across downtime. Restore no previous reservation handles.
A new owner appends checkpoints for both scopes atomically; every subsequent mutation requires its
expected current checkpoint, fencing old in-memory owners before they consume additional capacity.

The invoker verifies its existing schedule/runtime authorities and binds both budgets before a new
or unstarted invocation claim. A trusted deployment can bind the same pair before other Campaign
work begins. The six previously post-accounted ordinary Tool paths now reserve before the Gateway;
only a proven non-executed outcome refunds. Replay retains its existing pre-dispatch attempt charge.

An exact v1 journal upgrades additively after verifying all existing invocation history. Existing
Campaign invocation history without complete budget history remains readable but cannot initialize
a replacement zero budget for new dispatch. Receipt and request wire formats do not change.

## Consequences

Restart, simultaneous controller use, uncertain execution, partial writes and ambiguous commits
cannot silently reset the supported budget scope. Verified actual model settlement remains valid;
unknown outcomes retain their upper bound. Accounting failures must not replace cancellation, so
existing runners can complete their cancellation/cleanup reporting while the budget stays fenced.

This is one trusted local journal, not a distributed budget service or an independent rollback
anchor. Recovery must use fresh controllers and the original journal and policy. Late initial
binding cannot reconstruct work lost before that first durable boundary. Complete deployment
inventory, quiescent cross-store backup and urgent-stop application remain separate OPS-001 work.
The operational, migration and validation contract is in
[OPS-001](../orchestration/OPS-001-single-host-recovery-and-urgent-stop.md).
