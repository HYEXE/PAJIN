# ADR-0309: Reserve Receiver-Acknowledged Specialist Assignments before Dispatch

- Status: Accepted
- Date: 2026-09-18
- Scope: AGENTIC-003C1 durable specialist assignment authority
- Implementation status: Implemented in the local working tree

## Context

AGENTIC-002 makes logical agent commands durable, while AGENTIC-003A/B resolves selected Web
specialists to exact inert profiles and code-owned executor definitions. Neither boundary proves
that an assignment is still live when execution is about to start. A raw command, receiver inbox
receipt, Candidate, or executor descriptor can be internally consistent after the Supervisor head
has advanced, after the assignment has terminated, or before the sender has durably acknowledged
receiver admission.

The later Capability, approval, Permit, Gateway, and Worker bridge also needs a crash boundary.
Retrying a specialist action after an uncertain dispatch can duplicate target effects. Treating a
plain serialized row as dispatch authority would reissue that authority after process restart.

## Decision

Add a first, non-executing AGENTIC-003C slice to the Linux descriptor-bound coordination store.

The store issues a process-local `VerifiedAdmittedSpecialistAssignment` only after it independently
revalidates all of the following against the exact current durable head and current Graph head:

1. the outbox command is `assign` or `follow-up` and is in `acknowledged` state;
2. the receiver inbox receipt, delivery claim, sender acknowledgement, command digest, and receiver
   identity match exactly;
3. the command belongs to one immutable Supervisor cycle and one selected Candidate;
4. the Candidate proposal maps to the current deployment-fixed Exploit Group specialist; and
5. the issued command is nonterminal and the target Agent Session still owns the exact Task and
   Candidate.

Raw commands, receipts, Candidates, decisions, audit rows, and caller-constructed values remain
non-authoritative. The verified handle is store-local, immutable, non-copyable, non-serializable,
and consumable once.

Reservation inserts one `agentic_specialist_executions` row with the exact durable checkpoint,
Graph Snapshot, cycle, command, admission receipt, Task, Candidate, proposal, target, threat class,
specialization, and specialist-definition digests. A unique command constraint and write
transaction make concurrent reservation single-winner. Existing reservation is never returned as
new authority.

The only state transition is:

```text
reserved -> dispatch-started-outcome-unknown
```

The transition consumes a store-local reservation handle and uses a row-state digest compare-and-
swap. There is no lease expiry, timeout recycling, rewind, deletion, or automatic redispatch. A
restart can read the audit entry but cannot reconstruct either one-use handle. Full-history reload
replays the admitted assignment at the pinned historical checkpoint and rejects schema, trigger,
canonical-wire, index, timestamp, digest, transport, Candidate, specialist, or checkpoint drift.

Every durable entry keeps automatic redispatch, execution, Finding, and Graph authority at literal
false. Entering `dispatch-started-outcome-unknown` occurs before any future external I/O; this slice
does not call a target, browser, Gateway, Worker, Provider, or delivery system.

## Consequences

### Positive

- Receiver admission alone cannot authorize a specialist action; sender acknowledgement is also
  required.
- Verification-to-reservation and reservation-to-dispatch head changes fail closed.
- Concurrent callers cannot reserve or begin the same assignment twice.
- Crash recovery preserves uncertainty without silently repeating target effects.
- Later governed execution receives an opaque local handoff point instead of trusting by-value
  lifecycle or executor objects.

### Tradeoffs and residual risks

- This slice reserves and fences work but creates no Campaign Scope, Capability, approval, Permit,
  Gateway policy, Worker job, browser/network provenance, Evidence, Finding, or Graph authority.
- `dispatch-started-outcome-unknown` deliberately becomes stuck if the future bridge crashes after
  the CAS. Recovery requires explicit reconciliation; automatic retry remains prohibited.
- Current Graph verification and the coordination-store transaction are separate durable stores,
  not one distributed transaction. AGENTIC-003C2 must reverify the current Graph immediately before
  its governed action boundary and must not accept caller-supplied Graph or executor state by value.
- Hosting-process integrity remains part of the TCB. Python `object.__setattr__`, private testing
  factories, or arbitrary same-process code execution are process compromise, not a supported
  authority boundary.
- The local pre-release coordination schema advances from version 2 to version 3. Existing draft
  stores fail closed and are not migrated; no production store compatibility claim exists yet.
- Finding validation, Graph admission, report, SARIF, and redacted PoC projection remain
  AGENTIC-003D work.

## Compatibility, migration, and rollback

The public Campaign, Web, Capability, Permit, Gateway, Worker, Finding, and Graph APIs are
unchanged. The new methods are additive and no production caller consumes them. Rollback removes
the reservation table, methods, and tests and restores the previous pre-release schema version.
Any version-3 draft coordination store must be retained only as audit evidence or recreated from
its original immutable inputs; it must not be silently downgraded.

## Rejected alternatives

### Treat the inbox receipt as execution authority

Rejected because receiver persistence does not prove that the sender recorded the acknowledgement
or that the assignment remains current.

### Return a prior reservation on retry

Rejected because an audit row cannot prove that the caller still owns the original process-local
one-use authority.

### Expire and recycle uncertain dispatches

Rejected because timeout does not prove that external I/O did not occur.

### Let the caller pass a profile, executor, or observation into the reservation

Rejected because by-value objects do not prove current code-owned routing or runtime provenance.

## Related documents

- [ADR-0306: Publish Durable Agentic Coordination without Execution Authority](0306-publish-durable-agentic-coordination-without-execution-authority.md)
- [ADR-0308: Bind Specialist Profiles to Closed Executor Definitions](0308-bind-specialist-profiles-to-closed-executor-definitions.md)
- [AGENTIC-003 governed specialist execution](../orchestration/AGENTIC-003-governed-specialist-execution.md)
