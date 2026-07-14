# ADR 0024: Cooperative execution cancellation and local cleanup receipts

- Status: Accepted
- Date: 2026-07-14

## Context

ADR 0023 made operator cancellation durable and fenced every supported Control Plane path that could
dispatch or commit a cancelled Job. A leased Worker learns about that fence through a rejected
heartbeat or finalization request. The daemon previously responded by immediately cancelling its
async execution task. That protected the Control Plane result boundary, but it gave the engine no
typed reason or bounded opportunity to seal partial evidence and finish registered cleanup.

The same ambiguity applied when heartbeat availability was lost or the daemon received a shutdown
signal. An executor could observe only an untyped `asyncio.CancelledError`, and an indefinitely
draining executor could delay shutdown. Docker cleanup covered expected cancellation and timeout
paths, but an unexpected `BaseException` could also leave an execution container or its egress
resources behind.

Cancellation has two distinct authorities. The Control Plane owns the durable Run and Job fence.
The process running an executor can report only what it observed and cleaned up locally. A local
receipt must not be presented as proof that an external target rolled back an effect or that every
distributed process is physically quiescent.

## Decision

Every claimed execution receives one typed `ExecutionCancellationContext`. The context is a one-way,
first-write-wins signal. It retains a normalized source, a bounded detail, and the time at which the
Worker observed the signal; a later failure or shutdown cannot replace the cause that first
initiated cancellation.
Supported sources are:

| Source | Meaning at the Worker boundary |
| --- | --- |
| `run-cancelled` | The Control Plane has fenced the Run as cancelled |
| `lease-lost` | The Worker no longer owns the Job lease |
| `heartbeat-unavailable` | The daemon cannot maintain the lease through its heartbeat channel |
| `daemon-shutdown` | The daemon stop signal arrived while execution was active |
| `caller-cancelled` | A runner invoked outside the daemon had its owning async task cancelled |

All state-changing Worker endpoints use the machine-readable conflict code `run_cancelled` when the
Run fence rejects heartbeat, completion, failure, or checkpoint creation; heartbeat is the normal
in-flight delivery path. Other lease rejection uses `lease_lost`. The Worker maps those codes to the
context sources above. The response detail remains generic: an Operator's cancellation reason is
audit data and is not disclosed to the Worker credential. Older servers that omit a code remain
compatible and map to `lease-lost`.

The daemon passes the same context through `ExecutorRegistry` into trusted built-in executors. It
does not derive an executable, callback, or cleanup command from Job input.
Registered Job adapters must accept the keyword-only cancellation context; legacy `execute(job)`
adapters are rejected at Worker startup instead of failing after a Job has been claimed.

When a terminal heartbeat condition or daemon shutdown wins the execution race, the Worker first
signals the context and gives the executor a configured, bounded cooperative grace period. An
executor that observes the signal may stop dispatch, unwind its Tool Gateway and Worker resources,
and finalize its local evidence. If it does not return before the grace period expires, the daemon
falls back to forced async task cancellation and waits only for bounded forced cleanup. The original
first cause remains authoritative across both phases. No completion, failure, or checkpoint result
from that execution is submitted after lease ownership has been lost.

If the executor has already returned, a heartbeat or finalization conflict is an immediate result
fence rather than a new cooperative cleanup phase. The daemon may retain a typed cancellation or
lease cause with an `executor-drained` status, but it does not signal a finished runner or synthesize
`cancellation.json` or `quiescence.json` for that finalization-only conflict.

The trusted `LocalCampaignRunner` and `PolicyToolLoopRunner` cancellation paths write
`cancellation.json` and append an integrity seal after their owned cleanup completes. The enclosing
trusted Job executor then writes `quiescence.json` and appends a second seal after the engine stack
has unwound. The two receipts distinguish:

- the cancellation source, bounded reason, and observation time;
- whether forced fallback was required and when it began;
- completion of cleanup owned by that local runner; and
- local engine cleanup from executor-stack quiescence.

Receipt creation is best effort when cancellation happens before a Run store exists or forced
fallback interrupts the runner. A missing receipt therefore means local cleanup was not attested;
it is never interpreted as successful cleanup. The receipt and its seal are evidence artifacts, not
a Control Plane state transition.

Docker execution cleanup attempts are widened to every exit path, including unexpected
`BaseException` propagation. Once launch has been attempted, the backend uses its known container
name to attempt bounded process termination, forced container removal, stream-task cleanup, and
per-execution egress teardown before preserving the original exception. Cleanup remains idempotent
because cancellation and timeout paths may race; a failed CLI attempt is not physical-cleanup
attestation.

## Trust and state boundary

The durable Control Plane Run still transitions directly to `cancelled`; this ADR does not add a
`cancelling` state. The current API also does not ingest, verify, or acknowledge a runner receipt.
Consequently, a sealed receipt supports only a process-local statement: the built-in runner observed
the typed signal and completed the cleanup steps that it owns before returning.

It does not prove any of the following:

- rollback of a Tool call or any effect already committed by an external system;
- termination of an executor that suppresses both cooperative and forced cancellation;
- physical quiescence of a remote Worker, child process, or distributed Agent fleet;
- cleanup after abrupt process death, host loss, or power failure; or
- destination-level exactly-once delivery.

The grace and forced deadlines are event-loop deadlines, not preemptive wall-clock guarantees.
Trusted executors must keep cancellation handlers non-blocking; synchronous cleanup or integrity
hashing that monopolizes the Python event loop cannot be interrupted by another asyncio timeout.
Strict wall-clock termination requires a separately supervised, killable executor process and is a
future isolation boundary.

A future protocol may add `cancelling`, Worker cleanup acknowledgement, signed receipt upload,
timeouts, and a Control Plane-authoritative physical-quiescence state. Such a protocol must define
late and missing acknowledgements without weakening the existing immediate dispatch/result fence.
External side-effect compensation remains a Tool- and destination-specific workflow rather than a
generic cancellation guarantee.

## Consequences

- Policy and audit code receive a stable cancellation cause instead of inferring one from exception
  text.
- Cooperative runners have a bounded opportunity to preserve partial evidence without allowing an
  unresponsive executor to delay the daemon indefinitely.
- First-write-wins semantics keep an operator cancellation from being relabelled as shutdown or a
  secondary heartbeat failure.
- Local cleanup receipts improve forensic confidence but intentionally do not change Control Plane
  authorization, Run state, or delivery semantics.
- The grace and forced-cleanup bounds become operational parameters. The supervisor window must
  exceed one grace plus two forced-drain windows and scheduling margin, and an embedded backend's own
  cleanup cap must fit inside those bounds while the event loop remains alive.

## Validation

Automated tests cover first-write-wins source retention, context propagation through the trusted
executor registry, cooperative completion before the grace deadline, forced task cancellation after
that deadline, heartbeat and daemon-shutdown source mapping, and the absence of stale finalization.
Runner tests verify sealed Local Campaign, Tool Loop, and Multi-Agent cancellation evidence; the
Control Plane Campaign executor test verifies the two-seal cleanup and quiescence sequence. Docker
backend tests exercise container and egress cleanup for cancellation, repeated cancellation,
timeout, and successful completion. Live Control Plane and Docker tests remain environment gated.

## References

- [ADR 0012: Lease-aware Worker daemon](0012-lease-aware-worker-daemon.md)
- [ADR 0016: Tamper-evident Run integrity](0016-tamper-evident-run-integrity.md)
- [ADR 0023: Fenced Control Plane actions](0023-fenced-control-plane-actions.md)
- [Python asyncio task cancellation](https://docs.python.org/3/library/asyncio-task.html#task-cancellation)
