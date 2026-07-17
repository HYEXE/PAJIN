> Languages: [English](0012-lease-aware-worker-daemon.en.md) | [한국어](0012-lease-aware-worker-daemon.ko.md)

# ADR 0012: Lease-aware Control Plane Worker daemon

- Status: Accepted
- Date: 2026-07-12
- Amended by: [ADR 0024](0024-cooperative-execution-cancellation.en.md)

## Context

ADR 0011 made Run, Job, checkpoint, approval, and event state durable, but execution still required a
caller to manually claim and complete each Job. A production Worker must survive temporary Control
Plane failures, retain a lease while a campaign is active, stop when its identity is rejected, and
translate existing PAJIN execution results into durable state without allowing a submitted payload
to select a process command or Python callable.

## Decision

PAJIN adds an asynchronous Worker daemon and a typed Control Plane client. One HTTPX `AsyncClient`
is retained for connection pooling. Connect, read, write, and pool timeouts are explicit. Claim uses
a server-side long poll bounded to 20 seconds. Transport and 5xx failures back off; 401/403 is fatal.
A 409 is a terminal Worker state or ownership fence: structured codes distinguish a cancelled Run
from lease rejection, while an older or untyped 409 fails closed as `lease-lost`.

The daemon processes one Job at a time. It starts a heartbeat task before dispatch and keeps it alive
through completion, failure, or checkpoint finalization. Temporary finalization failures are retried
with the same lease token, and the Control Plane completion operation remains idempotent. While the
executor task is active, heartbeat ownership loss or unavailability signals the typed,
first-write-wins execution cancellation context. It gives the executor a bounded cooperative cleanup
grace period before forced async task cancellation, and no stale result is submitted. After the
executor has returned, a heartbeat or finalization conflict cancels result submission immediately;
it does not reopen the engine or claim that runner cleanup occurred.

SIGTERM/SIGINT stops new claims and signals an active execution with `daemon-shutdown` rather than
waiting for an unbounded drain. The same cooperative grace and forced fallback apply. An abrupt
process or container death still leaves no cleanup call; PostgreSQL lease expiry requeues the Job
with a new token and incremented attempt. ADR 0024 defines the cancellation sources, local runner
receipts, and their evidence boundary.

`ExecutorRegistry` is the execution authority. The submitted Job kind is only a key into a trusted,
startup-time registry. There is no command, module, class, script path, URL, or executable field in
the Job contract. Unknown kinds and strict payload-validation failures are permanent failures, and
validation values are not copied into Control Plane error text.

Two adapters form the first vertical slice:

| Kind | Trusted adapter | Existing PAJIN boundary |
|---|---|---|
| `campaign` | `CampaignJobExecutor` | `LocalCampaignRunner`, Policy Engine, Tool Gateway |
| `tool-loop` | `ToolLoopJobExecutor` | `PolicyToolLoopRunner`, Provider Gateway, Secret Lease, Capability Ledger |

The campaign profile accepts only deterministic `mock-agent` and `mock-sleep` targets. The Tool Loop
profile uses a no-network deterministic Provider fixture and the T3 `mock.approval-probe`. It is a
safe integration fixture, not a production model backend. It still exercises the real Tool Loop,
Provider Tool, Secret Lease, Capability, policy re-entry, and checkpoint code.

When Tool Loop execution reaches `awaiting-approval`, the adapter uploads its complete typed
checkpoint and exact pending intent. The Control Plane adds source Job kind and retry bounds to the
signed payload. Resume consumes an approval once, preserves the source kind, and includes a trusted
approval snapshot in the continuation Job. The adapter reconstructs `ToolLoopApproval` and calls the
existing runner's resume path.

## Delivery semantics

The queue provides at-least-once execution, not exactly-once tool side effects. Completion and
checkpoint finalization are idempotent, but a Worker can die after an external Tool performed an
effect and before the result was committed. Production Tool adapters must use destination-supported
idempotency keys where available, otherwise expose the replay risk to policy and require approval.
The checkpoint's one-time claim prevents two continuation Jobs; it cannot make arbitrary external
systems transactional with PostgreSQL.

## Operations and security

- Worker bearer credentials are never written to status, Job, event, checkpoint, or artifact data.
- A status file contains only Worker ID, state, active Job ID, count, timestamp, bounded error, and
  the last secret-free typed cancellation snapshot.
- `PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS` defaults to 2 seconds and
  `PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS` defaults to 5 seconds; each accepts 0.05 through 30.
- The daemon may consume one grace window and two forced windows before it abandons a still-pending
  task. The process supervisor must allow more than `grace + (2 * force)` plus scheduling margin.
- These bounds require a live asyncio event loop and do not preempt synchronous blocking code. A
  backend cleanup must fit the same window. `DockerWorkerBackend` has a separate 20-second internal
  cleanup cap, so an adapter embedding it needs a forced window greater than 20 seconds and a larger
  supervisor allowance than the deterministic Compose profile.
- The Compose Worker is non-root, read-only, capability-free, and has writable tmpfs only for status
  and lab artifacts.
- Compose uses a six-second lease only to make crash tests fast. Production should size lease and
  heartbeat intervals for its latency and recovery objectives.
- Production execution adapters must retain the existing isolated Worker and egress boundaries. The
  deterministic in-process adapters are local verification profiles.
- Artifact tmpfs in Compose is ephemeral. Production needs a durable evidence store with retention,
  encryption, access control, and Run-to-object integrity metadata.

## Validation

The Docker scenario verifies submission-only automatic execution, T3 approval pause, authenticated
approval, continuation resume, and completion. A second scenario forcibly kills the Worker during a
five-second campaign, waits past the lease, restarts it, and verifies attempt two completes with a
`job.lease-expired-requeued` event. Unit coverage verifies typed heartbeat and shutdown
cancellation, cooperative grace and forced fallback, transient completion retry, stale lease
rejection, long-poll bounds, invalid payload rejection, both real execution adapters, and sealed
local cancellation receipts.

## References

- [HTTPX asynchronous client](https://www.python-httpx.org/async/)
- [HTTPX timeout configuration](https://www.python-httpx.org/advanced/timeouts/)
- [Python asyncio task coordination](https://docs.python.org/3/library/asyncio-task.html)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.en.md)
