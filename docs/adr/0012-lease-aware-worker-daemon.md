# ADR 0012: Lease-aware Control Plane Worker daemon

- Status: Accepted
- Date: 2026-07-12

## Context

ADR 0011 made Run, Job, checkpoint, approval, and event state durable, but execution still required a
caller to manually claim and complete each Job. A production Worker must survive temporary Control
Plane failures, retain a lease while a campaign is active, stop when its identity is rejected, and
translate existing PAJIN execution results into durable state without allowing a submitted payload
to select a process command or Python callable.

## Decision

PAJIN adds an asynchronous Worker daemon and a typed Control Plane client. One HTTPX `AsyncClient`
is retained for connection pooling. Connect, read, write, and pool timeouts are explicit. Claim uses
a server-side long poll bounded to 20 seconds. Transport and 5xx failures back off; 401/403 is fatal;
409 means the lease is stale and cancels the in-flight execution.

The daemon processes one Job at a time. It starts a heartbeat task before dispatch and keeps it alive
through completion, failure, or checkpoint finalization. Temporary finalization failures are retried
with the same lease token, and the Control Plane completion operation remains idempotent. If a
heartbeat loses ownership, the execution and finalization tasks are cancelled and no stale result is
submitted. SIGTERM/SIGINT stops new claims and lets the active operation drain while its heartbeat
continues. An abrupt process or container death leaves no cleanup call; PostgreSQL lease expiry
requeues the Job with a new token and incremented attempt.

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
- A status file contains only Worker ID, state, active Job ID, count, timestamp, and bounded error.
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
`job.lease-expired-requeued` event. Unit coverage verifies heartbeat cancellation, transient
completion retry, stale lease rejection, long-poll bounds, invalid payload rejection, and both real
execution adapters.

## References

- [HTTPX asynchronous client](https://www.python-httpx.org/async/)
- [HTTPX timeout configuration](https://www.python-httpx.org/advanced/timeouts/)
- [Python asyncio task coordination](https://docs.python.org/3/library/asyncio-task.html)
