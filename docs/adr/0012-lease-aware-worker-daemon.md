# ADR 0012: Lease-aware Control Plane Worker daemon

- Status: Accepted
- Date: 2026-07-12
- Amended by: [ADR 0024](0024-cooperative-execution-cancellation.md)

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
The authenticated client accepts only an origin-only HTTPS base URL. Plaintext HTTP is rejected
unless `PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB` is the literal `true`, and even then is limited to
loopback or the bundled `control-plane` Compose service name.

The daemon processes one Job at a time. It starts a heartbeat task before dispatch and keeps it alive
through completion, failure, or checkpoint finalization. Temporary finalization failures are retried
with the same lease token, and the Control Plane completion operation remains idempotent. While the
executor task is active, heartbeat ownership loss or unavailability signals the typed,
first-write-wins execution cancellation context. It gives the executor a bounded cooperative cleanup
grace period before forced async task cancellation, and no stale result is submitted. After the
executor has returned, a heartbeat or finalization conflict cancels result submission immediately;
it does not reopen the engine or claim that runner cleanup occurred.

Each claim and renewal maps the server heartbeat/expiry interval onto the event loop's monotonic
clock. The mapping is anchored at request start, so network and server latency consume rather than
extend the lease window. A heartbeat call is bounded by that deadline. If it stalls until expiry,
the daemon cancels the I/O, skips the cooperative grace, forces executor cancellation, and rejects
even a concurrently arriving completion response before another Worker can reclaim the Job.

Control Plane schema v10 persists a separate absolute `lease_deadline_at`. Claim sets it to no more
than 24 hours after the server claim time; Replay may narrow it to the compiled specification or
Grant expiry, but neither a heartbeat nor a late schema-v9 writer may extend it. The database
requires every leased row to have canonical expiry, heartbeat, owner, token, attempt, and deadline
authority within that horizon. A Job submission digest binds the immutable dispatch tuple and is
recomputed during migration, startup, and claim. Managed triggers also enforce the Run/Job state
machines, reject late old-writer inserts and row replacement/deletion, and make terminal history
immutable. Heartbeat transitions remain durable on every accepted renewal, while `job.heartbeat`
audit events are emitted at most once per 60 seconds. Lease expiry/reclaim checks both the rolling
expiry and the absolute deadline.

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

The `campaign` adapter also has an opt-in `capability-graph-v1` profile. It is unavailable unless
the daemon starts with both `PAJIN_CAPABILITY_GRAPH_DEPLOYMENT_PATH` and
`PAJIN_CAPABILITY_GRAPH_DEPLOYMENT_SHA256`. The no-follow, bounded JSON document is pinned by its
raw SHA-256 before parsing and contains the exact Campaign, CAP-004 lifecycle policy and public
trust keys, all seven signed first releases, the explicit activated subset, release/activation-set
digests, exact MissionEnvelope authority ceiling, Graph database, Run audit root, and Permit
compiler identity. The Envelope Campaign digest, compiler, and complete activated Capability set
must match the rest of that same pinned document. Partial configuration, unknown fields, digest
drift, signature failure, or durable writer drift stops daemon startup. The Job can provide only a
typed Proposal, Decision, request, release reference, and attenuating Gateway Grant inside that
deployed Envelope; it cannot choose a module, class, command, executable, plugin, Tool path, or
MissionEnvelope. Runtime Tools remain the closed CAP-005 inventory.

The profile consumes the SQLite `ActionPermit` before entering `ToolGateway`, records
`claimed` plus one terminal `completed`/`failed`/`cancelled`/`expired` event in the matching
hash-chained Run, and seals that Run mutation. A retry resolves the already-consumed Permit and
verifies the sealed lifecycle instead of invoking the Worker again. SQLite Graph authority,
RunStore audit, Control Plane PostgreSQL Job state, and an external Tool target are still separate
transactions; a consumed Permit with missing or unsealed terminal audit fails closed and is not
redispatched.

Before the Permit claim, the Worker seals an exact deployment/Run anchor. Reopen recovery seals any
hash-valid interrupted extension and classifies a consumed Permit with no `claimed` event as
`consumed-without-claim`, or a lone `claimed` event as `claimed-outcome-unknown`. Both states are
content-addressed, durably recorded once, require manual review, and permanently prohibit automatic
redispatch. A terminal lifecycle remains the only path that can report an observed dispatch status.

Both built-in profiles bind the canonical Worker execution context into the sealed Run and copy the
verified value into the optional completed-Job result fields `executionProfile` and
`executionContext`. The defaults are explicitly `simulated-development-only`; Docker-backed
adapters are `worker-observed-execution`, and other custom backends remain
`custom-backend-unclassified`.

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
- Worker bearer credentials are sent only to a validated HTTPS origin. The explicit plaintext flag
  exists solely for the isolated bundled Compose/loopback lab and must remain disabled remotely.
- A status file contains only Worker ID, state, active Job ID, count, timestamp, bounded error, and
  the last secret-free typed cancellation snapshot.
- Both Worker daemons replace status through one directory-descriptor-anchored writer. It creates a
  private random temporary leaf with `O_EXCL`/`O_NOFOLLOW`, fsyncs it, atomically replaces the
  destination without following symlinks, and fsyncs the parent directory.
- Host defaults live below `~/.pajin/status`, not a predictable leaf in shared `/tmp`. A custom
  parent must be owned by the daemon effective UID and not writable by group or others. Compose's
  explicit `/tmp` is a container-private UID-owned mode-0750 tmpfs. Health readers accept only a
  no-follow regular UTF-8 file of at most 64 KiB.
- That status guarantee and Tool Loop continuation-checkpoint isolation require POSIX dirfd,
  `O_NOFOLLOW`, effective-UID, and sticky-directory semantics. A native Windows daemon fails closed
  before either write with a clear error; use the Linux container or WSL. PowerShell-driven Docker
  Compose remains supported.
- `PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS` defaults to 2 seconds and
  `PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS` defaults to 5 seconds; each accepts 0.05 through 30.
- The daemon may consume one grace window and two forced windows before it abandons a still-pending
  task. The process supervisor must allow more than `grace + (2 * force)` plus scheduling margin.
- These bounds require a live asyncio event loop and do not preempt synchronous blocking code. A
  backend cleanup must fit the same window. `DockerWorkerBackend` has a separate 20-second internal
  cleanup cap, so an adapter embedding it needs a forced window greater than 20 seconds and a larger
  supervisor allowance than the deterministic Compose profile.
- The Compose Worker is non-root, read-only, capability-free, and has writable tmpfs only for status
  and lab artifacts. It also mounts separate named volumes for opt-in Capability Graph SQLite state
  and sealed Run audit. The default placeholder is not JSON and both deployment environment values
  are empty, so the profile remains disabled. An operator must mount the organization-issued JSON,
  set its in-container path (normally `/run/pajin-capability/deployment.json`), and provide the exact
  SHA-256. The bundled Worker backend is still simulated-development-only and does not satisfy the
  production Web+AI Campaign exit gate.
- Compose uses a six-second lease only to make crash tests fast. Production should size lease and
  heartbeat intervals for its latency and recovery objectives.
- The absolute server lease horizon is 24 hours regardless of configured rolling lease duration;
  long-running work must reach a new fenced Job rather than renew one authority indefinitely.
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
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
