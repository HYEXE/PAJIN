# ADR-0265: Bind Urgent Cancellation and Worker Observations to the Control Plane Journal

- Status: Accepted
- Date: 2026-09-08

## Context

The collaboration fast gate admits a metadata-only stop-and-escalate decision. It does not
identify an authorized Control Plane cancellation target. Existing cancellation durably revokes
Jobs and approvals, but clears the lease proof and retains Worker cleanup observations only in
local status and sealed Run artifacts. A committed cancellation alone cannot prove execution
quiescence, and an operator cannot see or acknowledge the urgent decision in the Console.

## Decision

Add an explicit trusted-host `UrgentStopRuntime` that owns the complete admission inputs and a
fixed binding to the CP Run, immutable submission digest, canonical Campaign, exact sealed source
Run/root, result artifact, terminal handoff and fast-gate authority. Require an already configured
Run-cancellation ABAC rule. Do not expose an HTTP endpoint accepting a decision, binding, verifier
or source path as cancellation authority.

Its `admit` method resolves the terminal authority, verifies the sealed source Campaign and
binding, admits and re-verifies the existing fast-gate decision, then invokes the durable consumer.
The original decision remains `admitted-not-applied`; a separate application records the applied
CP cancellation. Keep the existing Job/Approval/Run lock ordering and authorization. Append the
application alert in the same transaction as Run/Job cancellation and approval revocation. A
handoff cannot be applied to another target. Matching retries reuse the original application and
decision time after full verification; equivocation fails closed.

Before clearing a leased Job, append a purpose-separated commitment to its lease hash. The
authenticated original Worker can present the old lease on the matching generic or Replay
stop-observation route. This proves only ownership of the cancelled lease. It cannot heartbeat,
renew, finalize, obtain a permit, or resume execution. Preserve existing actor-bound and legacy
lease semantics; never store or expose the raw lease or its reusable hash in an event.

The default Worker entry points report the minimized final local cancellation snapshot after
draining their tasks, using the authenticated CP client. Preserve the original cancellation error
if delivery fails and expose delivery status locally. A Worker report is distinct from sealed
cleanup evidence and independent resource attestation. In particular, a Replay daemon's drained
stack does not promote its child Run's cleanup evidence into whole-host quiescence.

Use the existing append-only CP event journal rather than adding an independent store or changing
schema v16. Human read and operator acknowledgment routes expose bounded alerts and Worker report
counts. Acknowledgment is append-only, idempotent and has no execution effect. Console locking and
credential changes clear all alert data and discard stale responses. No external messages are sent.

## Consequences and limits

Explicit trusted runtime composition is required; constructing a fast-gate decision alone still
does not stop a Run. The initial binding targets a manifest-bearing CP submission, not an inferred
Replay or cross-Run target. The complete host inventory, first-work binding and cross-store recovery
remain separate obligations under OPS-001. Process-local terminal/Graph verifier objects are not
reconstructed from their public IDs. Graph/source checks and the CP transaction are not a distributed
transaction. A copied database or local commitment is not an independent rollback anchor.

Old cancelled Jobs without a recorded lease commitment cannot submit newly invented stop reports.
Missing reports and interrupted delivery remain unknown. Exact duplicate delivery is supported,
but a different later report cannot silently replace the first. Mixed executable versions require
the existing quiescent deployment discipline; old daemons do not produce the new observations.
Raw observation content, cleanup errors, credentials and local paths do not enter public alerts.
