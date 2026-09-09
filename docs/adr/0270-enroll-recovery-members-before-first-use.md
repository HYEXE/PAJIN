# ADR-0270: Enroll Recovery Members before First Use

- Status: Accepted
- Scope: OPS-001 local POSIX SQLite deployment
- Builds on: ADR-0268 and ADR-0269

## Context

A manually supplied checkpoint plan cannot establish that it includes every store actually used
by a deployment. Reopening a missing database can also manufacture an empty authority or budget.
Producer input digests are insufficient if they are never compared with original CP inputs.

## Decision

Add opt-in runtime inventory v3 with `recoveryPolicy: closed-local-sqlite-v1`. Enrollment creates a
private state directory and append-only recovery index with the exact original runtime inventory
bytes and host-gate identity. The gate is reserved before index creation; interrupted enrollment
cannot be repaired by repeating enrollment. Existing inventory v1/v2 serialization remains intact.

Record actual admitted components and register default CP SQLite, Graph, Run-bound journals and
RunStore directories before returning them to callers. Record canonical relative paths and domain
identities. Existing unregistered state, missing registered state, conflicting bindings and linked
paths fail closed. A crash between store creation and registration requires explicit reconciliation;
it never grants permission to silently adopt that state.

Supervisor invocation checks its enrolled Graph, journal, original CP input, Campaign and exact
sealed schedule/shared-source Runs before budget binding or claim. Its Campaign digest retains the
existing profile-compilation convention; Campaign-only Worker budgets retain their existing
component-digest convention. Urgent admission checks enrolled Graph/source Runs and the actual CP
repository before its existing authorized cancellation transaction. Registration grants no execution
authority and cannot change Campaign-only accounting into a Supervisor allowance.

Build checkpoint plan v2 from complete first-use registration under exclusive host exclusion.
Require every component in the original pinned inventory, all registered members, sealed Run
integrity and original typed CP inputs for journals. Pin all Run files. Repeat these checks on the
copied/restored set. V3 hosts reject manually declared v1 plans. Independently expected checkpoint
and plan identities remain required; registration alone is not a monotonic rollback authority.

## Consequences

This supported deployment uses one local CP SQLite database, SQLite Graph stores, durable journal
budgets and sealed Runs. Other provider stores, PostgreSQL, external cleanup and distributed writers
are outside the closed recovery set and are not silently imported. Deployment-specific producer
objects still require their existing trusted composition and source verification.

Restore remains passive, preserves historical references and creates no runtime gate. Automatic
relocation/reactivation, in-place legacy adoption and whole-host rollback detection without an
independent expected checkpoint are not provided. A valid offline restore proves the retained
checkpoint, not permission to resume execution at a new location.
