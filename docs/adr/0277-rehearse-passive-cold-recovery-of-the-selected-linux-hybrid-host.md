# ADR-0277: Rehearse Passive Cold Recovery of the Selected Linux Hybrid Host

- Status: Accepted
- Date: 2026-09-10

## Context

The operator selected a single Linux host with PostgreSQL 17 for the Control Plane,
local SQLite for Graph and execution journals, and local RunStore files. OPS-002's
first drill ran Python on a different host platform and used an in-process API
transport. Its PostgreSQL dump does not cover the selected deployment's complete state.
OPS-001's enrolled SQLite recovery API deliberately rejects a PostgreSQL Control Plane.

## Decision

Add a disposable Linux operational drill, using the existing real PostgreSQL
migration and contention assertions and actual TLS HTTP between the API process
and Worker. Only the test controller can access Docker; target Workers retain their
existing isolation. Verify running cancellation, durable alerts and physical absence
separately. Exercise process/container loss, never represent it as physical-host loss.

Rehearse a manual cold backup after stopping and inspecting every owned application
container, excluding new application writers and checking remaining database sessions.
Bind the PostgreSQL dump and complete local file inventory to one encrypted checkpoint.
Keep its expected digest and original verifier configuration outside both source and
restored state volumes. Restore only to a newly created database and empty volume,
then validate normal domain readers in a fresh Linux process before publication of
a successful report. Replacing, truncating, omitting or mixing checkpoint objects
must reject recovery. Source owners remain stopped while the restored state is checked.

This is a passive recovery rehearsal, not a new production recovery API or an
extension of OPS-001 enrollment. Unknown dispatches remain charged, require review
and cannot be redispatched through the invocation journal. No restored Worker starts
automatically. The test fixture's manually fenced writers do not prove exclusion of
unregistered production writers, distributed fencing, external rollback, live backup,
automatic failover, storage-device durability or readiness of an arbitrary host.

## Consequences

The selected configuration gains reproducible full-state operational evidence without
changing existing imports, schemas, runtime inventory policies or checkpoint readers.
Production rollout still requires its own host, storage, key custody, writer-fencing
and recovery activation review. A restored byte set never grants Scope, Capability,
Permit, approval or Finding authority.
