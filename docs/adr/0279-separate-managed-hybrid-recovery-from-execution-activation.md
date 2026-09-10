# ADR-0279: Separate Managed Hybrid Recovery from Execution Activation

Status: Accepted

## Context

OPS-002 rehearsed a selected Linux/PG17/SQLite/RunStore configuration using a test controller.
OPS-001 enrollment remains SQLite-specific. Operators need a finite cold recovery procedure without
silently importing test fixtures into a runtime API or turning restored state into fresh authority.

## Decision

Add an independent OPS-003 operator command for a pinned, fully enumerated managed Docker deployment
on one Linux host. Inspect exact participants, require disabled automatic restarts, stop and observe
writers, verify domain state and capture one complete encrypted checkpoint. Retain an independent
pin and original verification keys. Restore only to a separate empty target and compare all rows,
Graph/journal evidence and Run seals. Preserve uncertain calls and elapsed budgets.

Recovery verification never starts execution Workers. A later resume requires a separately signed
recovery authorization and the current authenticated CP approval/continuation transaction. Existing
Scope, Capability, Policy and Permit checks remain downstream authorities. Additive versioned objects
leave OPS-001/002 and existing database formats/readers intact. Share original CP input verification
between SQLite and PostgreSQL without weakening either caller's row-source validation.

## Consequences

The operator must independently establish complete participant and state membership. This first
procedure supports manifest-bound campaign-only local journals and fails closed on unsupported
producer modes. Administrative Docker access belongs only to the recovery controller. Current
physical-host failure, unregistered writers, external supervisors and distributed failover remain
outside the evidence. Mid-operation failure keeps targets quarantined and sources recoverable;
external rollback stays unknown. Changing verifier code or layout requires explicit compatibility
review, not in-place archive migration.
