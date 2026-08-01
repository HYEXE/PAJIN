# ADR-0082: Durable Fenced Target Operations Before Provider-Specific Adapters

- Status: Accepted
- Date: 2026-08-01

## Context

P0-C1 guarantees cleanup for ordinary Python exception paths after isolation, but creates its
sealed Run only after the complete provider lifecycle. A process or host loss can therefore leave a
provider environment active while losing the local receipt needed to prove or retry cleanup. A
Docker-only fix would couple crash recovery to one provider and leave the authority contract
undefined.

## Decision

1. Keep the P0-C1 adapter and completed Run wire formats unchanged.
2. Add a recoverable provider Protocol whose calls receive content-addressed idempotency operation
   IDs and a monotonically issued fence.
3. Require providers to make operation IDs idempotent and reject stale fences.
4. Persist intent before each provider call and validated receipt or stable error classification
   afterward in a synchronous SQLite journal.
5. Reconcile every open attempt before new reset work, using a newer fence and bounded cleanup
   retries, including when no isolation receipt was returned.
6. Seal every reconciliation result as a content-addressed, measurement-ineligible failure
   authority before marking an attempt reconciled.
7. Keep actual Docker/provider evidence, network enforcement, and measurement-key registry work in
   P0-C2B because the current Docker daemon is unavailable for truthful live validation.

## Consequences

- A hard process exit leaves enough durable intent to discover and clean provider resources on the
  next start.
- A stale local writer cannot append journal results after a recovery fence supersedes it, provided
  the provider also enforces the contract fence.
- Unresolved cleanup blocks new work instead of becoming a successful or measured Benchmark Run.
- Recovery audit is explicit and sealed but does not claim provider-signed measurement truth.
- The SQLite journal is a single-filesystem coordination mechanism; provider fencing remains the
  cross-host truth root.

## Compatibility and rollback

The new models, Protocol, Runner, journal, reader, artifacts, and events are additive. Existing
P0-C1 callers keep their behavior. Rollback removes the P0-C2A layer and returns to P0-C1's
documented lack of hard-exit recovery; no existing wire format requires migration.

## Related documents

- [P0-C2A contract](../benchmark/P0-C2A-durable-target-operation-recovery.md)
- [ADR-0081](0081-provider-neutral-benchmark-target-lifecycle.md)
- [P0-C1 contract](../benchmark/P0-C1-provider-neutral-target-factory-lifecycle.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
