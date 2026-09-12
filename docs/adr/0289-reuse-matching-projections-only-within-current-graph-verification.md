# ADR 0289: Reuse matching projections only within current Graph verification

Status: Accepted

## Context

GRAPH-PERF-003 limited retained historical Snapshot objects but left repeated model validation.
A separate Linux diagnostic of the frozen large-history fixture measured 17.59 seconds with
cProfile, including 10.68 seconds in historical Snapshot verification. Node and edge identity
validators repeatedly serialized embedded Projection content that had already been validated
against the complete Event Log in the same read transaction. Instrumented time is not an
uninstrumented latency claim.

## Decision

For the current-Snapshot path only, pass the transaction's fully verified Projection to the
private Snapshot row reader. Before substitution, compare every decoded embedded Projection
field with that verified model's complete JSON representation. Then validate the Snapshot model,
its original canonical bytes, indexes, ordinals, chain and final current head as before.
There is no digest-only admission, unvalidated model construction or trusted persisted cache.

The original canonical-byte comparison remains essential: Python equality can equate an integer
and a floating-point spelling, while JSON decoding can erase duplicate keys. Neither may be
accepted merely because its decoded mapping matches the verified Projection.

The model instance is reused only inside this verified transaction. Existing defensive copies
remain at public read boundaries. Full history, backup and recovery paths keep their original
independently constructed Snapshot objects. No model-wide revalidation configuration changes.
[Pydantic's model-copy behavior](https://pydantic.dev/docs/validation/latest/concepts/models/#attribute-copies)
supports instance reuse; PAJIN must supply its own verified provenance and preserve mutable-child
isolation. Library behavior alone is not evidence authority.

## Consequences and validation

Every stored Projection still receives complete validation and exact Event Log replay comparison.
Every historical Snapshot still receives content, model, canonical-byte, index and chain checks,
including discarded rows and requests for a missing Snapshot. Cache limits, full-file hashes,
schema/integrity checks, current-head checks and concurrent-change handling stay unchanged.

Regression checks cover canonical-but-wrong nested projections, equivalent numeric spellings,
duplicate keys, extra fields, caller mutation, historical independence and existing corrupt history,
stale/current concurrency, size-boundary and fallback cases. Performance comparison uses frozen
before/after sources with only the Graph store changed, separate Linux processes, observed guest
file-page residency and the same bounded runtime. Physical storage caches and operating SLOs are
outside this measurement. Validation remains proportional to complete stored history.
