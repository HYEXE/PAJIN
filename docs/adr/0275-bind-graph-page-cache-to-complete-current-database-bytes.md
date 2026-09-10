# ADR-0275: Bind Graph Page Cache to Complete Current Database Bytes

- Status: Accepted
- Date: 2026-09-10

## Context

Snapshot-bound pages reduce output size, but each page reparses every Event, rebuilds every
Projection prefix and verifies every Snapshot. The local GRAPH-PERF-001 profile measured 11.54
seconds per repeated 100-item page at 5,002 nodes / 10,000 edges, with six Projection recomputations.
Caching only file timestamps, head IDs, a cursor or an authorization decision would allow modified
historical input to evade the established verification path.

## Decision

Use one bounded, process-local verified Snapshot cache for the paged reader only. A hit requires
the same regular-file identity, Campaign, Snapshot and SHA-256 of the complete SQLite database.
Every request opens a read-only/query-only transaction, rechecks the exact schema and SQLite
integrity policy, and reads current Event/Projection/Snapshot heads. DELETE journal mode holds the
read view against normal SQLite writers. Hash the complete file before and after making a defensive
copy; refuse changed bytes, file identity or head. Return no shared mutable model to callers.

A miss uses the same complete verifier as before. Any byte change requires that verifier again;
exceptions evict the entry. Keep at most one Snapshot for a database no larger than 128 MiB and a
serialized Snapshot no larger than 16 MiB. Larger inputs and platforms without `O_NOFOLLOW` retain
complete verification without caching. No migration, cursor change, import removal or wire change
is introduced. The original full view and other authority readers continue their existing paths.

Authentication, grants, approvals, permits, current activation and external verifier decisions do
not enter the cache. API authorization remains per request; new application configuration creates
a new reader. Database writer/key metadata changes alter the input digest, while the existing
verifier still decides their admissibility. The cache adds no new trust anchor or execution authority.

## Consequences

Repeated page CPU falls substantially on unchanged inputs, but every hit still scans the full DB
twice, validates SQLite structure and copies the Snapshot. Cold reads and changing/oversize stores
still incur complete verification. A single reader serializes its cache access and retains one
bounded model. These tradeoffs are measured in GRAPH-PERF-001, not inferred as production SLOs.

The read linearizes within its SQLite transaction; a later committed change is checked on the next
request. This is not off-host rollback detection or protection against a compromised Python/Docker
host. A trusted-host mutation that replaces both data and an independently expected checkpoint
remains subject to the separate recovery contracts.

See [GRAPH-PERF-001](../benchmark/GRAPH-PERF-001-current-graph-page-cost.md) for reproducible
measurements and concurrency/tamper/configuration regression evidence.
