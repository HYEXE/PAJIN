# ADR 0295: Share equal verified Graph prefixes and bound historical read caching

Status: Accepted

## Context

GRAPH-PERF-005 reduced serialization work but retained a separate complete node and
edge object graph for each stored Projection prefix. UX-012 also fully verified
the same database on every historical page request. Larger histories therefore
retained substantial duplicate objects and repeated verification work.

## Decision

Continue validating every persisted Event, node index, Projection, and Snapshot:
canonical bytes, complete model fields, row indexes, exact event-prefix equality,
digests, chain continuity, schema, and current head checks remain mandatory.
After a Projection passes those checks, its internal node and edge tuples may
reuse the equal objects already validated in the replayed Event prefix. No digest
substitutes for full field equality. Public Snapshot readers return independent
copies; shared objects never become mutable caller state.

The Campaign browser owns one historical selection cache across its entire
deployment registry. A cache hit requires the same absolute path and file
identity, schema/integrity checks under a DELETE-journal read transaction, fresh
hashes of all database bytes before and after copying, and an independent history
head check. Campaign, selected Snapshot, catalog offset and limit are part of the
key. The requested catalog state must match on every hit and miss.

An entry retains at most 50 scalar catalog entries and one selected Snapshot.
Database and serialized Snapshot bounds are 256 MiB and 16 MiB, respectively;
Python object overhead is additional. Oversized inputs use complete verification
without retention. File replacement, changed bytes, changed schema, WAL mode,
stale state, or a failed read cannot reuse an entry. A process-local lock
serializes access to the one entry. Authentication, admission, execution and
approval decisions are never cached.

## Consequences

The wire format, stored Graph bytes, current-read API and history authority
boundary are unchanged. Reading a different historical selection can evict the
entry, and each process has its own cache. RSS is measured rather than inferred
from the serialized size limit. The complete-history export intentionally retains
its existing independent public objects.

GRAPH-PERF-006 measures current pages, catalogs and historical pages with separate
Linux reader processes. It samples simultaneous summed reader RSS; shared pages
count once per process, so this is not unique physical-memory usage. Guest page
residency is observed, while host/device cold-cache and production SLOs remain
outside the measurement.
