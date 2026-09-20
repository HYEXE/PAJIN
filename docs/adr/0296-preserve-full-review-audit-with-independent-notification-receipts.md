# ADR 0296: Preserve full review audit with independent notification receipts

Status: Accepted

## Context

UX-013 records assignment acknowledgments in the same 200-revision journal as
assessments and decisions. The last assignment can therefore leave a recipient
unable to acknowledge it. Review discovery also lacks work-oriented filters.
Raising the journal limit would increase verification and rendering costs without
providing a finite continuation contract.

## Decision

Keep the existing 200-revision and eight-MiB history bounds and all v1/v2 bytes.
Schema 17 adds `cp_review_notification_receipts`, an append-only table with one
row per immutable assignment revision and recipient. A canonical receipt binds
the assignment digest, review, authenticated actor and role, timestamp and exact
request identity. A foreign key binds it to the retained revision. Unique actor
request keys provide exact retry recovery in a separate receipt namespace.

An assignment has at most two recipients; at most 398 four-KiB receipts can exist
per review. Verify the complete review and receipt set before serving an inbox,
filtered result or report. Preflight the stored receipt count and total JSON bytes
before loading the set. Legacy acknowledgments and independent receipts cannot
acknowledge the same assignment-recipient pair twice. All review mutations and
new receipt writes lock the opening row on PostgreSQL; SQLite uses its existing
immediate writer transaction. Current roles are checked on every operation.

A new Operator-only follow-up command requires the exact revision-200 head and
explicit continuation reason. It creates a new v3 opening record with the same
historical baseline evidence and a predecessor identity and digest. The new review
starts open, without inherited assessment, decision, retest or assignee. Original
rows are never rewritten. Reads verify the immediate predecessor's complete
bounded journal and evidence equality, not an unbounded recursive lineage. A
missing or corrupt immediate predecessor refuses the read. Following another
predecessor requires opening that review separately.

Add filtered v2 discovery for current assignee, unassigned, review state and the
current principal's unread notifications. Scan at most ten fully verified review
journals per page before filtering, including nonmatching journals. An empty page
may have a continuation cursor. Bind canonical cursors to principal, filters,
endpoint kind and last scanned review. Cursors are pagination inputs, never
credentials or snapshot-isolation claims. The Console keeps draft controls apart
from applied filters, resets cursors on apply and discards responses across auth
changes. Failed writes retain their exact request key and payload.

## Compatibility and recovery

Exact schema 16 upgrades add an empty table and guards without rewriting existing
review or execution data. Partial or inconsistent schema histories are refused.
Readers and recovery tools must support schema 17 and v3 before the first new
write. Older binaries refuse the new schema; reverting application code alone is
not a supported rollback. Restore an independently retained pre-migration backup
under the existing recovery procedure if necessary. Never drop receipt or follow-up
rows to manufacture an older schema. Existing v1 endpoints and v1/v2 serialized
records retain their behavior, including the legacy acknowledgment capacity limit.

The new endpoints grant no execution, approval, generic Finding, SARIF or external
delivery authority. Notifications remain inside the application. Demotion to
Auditor retains read access but removes acknowledgment permission. Receipt integrity
checks do not independently prove freshness if all database state is rolled back;
operational checkpoint and witness requirements remain separate.
