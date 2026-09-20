# UX-014: Review work filters and preserved continuation

## User flow

The Console can filter saved reviews and personal assignment notifications by
current assignee (all, me, unassigned or a specific identity), state and unread
notifications for the connected identity. Apply filters starts both lists at their
first page. Ten review records are verified per request; a page with no matches
can still offer another page. Concurrent new reviews require an explicit refresh.
Changing a control without applying it does not alter the current pagination.

Marking a notification read uses an independent receipt and consumes no review
revision. It works for assignment revision 200. At capacity, an Operator can open
a linked follow-up with a title and reason. It preserves the same historical
baseline evidence, starts open and requires a new assessment and distinct review.
The original record, assessments, decisions and acknowledgment history remain
available by ID and in downloaded reports. No test or external notification is
started by these controls.

## Endpoints

| Endpoint | Authorized roles | Result |
| --- | --- | --- |
| `GET /v2/measured-reviews` | Operator, Approver, Auditor | `pajin.dev/review-search/v1` |
| `GET /v2/measured-review-inbox` | Operator, Approver, Auditor | `pajin.dev/review-inbox/v2`, personal recipients only |
| `POST /v2/measured-reviews/{id}/notification-ack` | Current Operator or Approver, eligible recipient | Immutable `pajin.dev/review-notification-receipt/v1` |
| `GET /v2/measured-reviews/{id}/notification-receipts` | Operator, Approver, Auditor | Complete bounded, verified receipt list |
| `POST /v2/measured-reviews/{id}/follow-up` | Operator | New `pajin.dev/measured-human-review/v3` |

Worker credentials are refused even when they also carry a human role. Existing
v1 routes remain available. The existing Markdown report includes independent
receipts and a follow-up's predecessor reference when present.

Search accepts `assignee`, `unassigned`, `state`, `unread` and `cursor` only.
`assignee` and `unassigned=true` conflict. State is `open`, `awaiting-review`,
`changes-requested` or `accepted`. Responses echo applied filters, `scannedReviews`
and `nextCursor`; list items include assignee, unread count and `historyFull`.
Duplicate or unknown query keys and read bodies return 400. Invalid filters or a
cursor with a different principal/filter/endpoint scope return 422. Every scanned
review and receipt is verified before filtering, including nonmatches.

Acknowledgment accepts `requestKey`, `notificationId` and `assignmentRevision`
(2 through 200). The notice ID binds the immutable assignment digest, so a later
review edit does not invalidate it. Exact retries return the original receipt;
key reuse with different data, wrong recipients, changed identity or an already
acknowledged assignment returns 409. Legacy and new acknowledgments share the
same logical acknowledged state without rewriting either record format.

Follow-up accepts `requestKey`, `expectedRevision` (exactly 200), `expectedDigest`,
`title` (1..180 characters) and `reason` (1..1000). A stale or nonfull predecessor
returns 409. Exact retry returns the original new review. Different request keys
are separate explicit continuation intents. Reading the new review verifies its
immediate predecessor's complete journal and baseline evidence equality. This is
a bounded one-hop reference check, not recursive validation of all ancestors.

Unauthenticated requests return 401, disallowed roles 403, absent records 404 and
stored integrity conflicts 409. The server remains the source of saved state.
The Console preserves failed write intent, rejects duplicate submission while
busy, discards stale auth responses and restores focus after list replacement.

## Storage and upgrade

[ADR 0296](../adr/0296-preserve-full-review-audit-with-independent-notification-receipts.md)
defines schema 16 to 17 migration, role and concurrency boundaries. The new table
is append-only, has an assignment foreign key, and is limited to 398 canonical
receipts per review. Receipt bounds are four KiB each; review bounds stay at 200
revisions/eight MiB. Reads preflight receipt JSON size before ORM hydration.
The read pipeline validates payload digests, SQL-column equality, original
assignment, eligible recipients, timestamp ordering and exact request bindings.
A receipt timestamp before its assignment, or a follow-up timestamp before its
predecessor's last revision, returns 409 before any insert. Clock rollback cannot
create a record that the subsequent integrity reader rejects.

Existing v1/v2 journal bytes and digests remain unchanged. Deploy compatible
readers and recovery tools before new writes. Schema downgrade by dropping data is
unsupported; an authorized restoration of a pre-migration backup follows the
existing operational recovery contract. No production migration or deployment is
implied by isolated tests.

## Verification status

Local API and regression tests cover revision-200 acknowledgment without journal
changes, role/recipient checks, exact retry and concurrent writes, legacy/new
acknowledgment conflicts, append-only and corruption rejection, preserved follow-up,
filtered cursor scope, clock rollback and exact schema-16 migration.

An actual, freshly owned PostgreSQL 17.11 TLS server passed 69 tests in 113.00
seconds, including ten explicit review-work probes plus the existing repository
and Replay PostgreSQL suites. Probes verified revision-200 receipts across restart,
concurrent exact retry, demotion, filters and cursor scope, both legacy/new
acknowledgment orders, simultaneous legacy/new writes with one winner, exact
schema-16 upgrade with byte-preserved old history, statement-level UPDATE/DELETE/
TRUNCATE/ON-CONFLICT mutation refusal, and concurrent follow-up retry preserving
the full predecessor. Every connection used `sslmode=verify-full`; an independent
owned-label observation confirmed no container or volume remained afterward.
This was an isolated database, not a production migration or cross-host recovery.

An actual browser against a fresh loopback test database verified assignee,
unread, state and unassigned filters, applied-versus-draft filter state, keyboard
submission and focus restoration. At revision 200 the test saved a receipt and
deliberately lost its response; retry sent the identical key and payload, returned
the original receipt and left every original journal byte unchanged. It also
verified auth reset, a linked open follow-up and reopening its predecessor.
Desktop 1440 by 1000 and mobile 390 by 844 layouts had no horizontal overflow;
screenshots were inspected. The only browser request error was the deliberate
lost response. Screen-reader behavior was not observed. The later clock rollback
guards were checked with focused API tests; they were not part of that browser
run. The test browser and both owned loopback servers were closed afterward.
