# UX-013: Review Assignment and Internal Notifications

## API and authority

The existing measured review workflow gains these additive endpoints:

| Endpoint | Authorized user / behavior |
| --- | --- |
| `GET /v1/measured-review-assignees` | Human read roles; configured Operator/Approver subjects |
| `POST /v1/measured-reviews/{review_id}/assignment` | Operator; `requestKey`, `expectedRevision`, `assignee` or null, `reason` |
| `GET /v1/measured-review-inbox` | Human read roles; only the caller's assignment notices |
| `POST /v1/measured-reviews/{review_id}/notification-ack` | Recipient with a current Operator/Approver role; `requestKey`, `expectedRevision`, `assignmentRevision` |

Worker credentials cannot use these routes. Unknown or Worker/Auditor assignees are
refused. The roster comes from the configured bearer/OIDC identity policy; input cannot
enroll a new identity. Role changes require normal deployment configuration changes.
The same subject may still read a retained notice after becoming an Auditor, but cannot
append an acknowledgment. This preserves the existing database's human writer roles.

Assignment/unassignment atomically appends an attributed, digest-bound command.
Old and new assignees receive the same immutable notice ID; an unrelated actor does
not receive it. Same-key retries recover the original revision; a changed request
using that key or a stale revision conflicts. Acknowledgments append to the same chain
and never modify evidence, assessment, decision or execution permission.

Inbox v1 returns `items`, `scannedReviews`, `nextAfter` and
`externalDeliveryAuthorized=false`. Each item identifies its review, assignment
revision, current review revision, actor, assignee, time and acknowledgment status.
Pages scan up to ten complete review histories. Follow `nextAfter` even when a page
contains no notices; restart from the first page to observe later changes to earlier
reviews. This is a bounded read and explicit refresh, not delivery or background monitoring.

## Versioning and persistence

New commands use `pajin.dev/measured-review-revision/v2` and digest domain
`pajin.measured-review.revision/v2`. Existing v1 records remain exact. Views use
`pajin.dev/measured-human-review/v2` once assignment history exists, with
`assignmentRevision`, optional `assignee` and the original `decisionRevision` when
applicable. Normal assessment/retest/decision behavior and independent-review checks
remain unchanged. The 200-revision and history byte bounds include administrative records.
A final assignment at revision 200 remains readable in the inbox. No further acknowledgment
can be appended to a full history; the Console states that it remains unread and offers no
write control. It never manufactures a read receipt to bypass the capacity bound.

Before enabling assignments, update every reader and recovery controller. There is
no database schema migration. Old software rejects v2 history; downgrade is supported
only before the first v2 write. Afterward retain v2 readers or deploy forward. Never
rewrite authenticated history to hide an unsupported version.

## Console and verification

The Console loads the configured roster, preserves a reason until successful save,
displays assignment separately from assessment, and provides a personal inbox with
review links and explicit Mark read. Pending changes use operation/authentication
identity, exact request keys and server-confirmed results. Version conflicts require
reloading; there is no optimistic approval or external delivery.

Tests cover restart, original v1 preservation, explicit v2 refusal on downgrade,
role/recipient checks, reassign/unassign, acknowledgment idempotence, concurrent CAS,
stale revision refusal and preservation of the original human decision. Results do
not imply a generic Finding, SARIF eligibility, production remediation or execution.

Fourteen assignment regressions include API and JavaScript state tests. A demoted
Auditor recipient is refused with 403 before a database write, and an assignment
at revision 200 remains readable while further writes are refused. Both failures
were reproduced before correction. JavaScript tests also verify exact retry after
a failed request, preserved reason input, duplicate-click suppression, authentication
reset, read-only role/capacity controls and focus after an acknowledged row is replaced.

Actual local browser verification exercised Operator assignment, the new server
revision, switching to the Approver recipient, the personal unread notice and its
explicit acknowledgment. Focus moved to the inbox status after the update. Desktop
and 390 × 844 layouts were inspected. The Auditor/capacity edge paths are covered
by API/JavaScript tests, not claimed as additional manual browser observations.
