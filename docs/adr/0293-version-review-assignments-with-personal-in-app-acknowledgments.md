# ADR-0293: Version Review Assignments with Personal In-App Acknowledgments

- Status: Accepted
- Date: 2026-09-12
- Contract: [UX-013](../orchestration/UX-013-review-assignment-and-internal-notifications.md)

## Decision

Store assignments and notification acknowledgments in the existing append-only
review chain, using explicit revision v2 commands and a separate v2 digest domain.
V1 commands and bytes remain unchanged. Review views become v2 after their first
assignment. No schema migration or independent mutable notification queue is needed:
one assignment record is also the durable notice for its old and new recipients.

Only an Operator assigns a deployment-configured human Operator or Approver.
Assignment never grants that role or changes human assessment, decision, evidence,
capability or execution status. A personal acknowledgment requires the authenticated
recipient, expected review revision and request key. Existing SQL append-only guards,
CAS uniqueness, exact duplicate recovery, bounded history and corruption refusal apply.
Decision revision remains explicit when later administrative records are appended.

## Compatibility and rollback

All readers and recovery controllers must understand revision/view v2 before the
first assignment is written. Old readers fail closed on new commands. Before any v2
write, application rollback is data-compatible; afterward keep v2 readers or deploy
forward. Never erase assignments or relabel them v1 to make a downgrade appear safe.
Retain the normal encrypted checkpoint and independently verified recovery procedure.

## Consequences

Notifications are app-internal records, not email, Slack, push delivery, SLA tracking
or proof a human understood the task. Inbox pages scan at most ten verified review
histories; an empty page can still have a continuation. Users explicitly refresh for
new assignments. Retained acknowledgments count toward the 200-revision bound.

## Implementation clarification

The existing SQL writer-role guard also applies to acknowledgments: the recipient must
currently be an Operator or Approver. An Auditor can read retained personal notices only.
An assignment in the final revision remains readable, but full histories cannot append
acknowledgments. Keeping these limits avoids a schema migration or false read receipts.
