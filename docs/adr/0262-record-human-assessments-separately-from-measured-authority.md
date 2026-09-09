# ADR-0262: Record Human Assessments Separately from Measured Authority

- Status: Accepted
- Date: 2026-09-07

## Context

The Web, Network, and AI measured readers verify bounded benchmark evidence. They provide neither
a persistent human impact/severity assessment nor a remediation and retest report. Existing human
approval queues govern execution; existing SARIF exports require independently verified Findings.
Reusing either as a generic annotation store would confuse separate authority decisions.

## Decision

Add a dedicated, persistent human-review workflow to the Control Plane and Console. Reuse the
deployment-selected readers for evidence verification and preserve their source models unchanged.
Bind assessments to the complete observed source identity, authenticate the author, and require a
distinct Approver for acceptance of the exact current revision. Record edits and retest attachments
as append-only revisions with atomic idempotency and optimistic concurrency.

Reports clearly attribute impact, severity, remediation, and retest conclusions to humans while
retaining the original measurement scope. A retest attachment must cite a distinct verified source
for the same benchmark case contract. It does not schedule execution or automatically establish
remediation success. Historical source verification and a current reader check remain distinguishable.

Use an additive versioned Control Plane schema migration and its existing append-only guards.
Do not repurpose execution approvals, mutate immutable source Runs, or promote human judgments
to Finding, independent Replay, Scope, Permit, or SARIF authority. External delivery remains a
separate authorized operation.

## Consequences

The product gains an actionable human review and report flow without silently changing measured
claim ceilings. Reports can preserve and explain incomplete evidence. A second human must review
changes before an accepted report represents them. The ledger depends on the existing trusted
host/database boundary; independently anchored rollback protection is not implied.

The executable contract and completion evidence belong in
[UX-011](../orchestration/UX-011-human-review-and-remediation-report.md).
