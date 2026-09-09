# UX-011: Human Review and Remediation Reports

- Status: Implemented and locally verified; whole-project integration remains in the sequential goal.
- Scope: Sequential improvement 4, following the verified EFFECT-001 evaluation.
- Decision: [ADR-0262](../adr/0262-record-human-assessments-separately-from-measured-authority.md).

## User outcome

An authenticated human can inspect retained evidence, document impact and severity with their
reasoning, specify remediation and a retest plan, obtain another human's review, and download a
report that includes subsequent verified evidence and the human retest conclusion. The workflow
must be available through the default Control Plane and Console when measured readers are configured.
It must survive restart and preserve previous assessments when a revision or retest is added.

The initial sources are the existing deployment-selected Web, Network, and AI measured products.
Their public records contain verified benchmark summaries, case identities, metric observations,
and bounded validation references. They do not contain raw requests, responses, credentials,
private Ground Truth, or arbitrary file attachments. The evidence viewer must show the actual
verified summary, its identity, verification time, and disclosure limit. A content-free reference
must not be described as a full transcript or proof of production impact.

## Authority and disclosure

- Reopen sources through the existing exact reader types and deployment-owned verifier context.
  HTTP requests select only a registered domain and an observed evidence digest. They cannot
  supply a source projection, filesystem path, verifier, trust anchor, model, or target.
- The evidence digest binds the complete, strictly parsed source projection and its domain.
  Repeated verification of the same source has the same digest; the host records verification time
  separately. Every mutating request pins the evidence or review revision the human actually saw.
- Operator credentials create and revise assessments and attach retest evidence. A distinct
  Approver accepts the assessment or requests changes. Operator, Approver, and Auditor credentials
  may inspect the new minimized review evidence and review history; Worker credentials may not.
  Existing measured-product endpoint roles remain unchanged.
- Identity and role come from authentication, not request fields. Acceptance is specific to the
  complete current revision, including any retest. A later edit invalidates that acceptance.
- Human impact, severity, remediation, and retest conclusions are attributed human judgments.
  They do not alter the source projection, grant execution authority, create a generic Finding,
  satisfy independent Replay requirements, or make an unverified result eligible for SARIF.
- A review report is a new human-review artifact. Existing source report-authority fields remain
  unchanged. Report download is local HTTP response delivery; it does not authorize external
  SARIF delivery, email, messaging, target execution, or automatic remediation.

## Persistent history and concurrency

Use an additive Control Plane schema migration for an append-only review revision ledger.
Each revision binds the review identity, sequence, preceding digest, authenticated actor and role,
server timestamp and exact command. Rebuild the resulting state using the v1 transition rules.
Validate the chain and transitions
when reopening it. Keep the reviewed source snapshot and its verification timestamp in the ledger;
historical verification is explicitly distinguished from a current successful reader check.

Requests carry a bounded idempotency key and the expected current revision. An exact duplicate
returns the original result without a second revision. Reusing a key with a different actor-bound
request, editing a stale revision, or racing incompatible updates fails without a partial write.
The canonical command and revision commit in one database transaction. Updates, deletes, and
SQLite replacement of historical rows are prohibited by the existing append-only guard mechanism.
One record is limited to 512 KiB; a review is limited to 200 revisions and 8 MiB of history.
Saved-review lists return at most ten entries per page, ordered by immutable review ID. Refreshing
starts a new listing; the list does not claim a snapshot across concurrent new reviews.

This ledger uses the existing trusted host and database boundary. It does not claim independent
measurement signatures or whole-host rollback detection. Single-host recovery and key lifecycle
work are governed by [OPS-001](OPS-001-single-host-recovery-and-urgent-stop.md), including its
explicit enrollment and supported-host limits. The migration preserves existing rows; older binaries
must fail closed on the new schema. Rollback must use an explicitly retained pre-migration backup,
not deletion of review history or an implicit downgrade.

## Assessment, retest, and report

The assessment records impact, severity and rationale, cited evidence, known limits, concrete
remediation steps, and a retest plan with expected observations. Incomplete evidence remains an
explicit open review; the workflow must not fill missing judgments with a success placeholder.
Acceptance requires a complete assessment and a different reviewing principal from its author.

A retest is separately executed under the existing Scope, approval, Permit, Gateway, and Worker
rules. This workflow does not schedule or perform it. To attach its result, the Operator first
loads a newly verified source with a distinct source identity and the same registered benchmark
case contract. The record binds both evidence digests, the remediation/change reference, the
human retest conclusion, and its rationale. Cross-domain, incompatible-case, identical-source,
unverified, or caller-supplied evidence is rejected. A newly attached result requires fresh human
review. Changes in a benchmark summary alone are not automatic proof that a production issue is
fixed, and the report must not assert execution-after-remediation timing absent such evidence.

The report contains evidence scope and verification times, the actual measured summary, attributed
assessment and review decision, remediation and retest plan, linked retest evidence, and revision
history. Drafts remain visibly drafts. An accepted report names the exact accepted revision.
Human text is rendered as text, not executable HTML. Exports never write into a sealed source Run.
Generic SARIF export continues to require the existing independently verified Finding authority.

## Completion gate

- Positive flow: configured reader -> evidence view -> assessment -> distinct human acceptance ->
  report -> separately verified retest attachment -> renewed acceptance -> updated report.
- Negative flow: unauthenticated/Worker access, forged principal, injected raw source/path, stale
  evidence, stale revision, missing rationale, self-acceptance, duplicate-key substitution,
  incompatible retest, source tampering, stored-chain tampering, and attempted historical mutation.
- Restart and concurrency: retain the complete history and idempotent result, migrate an intact
  previous schema without changing its rows, and reject partial or unknown schema state.
- Console: real API-backed loading, errors/retry, empty/draft/accepted/retest states, keyboard and
  focus handling, stale-response suppression, and clearing evidence and form data on lock.
- Verify focused tests, schema migration regressions, Ruff, Linux strict mypy, and an HTTP-served
  browser flow. Record actual limitations and broader integration checks in the root checkpoint.

## Implemented API and operation

The default `create_app` composition reuses the readers already selected by the deployment settings.
No extra application module is needed. Existing measured-product routes keep their original roles.

| Route | Method | Human role | Result |
| --- | --- | --- | --- |
| `/v1/measured-review-evidence/{web,network,ai}` | GET | Operator, Approver, Auditor | Freshly verified public evidence; no query or body |
| `/v1/measured-reviews` | GET | Operator, Approver, Auditor | Ten saved review summaries; optional `after` cursor |
| `/v1/measured-reviews` | POST | Operator | Open a review from a pinned evidence digest |
| `/v1/measured-reviews/{review_id}` | GET | Operator, Approver, Auditor | Current review and historical verification receipt |
| `/v1/measured-reviews/{review_id}/assessment` | POST | Operator | Complete attributed assessment and remediation plan |
| `/v1/measured-reviews/{review_id}/decision` | POST | Approver | Acceptance or request for changes on the current revision |
| `/v1/measured-reviews/{review_id}/retest` | POST | Operator | Newly verified, distinct, compatible evidence plus human conclusion |
| `/v1/measured-reviews/{review_id}/history` | GET | Operator, Approver, Auditor | Complete retained commands, including superseded assessments |
| `/v1/measured-reviews/{review_id}/report.md` | GET | Operator, Approver, Auditor | Local Markdown attachment, visibly draft or accepted |

All writes carry `requestKey`. Revision writes also carry `expectedRevision`. Evidence selection
uses `domain` and `evidenceDigest`; retest uses the original review domain. Identity, role, timestamps,
source content, history, and authority markers are server-owned. The API returns 401/403 for missing
or insufficient authentication, 404 for an unknown review, 409 for integrity, state, revision, or
idempotency conflicts, 422 for malformed input, and 503 for an unconfigured evidence source. An exact
duplicate returns its original revision even after a later edit or deployment restart; the Console
reloads the latest review before allowing the next edit. Historical review reads and downloads work
while the original reader is offline and explicitly retain their historical verification status.

The Console's Human Review panel exposes evidence inspection, saved-review lookup, complete
assessment forms with up to twenty remediation steps, separate-role decision forms, retest
attachment, history, and report download. Locking clears credentials through the existing session
flow and clears all review evidence, form content, history, and pending idempotency keys. Responses
from earlier credentials are discarded. A failed review lookup clears the previous actionable
selection. A retest requires the deployment to select its separately executed result first.

## Local verification evidence

- Model and schema checks: 218 passed, including the complete 201-test migration suite, additive
  v14-to-v15 migration with existing Run preservation, exact schema validation, append-only guards,
  self-review rejection, superseded acceptance, and incompatible or reused retest rejection.
- API and ledger checks: 7 passed. Two separately executed in-process AI source/Replay fixtures
  completed open, assessment, separate human acceptance, restart, new evidence attachment, renewed
  acceptance, and report download. Further checks cover source tampering, stored-history corruption,
  duplicate requests across repository instances, competing edits, request-key substitution,
  incomplete assessments, role denial, and caller-supplied source/path rejection.
- Domain composition: Network and Web review/report checks passed. Network uses its existing
  in-process source/Replay fixture; Web uses the existing unit-level source-loader double. These
  tests verify the new composition and source claim preservation; they are not new live Docker
  attestations. Browser validators also accepted the real API JSON in both tests.
- Existing Control Plane, packaging, and SARIF regressions: 146 passed. Existing SARIF authority
  was preserved. Console runtime regressions: 18 passed. Ruff and Linux strict mypy passed.
- The installation-path recheck reproduced a missing `measured-reviews.js` wheel member. The
  explicit package-data list and built-wheel assertion were corrected; packaging and documentation
  checks then passed (21 tests). The distributed Console now includes the review module it imports.
- Chromium over actual loopback HTTP: 1440x1000 and 390x844. Two separately sealed in-process AI
  sources fed the real API. Evidence loading and a 503 retry, two remediation steps, separate-role
  acceptance, revision-5 retest reacceptance, history and Markdown downloads passed. Human markup
  remained text; lock and delayed-response checks passed. A fresh server retained the review,
  served the final assets, and passed keyboard Enter/Tab, mobile overflow, distinct field identity,
  and failed-lookup clearing checks. No unexpected console or page errors occurred.

These are local implementation checks. PostgreSQL SQL signatures and constraints are checked by
the migration suite; no live PostgreSQL instance was exercised. Recovery and larger-input behavior are implemented
under OPS-001 and SUP-004A; the current whole-project verification and remaining deployment gates
are recorded in the root HANDOFF rather than inferred from these earlier focused results.
