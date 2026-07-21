# ADR 0014: Conservative Bug Bounty finding deduplication

- Status: Accepted for deduplication; submission eligibility amended by ADR 0027
- Date: 2026-07-13
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)

> The reporter consumes the sealed Candidate/Decision validation snapshot, not the flat legacy
> Finding list as confirmation authority. An exactly supported Candidate without independent
> reproduction may produce only a `semantic-review-only` draft. Only a Finding in a verified
> independent-replay projection can become submission-ready.

## Context

Bug Bounty programs penalize duplicate submissions, but an aggressive semantic or LLM similarity
rule can hide a distinct affected endpoint, authorization boundary, impact, or regression. A report
generator must also prevent findings from a stale or tampered Campaign from being presented as if
they were produced under the currently reviewed program policy.

PAJIN's generic `Finding` already records validation, target, reproduction, and evidence. Bug Bounty
submission and conservative deduplication additionally need demonstrated impact, affected
component, root cause, and remediation. These fields must remain optional for other Mode Packs and
older artifacts while missing Bug Bounty data remains visible.

## Decision

`Finding` gains optional `impact`, `affected_component`, `root_cause`, and `remediation` fields. The
Bug Bounty reporter loads only a completed Run and performs these checks before triage:

1. the Run Campaign is `bug-bounty` and belongs to the selected program;
2. its authorization evidence contains the current canonical program scope digest;
3. compiled targets, allow/deny scope, risk, methods, tool categories, prohibitions, stop
   conditions, rate, time windows, and budgets still match the reviewed program;
4. the complete sealed Candidate/Decision snapshot loads without partial projection, ID,
   supersession, seal-chain, or authority substitution;
5. each reportable claim targets a declared, allowed endpoint and every cited evidence path is a
   sealed file under the same Run's `evidence/` directory;
6. `ready` and `submission_eligible` require a product Confirmed Finding from a
   `verified-independent-replay` projection. A Candidate with exact objective and semantic support
   but no independent reproduction is forced to `needs-review` and `submission_eligible=false`.

The optional `BugBountyFindingIndex` is a strict, program-bound snapshot of known external findings.
It does not grant execution authority.

### Exact fingerprint

The exact SHA-256 fingerprint contains:

- program name;
- normalized scheme, authority, path, and sorted query-parameter names, excluding query values;
- normalized vulnerability class;
- normalized affected component;
- normalized root cause.

Query values are excluded to avoid binding sensitive tokens and incidental test values into
identity. A Finding without component or root cause receives a finding-specific non-deduplicating
fingerprint and is marked `needs-review`.

An exact match against an `open`, `triaged`, `accepted`, or already `duplicate` known Finding is
`known-duplicate`. An exact second item in one Run is `run-duplicate`; the higher-confidence item is
retained as primary. These are the only automatic suppression cases.

### Cause fingerprint

A second fingerprint replaces the target path with its authority. It identifies the same class,
component, and root cause across endpoints. A match is only a duplicate candidate. Every distinct
exact fingerprint in that cluster becomes `needs-review`, and submission drafts remain available.

An exact match against a `resolved` known Finding also becomes `needs-review`, because it may be a
regression. Missing program-required report fields have the same disposition. No fuzzy title,
embedding, or LLM judgment suppresses a Finding.

## Artifacts

Each unique triage input receives a content-derived `triage_<digest>` directory containing a typed
JSON record, a Markdown summary, and one submission draft for every `ready` or `needs-review`
Finding. Exact duplicates receive no draft. Re-running the identical input fails rather than
overwriting the first report set. A completion event records only artifact paths and aggregate
counts.

Each triage item records its validation authority. `semantic-review-only` items also record
`independent-reproduction-not-confirmed`; the model rejects any attempt to combine that authority
with `ready` or submission eligibility. Unsupported, inconclusive, rejected, or authority-mismatched
Candidates are not reportable drafts.

Markdown content is HTML- and Markdown-escaped. The output remains a draft and is never submitted
externally by this workflow.

## Consequences and limitations

The rules are reproducible, explainable, and biased against hiding distinct vulnerabilities. They
may leave more work for the operator than a semantic deduplicator, which is intentional.

The known-finding index is currently a local snapshot; there is no HackerOne, Bugcrowd, Jira, or
GitHub synchronization. Local Run artifacts are not yet signed by a durable evidence service, so
same-Run path validation detects substitution boundaries but not privileged filesystem tampering.
The reporter does not calculate CVSS, prove business impact, independently attest target execution,
or submit reports. Semantic-review drafts do not prove product-level confirmation. Those remain
future validated integrations.

## Validation

Tests cover exact same-Run suppression, unresolved and resolved known matches, same-cause
multi-endpoint review, incomplete-field TODO drafts, HTML escaping, stale digest rejection, compiled
policy tampering, missing evidence, typed index loading, content-derived report IDs, repeat-write
protection, event emission, semantic Candidate draft generation, independent-replay eligibility,
forged authority rejection, hardened/no-Candidate behavior, untrusted Markdown escaping, and CLI
artifact generation.
