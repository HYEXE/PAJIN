# ADR-0194: Require Fresh, Revocable Selected-provider Admission

## Status

Accepted

## Context

ADR-0193 selects an exact disposable MinIO inventory and produces a provider-common conformance
report. The report binds activation, adapter, deployment profile, authority checkpoint, test
binding, challenge, and observations, but it does not embed the MinIO image, SDK versions, TLS CA,
bucket, or complete provider activation. It also has no maximum usable age or revocation head.

Using a report file or digest directly at startup would allow inventory substitution, replay after
configuration drift, and continued operation after an operator revokes the evidence. Blocking all
provider methods after revocation would create a different hazard by preventing cleanup of unknown
remote state.

## Decision

### Bind the full selected chain before policy selection

Add a content-addressed selected-provider evidence envelope containing the exact secret-free MinIO
inventory, concrete provider activation, and passing report. Cross-check every shared endpoint,
provider-family, encryption-policy, conformance-profile, adapter, deployment-profile, activation,
and authority-checkpoint identity.

### Fix a one-hour report window

Selected-provider admission v1 accepts a report only while
`finishedAt <= now < finishedAt + 3600 seconds`. The duration is a code-owned literal. There is no
clock-skew allowance, policy override, or inclusive expiry boundary. Changing the duration requires
a new contract version and ADR.

### Make policy and revocation append-only

Store deployment policies in a contiguous digest chain. An enabled policy selects every exact
evidence identity and can create an admission. A deny-all successor clears the selection and adds
the prior inventory and report to monotonic revocation sets. Any policy-head change invalidates the
previous admission until the newly selected evidence is admitted again.

### Require a durable local head and external checkpoint

Use an explicitly bootstrapped SQLite store for policy and admission chains. Validate integrity,
schema, metadata, immutable identity, and full chains on every open. Bind writes and startup to an
external checkpoint containing the current policy and admission heads. Missing state never
bootstraps implicitly.

The checkpoint detects local rollback only when the expected value is retained outside the
database. External transparency and cross-host anti-rollback remain separate work.

### Recheck immediately before work, but not cleanup

Require the current admission at wrapper construction, attempt start, credential issuance,
completion, and every remote read. Independently recheck the UX-007M authority head and UX-007O
provider activation. Leave cleanup and restart reconciliation outside the admission freshness gate
so revocation cannot strand already-created or unknown provider state.

### Preserve the authority ceiling

Evidence, policy, admission, and checkpoint fix public-network, Artifact-admission, and finalization
eligibility false. A current admission enables only the exact local selected-provider transport
wrapper. It does not select production credentials, KMS/HSM custody, tenant isolation, retention,
public routes, or Distributed Workers.

## Consequences

- A report cannot authorize a different image, SDK, CA, bucket, endpoint, adapter, profile,
  activation, deployment, or tenant.
- A replacement in any selected identity requires a new live report, evidence, policy revision, and
  admission.
- Revocation is retroactive for new work and survives process restart through the durable policy
  head.
- Existing cleanup and reconciliation remain available after admission expiry or revocation.
- A long-lived attempt can cross the one-hour boundary, but its next remote credential, completion,
  or read call fails before provider use.
- Three separate local stores cannot provide one cross-database transaction. Checks are
  cooperative and repeated at each provider-call boundary.
- The retained live admission is historical after its disposable target and stores are removed.

## Rejected alternatives

### Trust the report filename or digest alone

Rejected because the common report does not contain the selected inventory and is not a durable
deployment head.

### Make reports permanently valid

Rejected because SDK, image, CA, endpoint, credentials, and provider behavior can drift or be
revoked after observation.

### Let deployment configure an arbitrary age

Rejected because a permissive setting could silently convert a bounded observation into indefinite
authority.

### Put revocation only in process memory

Rejected because restart would erase the deny decision and accept an older admission.

### Require admission for cleanup

Rejected because expired or revoked authority must stop new work without preventing idempotent
cleanup and resolution of unknown state.

### Fold admission into the UX-007M or UX-007O database

Rejected because authority-head selection, provider-attempt recovery, and conformance admission
have different lifecycles and rollback semantics. Exact cross-store checks keep the boundaries
explicit.

## Compatibility and rollback

The implementation is additive and opt-in. It adds models, a separate SQLite store, a wrapper,
tests, and secret-free evidence. Existing public imports and direct provider-neutral/recoverable
runtimes are unchanged.

Rollback removes the wrapper and admission store only after pending attempts are reconciled. It
does not make direct provider use authoritative and cannot reactivate a revoked report. Restoring an
older store requires the matching external checkpoint and current UX-007M/UX-007O heads.

## Follow-up work

- UX-007R1 selected a non-executable AWS S3 Seoul custody contract. UX-007R2 must supply live
  account inventory, isolation probes, restore evidence, and operations/security/cost approval.
- Add cross-host revocation distribution and external anti-rollback anchoring before multi-host
  deployment.
- Keep public routes, Distributed Workers, and automatic garbage collection in separate decisions.

## Related documents

- [UX-007R1 AWS S3 production custody selection](../orchestration/UX-007R1-aws-s3-production-custody-selection.md)
- [UX-007Q selected-provider admission](../orchestration/UX-007Q-selected-provider-deployment-admission.md)
- [ADR-0193 disposable MinIO selection](0193-select-disposable-minio-for-local-provider-conformance.md)
- [ADR-0192 raw-observation conformance](0192-derive-provider-conformance-from-raw-observations.md)
- [ADR-0191 provider attempt recovery](0191-journal-and-reconcile-object-storage-provider-attempts.md)
- [ADR-0189 durable Object Storage authority head](0189-activate-object-storage-authority-head-before-provider-use.md)
