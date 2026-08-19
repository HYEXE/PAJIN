# ADR-0184: Authorize Replay Batch Admission by Exact Request

## Status

Accepted

## Context

`POST /v1/replay/batches` accepts an opaque source locator, an optional parent Retest locator,
projection and attestation choices, and an idempotency key. The server then reopens managed source
authority and may create durable batch, Replay Run, item, compilation, and event records. Operator
RBAC proves the caller category but does not constrain which exact source and derivation mode that
Operator may admit.

Source Artifact admission is already a separate boundary. It proves a managed handoff and cannot
implicitly authorize consumption of that Artifact into a particular Replay plan. A new
deployment-owned policy must therefore narrow batch admission without replacing source integrity,
derivation, attestation, idempotency, or issuance checks.

## Decision

### Add a separate exact Replay batch policy

`PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY` carries
`pajin.control-plane.replay-batch-admission-abac-policy/v1`. Each rule fixes one authenticated local
Operator subject, action `replay.batch.admit`, and one exact
`replay_batch_admission_authority_digest`. Complete tuples are unique and no broad matching form
exists.

The policy remains separate from approval, Run submission/cancellation, checkpoint resume, and
source Artifact policies. It is optional for compatibility; when configured, every batch admission
without an exact rule is denied by default. A rule cannot grant authentication or the Operator role.

### Bind the complete request that selects derivation

The server derives a domain-separated canonical digest over authenticated subject, exact baseline
Artifact locator, exact optional parent Retest locator including absence, Claim projection flag,
portable-attestation flag, target-attestation flag, and idempotency key. The request cannot supply
or override that digest. Deployment policy is authority; request fields only select a candidate
tuple for exact comparison.

The digest does not include caller-authored Candidate, contract, Capability, target, Tool argument,
or source digest because none exists in the public request. Those values remain server-derived from
the reverified managed source. The digest is not persisted into Replay rows: existing immutable
batch authority and exact idempotency checks remain authoritative after admission.

### Authorize before configuration, observation, or mutation

Exact ABAC authorization runs after authentication, Operator RBAC, and request validation but before
portable signer or target/executor trust checks, repository requirement, idempotency lookup, source
lookup, managed-byte resolution, derivation, or durable mutation. A denied request therefore returns
generic HTTP `403` without revealing configuration or resource state.

After authorization succeeds, all existing checks remain mandatory: attestation configuration,
managed source and optional Retest resolution, sealed-source integrity, eligible exact KISA
derivation, source re-open, completed producer Run state, transaction locking, exact idempotency,
and immutable Replay authority persistence. Batch admission still creates planned proof only;
separate internal issuance controls dispatch authority.

## Consequences

- Deployments can pre-authorize one complete Replay plan request for selected local Operators.
- Subject, locator, flag, Retest-presence, or idempotency drift fails closed before state observation.
- Idempotent retry cannot bypass policy admission or reveal an existing batch to another Operator.
- Attestation choices cannot use configuration errors as an oracle before authorization.
- Policy omission preserves previous Operator-only batch admission behavior.
- No database, request/response, event, Artifact, or Worker protocol migration is needed.
- Maintenance mutations remain a separate Human boundary for subsequent audit.

## Rejected alternatives

### Reuse source Artifact admission policy

Rejected because importing one managed Artifact does not authorize consuming it into a Replay plan,
choosing a parent Retest source, or selecting projection and attestation behavior.

### Match only source locator or idempotency key

Rejected because each groups requests that can select different Retest lineage or durable derivation
policy. Omitting the authenticated subject would also allow another Operator to reuse the tuple.

### Authorize after idempotency or source lookup

Rejected because an unlisted Operator could distinguish existing batch, source, repository, signer,
or trust-anchor state before the policy decision.

### Bind server-derived Candidate and compilation digests

Rejected for this pre-admission boundary because deriving them requires opening the very source whose
observation is gated. Existing source verification and immutable compilation records remain the
downstream authority and cannot be replaced by a caller or policy digest.

## Compatibility and rollback

The change is additive and opt-in. Removing
`PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY` restores the prior RBAC-only batch admission route.
Existing Replay, Artifact, OIDC, Worker mTLS, and other ABAC contracts remain unchanged.

## Related documents

- [UX-007H contract](../orchestration/UX-007H-exact-replay-batch-admission-abac.md)
- [ADR-0029 Replay orchestration](0029-control-plane-replay-orchestration.md)
- [ADR-0183 Replay source Artifact admission ABAC](0183-authorize-replay-source-artifact-admission-by-exact-handoff.md)
