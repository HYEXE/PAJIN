# UX-007H Exact Replay Batch Admission ABAC

## Status

Implemented as an additive, opt-in Control Plane authorization boundary.

## Purpose

Narrow `POST /v1/replay/batches` from broad Operator RBAC to one exact local Operator, action,
and Replay batch request. A successful request reopens managed source authority and can durably
create a batch, Replay Runs, items, canonical compilations, and audit events. Those mutations must
not follow from the Operator role alone when the policy is enabled.

## Policy contract

`PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY` contains strict bounded JSON with API version
`pajin.control-plane.replay-batch-admission-abac-policy/v1`. Each rule is one unique tuple:

```text
(principal_subject, replay.batch.admit, replay_batch_admission_authority_digest)
```

There are no wildcard, prefix, regular-expression, source-only, flag-only, or role/group rules.
Policy subjects must already resolve to authenticated local Operators. A configured policy denies
every missing exact tuple; policy omission preserves the previous Operator-only behavior.

## Exact admission authority

`replay_batch_admission_authority_digest` uses canonical Control Plane JSON and the domain
`pajin.control-plane.replay-batch-admission-authority/v1`. It binds:

- authenticated local Operator subject;
- exact baseline source Artifact ID and repository version;
- exact optional parent Retest Artifact ID and repository version, including its absence;
- Claim projection, portable attestation, and target attestation booleans; and
- idempotency key.

The service computes the digest from the authenticated principal and schema-validated request.
The request carries no digest. Locator and flag fields are candidate material for a
deployment-owned exact rule; they are not authority by themselves.

The policy digest is pre-admission authorization only. Existing immutable Replay batch rows remain
the durable idempotency and derivation authority, so no database migration is required.

## Admission sequence

1. Authentication resolves one canonical local `Principal`.
2. RBAC requires `PrincipalRole.OPERATOR`.
3. Request schema validation completes, including source separation and attestation dependencies.
4. The service derives the exact batch admission authority from the local subject and full request.
5. It matches local subject, fixed action, and exact digest.
6. Only then may attestor/trust configuration, repository availability, idempotency state, Artifact
   records or bytes, source eligibility, or Replay derivation be inspected.
7. Existing managed-source verification, deterministic derivation, transaction, idempotency, and
   immutable authority checks remain independently mandatory.

Authorization also precedes an idempotent existing-batch response. Another Operator or a drifted
request cannot use idempotency handling as a policy, configuration, or resource-state oracle.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Operator authority.
- The authenticated Operator has no exact rule.
- Subject, source or Retest locator, any projection/attestation flag, or idempotency key differs.
- The action differs from `replay.batch.admit`.

Policy denials return generic HTTP `403` before configuration checks, source observation,
derivation, or durable mutation.

## Authority exclusions

- A rule does not grant authentication, Operator role, Artifact admission or integrity, source
  eligibility, Replay issuance, Worker claim, Capability, Tool Permit, dispatch, or finalization.
- Selecting an attestation flag does not supply a signer or trust anchor and cannot bypass their
  existing mandatory configuration checks.
- URL, headers, bearer/OIDC claims, role/group/entitlement claims, certificate fields, paths,
  caller-authored Candidates, contracts, Capabilities, or digests are not policy authority.
- Approval, Run submit/cancel, checkpoint resume, source Artifact, and batch admission rules do not
  authorize one another.

## Validation

- Strict parser and startup subject validation cover malformed and non-Operator policies.
- An exact listed Operator can enter the existing batch path and repeat the same request.
- An unlisted Operator is denied before an existing idempotency result can be delegated.
- Baseline and Retest Artifact ID/version, Retest presence, all three flags, and idempotency
  substitutions each produce generic `403` before configuration or Replay service access.
- Policy omission preserves the existing Operator RBAC batch path.

## Related documents

- [ADR-0184](../adr/0184-authorize-replay-batch-admission-by-exact-request.md)
- [Replay orchestration](../adr/0029-control-plane-replay-orchestration.md)
- [UX-007G exact Replay source Artifact admission ABAC](UX-007G-exact-replay-source-artifact-admission-abac.md)
