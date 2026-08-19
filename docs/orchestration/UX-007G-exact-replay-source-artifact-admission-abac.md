# UX-007G Exact Replay Source Artifact Admission ABAC

## Status

Implemented as an additive, opt-in Control Plane authorization boundary.

## Purpose

Narrow `POST /v1/replay/source-artifacts` from broad Operator RBAC to one exact local Operator,
action, and managed handoff request. Successful admission imports a sealed Run into managed
storage and creates immutable Artifact metadata and an audit event, so this durable mutation must
not follow from the Operator role alone when the policy is enabled.

## Policy contract

`PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY` contains strict bounded JSON with API version
`pajin.control-plane.replay-source-artifact-abac-policy/v1`. Each rule is one unique tuple:

```text
(principal_subject, replay.source-artifact.admit,
 source_artifact_admission_authority_digest)
```

There are no wildcard, prefix, regular-expression, staging-only, producer-only, or role/group
rules. Policy subjects must already resolve to authenticated local Operators. A configured policy
denies every missing exact tuple; policy omission preserves the previous Operator-only behavior.

## Exact admission authority

`source_artifact_admission_authority_digest` uses canonical Control Plane JSON and the domain
`pajin.control-plane.source-artifact-admission-authority/v1`. It binds:

- authenticated local Operator subject;
- opaque staging ID;
- producer Run and Job IDs; and
- idempotency key;
- fixed sealed-Run media type and schema kind.

The service computes the digest from the authenticated principal and schema-validated request.
The request carries no digest. Its fields are candidate material for a deployment-owned exact rule,
not authority by themselves.

This ABAC digest is deliberately separate from the existing persisted Artifact admission digest.
It adds no migration and does not change existing Artifact identity or idempotency records.

## Admission sequence

1. Authentication resolves one canonical local `Principal`.
2. RBAC requires `PrincipalRole.OPERATOR`.
3. Request schema validation completes.
4. The service derives the exact admission authority from the local subject and complete request.
5. It matches local subject, fixed action, and exact digest.
6. Only then may repository configuration, idempotency state, producer records, staged bytes, or
   durable Artifact state be inspected or changed.
7. Existing producer eligibility, sealed Run verification, managed import, transaction, and
   staging-consumption checks remain independently mandatory.

Authorization also precedes an idempotent existing-Artifact response. A different Operator or a
drifted request cannot use idempotency handling as a policy or resource-state oracle.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Operator authority.
- The authenticated Operator has no exact rule.
- Subject, staging ID, producer Run, producer Job, or idempotency key differs.
- The action differs from `replay.source-artifact.admit`.

Policy denials return generic HTTP `403` before managed import or database mutation.

## Authority exclusions

- A rule does not grant authentication, Operator role, producer eligibility, staging ownership,
  Artifact integrity, Replay batch creation, execution, Capability, Permit, or Run authority.
- URL, headers, bearer/OIDC claims, role/group/entitlement claims, certificate fields, paths,
  caller-supplied Artifact identities, and content digests are not policy authority.
- Approval, Run submit/cancel, checkpoint resume, and source Artifact rules do not authorize one
  another.
- Campaign draft compilation remains a verified, nonpersisted projection and is not promoted into
  a new policy authority by this change.

## Validation

- Strict parser and startup subject validation cover malformed and non-Operator policies.
- An exact listed Operator can admit one source and receive the existing idempotent result.
- An unlisted Operator is denied before an existing idempotency result is inspected.
- Staging ID, producer Run, producer Job, and idempotency substitutions each produce generic `403`
  with zero Artifact or event mutation and no repository import.
- Existing Artifact admission tests preserve producer, sealed Run, concurrency, integrity, and
  policy-omission behavior.

## Related documents

- [ADR-0183](../adr/0183-authorize-replay-source-artifact-admission-by-exact-handoff.md)
- [Replay orchestration](../adr/0029-control-plane-replay-orchestration.md)
- [UX-007F exact Run submission ABAC](UX-007F-exact-run-submission-abac.md)
