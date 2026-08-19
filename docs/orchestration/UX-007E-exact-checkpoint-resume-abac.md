# UX-007E Exact Checkpoint Resume ABAC

## Status

Implemented as an additive, opt-in Control Plane authorization boundary.

## Purpose

Narrow `POST /v1/checkpoints/{checkpoint_id}/resume` from broad Operator RBAC to an exact local
Operator, action, signed checkpoint, and continuation approval authority. The route still requires
authentication and the Operator role before this policy is evaluated.

## Policy contract

`PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY` contains strict bounded JSON with API version
`pajin.control-plane.checkpoint-resume-abac-policy/v1`. Each rule is one unique tuple:

```text
(principal_subject, checkpoint.resume, checkpoint_resume_authority_digest)
```

There are no wildcard, prefix, regular-expression, role, group, target-only, or checkpoint-ID-only
rules. Policy subjects must already resolve to authenticated local Operators. When the policy is
configured, a missing exact tuple is denied by default. Omitting the policy preserves the prior
Operator-only behavior.

## Exact continuation authority

`checkpoint_resume_authority_digest` uses canonical Control Plane JSON and the domain
`pajin.control-plane.checkpoint-resume-authority/v1`. It binds:

- checkpoint ID, Run ID, sequence, and schema version;
- signed payload SHA-256, checkpoint signature, and signing key ID;
- approval ID and the exact signed call fingerprint, Tool ID, target, risk tier, and expiry.

The digest is derived only from locked repository records after the checkpoint signature is
verified and the approval is proven to match the signed checkpoint intent. URL or request fields do
not supply any digest component. Mutable approval state is deliberately excluded: the same exact
resource authority remains stable after consumption, while the service's separate one-use state
checks still reject a second claim.

## Admission sequence

1. Existing authentication resolves one canonical local `Principal`.
2. Existing RBAC requires `PrincipalRole.OPERATOR`.
3. The resume transaction locks checkpoint, approval, and Run records in the existing order.
4. It proves checkpoint/approval/Run relationships and verifies the signed checkpoint.
5. It recovers the signed intent and exact-matches the approval fields.
6. It computes the continuation authority digest from those locked, verified records.
7. It matches local subject, fixed `checkpoint.resume`, and the exact digest.
8. Only then may one-use, current-checkpoint, Run-state, approval-state, and expiry handling run.
9. Existing continuation Job creation, approval consumption, checkpoint claim, Run transition, and
   audit event remain one transaction.

Authorization therefore runs before either an idempotent/terminal response or durable mutation. An
unlisted Operator cannot inspect repeat-resume state by first passing through an earlier claimant's
authority.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Operator authority.
- The authenticated Operator has no exact rule.
- Any signed checkpoint identity or exact approval-intent field differs.
- The checkpoint signature is invalid or the approval does not match its signed intent.
- The action differs from `checkpoint.resume`.

Policy denials return generic HTTP `403` and leave checkpoint, approval, Run, Job, and event state
unchanged.

## Authority exclusions

- A policy rule does not grant authentication, Operator role, approval, checkpoint creation, or
  execution authority.
- URL IDs, request bodies, bearer/OIDC claims, roles, groups, entitlements, HTTP headers, and mTLS
  certificate fields are not policy authority.
- Approval-decision and Run-cancellation rules do not authorize resume, and resume rules do not
  authorize either of those actions.
- Reads, submission, cancellation, maintenance, Replay issuance, export, and Worker routes remain
  outside this policy.

## Validation

- Strict parser and startup subject validation tests cover malformed and non-Operator policies.
- Exact API tests prove one listed Operator can consume the matching continuation authority.
- An unlisted Operator is denied both before and after exact consumption.
- Approval ID, target, signed payload digest, and signing key substitutions each produce generic
  `403` with unchanged checkpoint, approval, Run, Job, and event state.
- Existing approval, cancellation, and RBAC-only resume tests preserve compatibility.

## Related documents

- [ADR-0181](../adr/0181-authorize-checkpoint-resume-by-signed-continuation-authority.md)
- [UX-007C signed approval ABAC](UX-007C-signed-approval-abac.md)
- [UX-007D exact Run cancellation ABAC](UX-007D-exact-run-cancellation-abac.md)
