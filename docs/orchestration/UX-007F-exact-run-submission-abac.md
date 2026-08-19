# UX-007F Exact Run Submission ABAC

## Status

Implemented as an additive, opt-in Control Plane authorization boundary.

## Purpose

Narrow `POST /v1/runs` from broad Operator RBAC to one exact local Operator, action, and canonical
submission authority. A successful request creates a queued Run and its first Job, so Run creation
must not follow from the Operator role alone when this policy is enabled.

## Policy contract

`PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY` contains strict bounded JSON with API version
`pajin.control-plane.run-submission-abac-policy/v1`. Each rule is one unique tuple:

```text
(principal_subject, run.submit, submission_authority_digest)
```

There are no wildcard, prefix, regular-expression, campaign-only, Job-kind-only, or role/group
rules. Policy subjects must already resolve to authenticated local Operators. A configured policy
denies every missing exact tuple; policy omission preserves the previous Operator-only behavior.

## Exact submission authority

The existing `submission_authority_digest` uses canonical Control Plane JSON and the domain
`pajin.control-plane.submission-authority/v1`. It binds:

- authenticated local Operator subject;
- campaign name and complete bounded input object;
- idempotency key, Job kind, and retry limit.

The service computes the digest from the authenticated principal and schema-validated request. The
request does not carry a digest and no individual request field grants authority. It only presents
candidate material that must exactly match a deployment-owned digest rule.

## Admission sequence

1. Existing authentication resolves one canonical local `Principal`.
2. Existing RBAC requires `PrincipalRole.OPERATOR`.
3. Request schema and bounded JSON validation complete.
4. The service canonically derives the complete submission authority with the authenticated local
   subject.
5. It matches local subject, fixed `run.submit`, and the exact digest.
6. Only then may idempotency lookup, Run/Job creation, or audit-event mutation occur.

Authorization also precedes an idempotent existing-submission response. A different Operator or a
drifted request cannot use idempotency handling as a policy or resource-state oracle.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Operator authority.
- The authenticated Operator has no exact rule.
- Campaign, complete input, idempotency key, Job kind, retry limit, or subject differs.
- The action differs from `run.submit`.

Policy denials return generic HTTP `403` before any Run, Job, or event row is created.

## Authority exclusions

- A policy rule does not grant authentication, Operator role, approval, Worker dispatch, Tool
  Permit, Replay, cancellation, or resume authority.
- URL, headers, bearer/OIDC claims, role/group/entitlement claims, and certificate fields are not
  policy authority.
- Approval-decision, Run-cancellation, and checkpoint-resume rules do not authorize submission;
  submission rules do not authorize those actions.
- Campaign-draft compilation, Replay admission, maintenance, reads, export, and Worker routes remain
  outside this policy.

## Validation

- Strict parser and startup subject validation tests cover malformed and non-Operator policies.
- An exact listed Operator can create one queued Run and Job and receive the existing idempotent
  response on retry.
- An unlisted Operator is denied before creation and on an existing idempotency key.
- Campaign, complete input, idempotency key, Job kind, and retry-limit substitutions each produce
  generic `403` with zero Run, Job, or event mutation.
- Existing submission tests prove policy omission preserves RBAC-only compatibility.

## Related documents

- [ADR-0182](../adr/0182-authorize-run-submission-by-canonical-submission-authority.md)
- [UX-007D exact Run cancellation ABAC](UX-007D-exact-run-cancellation-abac.md)
- [UX-007E exact checkpoint resume ABAC](UX-007E-exact-checkpoint-resume-abac.md)
