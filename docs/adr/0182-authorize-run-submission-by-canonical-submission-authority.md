# ADR-0182: Authorize Run Submission by Canonical Submission Authority

## Status

Accepted

## Context

`POST /v1/runs` creates a durable queued Run and its first executable Job. Operator RBAC proves the
caller category but does not constrain which exact campaign, input, idempotency authority, Job
kind, or retry budget that Operator may create.

The Control Plane already derives `submission_authority_digest` from the authenticated local
subject and the complete validated submission tuple. The same immutable digest is stored on the
Run and later supports exact cancellation authorization. It can therefore identify creation
authority without introducing a caller-supplied digest or a new wire field.

## Decision

### Add a separate exact submission policy

`PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY` carries
`pajin.control-plane.run-submission-abac-policy/v1`. Each rule fixes one authenticated local
Operator subject, action `run.submit`, and one exact `submission_authority_digest`. Complete tuples
are unique and no broad matching form exists.

The policy remains separate from approval, cancellation, and resume policies. It is optional for
compatibility; when configured, every submission without an exact rule is denied by default. A
rule cannot grant authentication or the Operator role.

### Treat the request as candidate material, not authority

The service computes the domain-separated canonical digest from the authenticated subject,
campaign, complete bounded input, idempotency key, Job kind, and retry limit. The client cannot
supply or override the digest. A deployment-owned exact rule grants authority; request fields only
select a candidate tuple for comparison.

OIDC claims, groups, roles, headers, certificate fields, and individual request attributes do not
select broader rules. Changing any bound field produces a different digest.

### Authorize before idempotency or creation

Exact ABAC authorization runs after request validation and canonical derivation but before opening
the submission transaction. It therefore precedes both the existing-idempotency response and every
Run, Job, and event mutation. A denied request returns generic HTTP `403` and creates no durable
record.

The existing transaction, uniqueness constraint, canonical request comparison, and concurrent
idempotency recovery remain unchanged after authorization succeeds.

## Consequences

- Deployments can pre-authorize one complete Run submission for selected local Operators.
- Subject or submission-field drift fails closed without durable mutation.
- Idempotent retry does not bypass policy admission or reveal existing submission state to an
  unlisted Operator.
- Policy omission preserves previous Operator-only submission behavior.
- No database schema, request/response schema, event schema, or Worker protocol changes.
- The policy does not grant approval, cancellation, resume, Worker dispatch, Tool Permit, Replay,
  export, or maintenance authority.

## Rejected alternatives

### Match campaign name, Job kind, or idempotency key alone

Rejected because each omits principal, complete input, or retry identity and can group unrelated
execution authorities.

### Accept a digest supplied in the request

Rejected because a caller-supplied digest would detach policy comparison from the server's
canonical validated submission tuple.

### Reuse Run cancellation rules

Rejected because creation and cancellation are distinct actions with different mutation effects.
Sharing rules would silently expand previously granted cancellation authority.

## Compatibility and rollback

The change is additive and opt-in. Removing `PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY` restores the prior
RBAC-only submission route. Existing OIDC, Worker mTLS, approval ABAC, cancellation ABAC, resume
ABAC, database schema, idempotency semantics, and wire formats are unchanged.

## Related documents

- [UX-007F contract](../orchestration/UX-007F-exact-run-submission-abac.md)
- [ADR-0169 Run cancellation ABAC](0169-authorize-run-cancellation-by-submission-authority.md)
- [ADR-0181 checkpoint resume ABAC](0181-authorize-checkpoint-resume-by-signed-continuation-authority.md)
