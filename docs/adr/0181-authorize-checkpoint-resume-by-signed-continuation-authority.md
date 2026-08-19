# ADR-0181: Authorize Checkpoint Resume by Signed Continuation Authority

## Status

Accepted

## Context

`POST /v1/checkpoints/{checkpoint_id}/resume` consumes a one-use approval, claims a signed
checkpoint, creates a continuation Job, and moves its Run back to queued. Operator RBAC identifies
the caller category but does not constrain which exact continuation authority that Operator may
consume.

Checkpoint ID or Run ID alone is not sufficient authority. They select records but do not bind the
signed checkpoint payload and signer or the exact approved Tool intent. Approval-decision ABAC also
cannot be reused: deciding an approval and consuming the resulting continuation mutate different
authority graphs.

## Decision

### Add a separate exact resume policy

`PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY` carries
`pajin.control-plane.checkpoint-resume-abac-policy/v1`. Each rule fixes one authenticated local
Operator subject, action `checkpoint.resume`, and one exact
`checkpoint_resume_authority_digest`. Complete tuples are unique and no broad match form exists.

The policy is separate from approval-decision and Run-cancellation policies. It is optional for
compatibility; when configured, every resume without an exact rule is denied by default. A rule
cannot grant authentication or the Operator role.

### Bind signed checkpoint and approved continuation intent

The digest is domain-separated and canonically binds checkpoint ID, Run ID, sequence, schema
version, signed payload digest, checkpoint signature, key ID, approval ID, call fingerprint, Tool
ID, target, risk tier, and expiry.

The service derives these values from locked database records only after verifying the checkpoint
signature and exact approval-to-intent match. URL and request values select candidate records but do
not become authority. OIDC claims, groups, roles, headers, certificate fields, and mutable state are
not policy inputs.

### Authorize before state handling or mutation

The transaction retains its checkpoint, approval, and Run lock order. Exact ABAC authorization runs
before claimed-checkpoint handling, current Run checks, approval consumption, continuation Job
creation, Run transition, or audit events. A denied request returns generic HTTP `403` with no
durable mutation, including after another Operator already consumed the exact authority.

The existing state machine independently enforces current checkpoint, awaiting-approval Run,
approved and unexpired decision, and single consumption. Excluding approval state from the digest
keeps one resource identity stable without weakening those checks.

## Consequences

- Deployments can restrict one exact signed continuation to selected local Operators.
- Changing the checkpoint signer or signed identity, approval identity, or signed Tool intent
  produces a different digest and fails closed.
- Approval, cancellation, and resume authority remain disjoint.
- Policy omission preserves the previous Operator-only route.
- No database schema, request/response schema, event schema, or Worker protocol changes.
- The policy does not grant checkpoint creation, approval, execution, reads, export, or Replay
  authority.

## Rejected alternatives

### Match only checkpoint ID, Run ID, Tool ID, or target

Rejected because each omits signed checkpoint or approval-intent identity and can group unrelated
continuations.

### Reuse approval-decision or cancellation rules

Rejected because those policies govern different actions and durable mutation graphs. Sharing them
would silently expand existing authority.

### Authorize from request data or identity claims

Rejected because caller-controlled input and external claims do not prove local continuation
authority.

## Compatibility and rollback

The change is additive and opt-in. Removing `PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY` restores the
prior RBAC-only resume behavior. Existing Human OIDC, Worker mTLS, approval ABAC, cancellation ABAC,
checkpoint signing, database schema, and wire formats are unchanged.

## Related documents

- [UX-007E contract](../orchestration/UX-007E-exact-checkpoint-resume-abac.md)
- [ADR-0168 approval decision ABAC](0168-authorize-approval-decisions-from-signed-attributes.md)
- [ADR-0169 Run cancellation ABAC](0169-authorize-run-cancellation-by-submission-authority.md)
