# ADR-0169: Authorize Run Cancellation by Submission Authority

## Status

Accepted

## Context

`POST /v1/runs/{run_id}/cancel` is an Operator-only kill-switch boundary. One accepted request can
cancel queued or leased Jobs, revoke pending or approved Approvals, abandon Replay tickets, release
unconsumed Replay reservations, and terminate the Run. RBAC proves that the caller is an Operator,
but it does not constrain which durable Run authority that Operator may cancel.

Campaign name, Job kind, Run ID, and cancellation reason are insufficient policy inputs by
themselves. Campaign and reason originate in requests, broad labels can group unrelated Runs, and a
generated Run ID does not bind the original submitter, input, idempotency authority, Job kind, or
retry limit.

Schema v10 already stores `submission_authority_digest` on every Run. For public submissions the
digest domain-separates and canonically binds the submitter, campaign, complete input, idempotency
key, Job kind, and retry limit. Migration-fenced or internal Runs receive a distinct non-replayable
authority digest. Database guards require a valid 64-hex digest and make it immutable with the Run's
submission identity.

## Decision

### Add a separate exact cancellation policy

`PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY` carries
`pajin.control-plane.run-cancellation-abac-policy/v1`. Each bounded rule fixes one local Operator
subject, action `run.cancel`, and one exact `submission_authority_digest`. Complete tuples must be
unique and contain no wildcard, prefix, regular expression, campaign-only, or Job-kind-only match.

This policy is separate from `PAJIN_CP_ABAC_POLICY`; approval authority does not imply cancellation
authority. The policy is optional for compatibility. When configured, every cancellation request
without an exact rule is denied by default. A rule cannot grant authentication or the Operator
role, which remains the route prerequisite.

### Evaluate the immutable digest inside the cancellation transaction

The lifecycle service acquires the existing canonical cancellation lock graph and locks the Run. It
then compares the authenticated local subject, fixed action, and the Run's immutable submission
authority digest before an idempotent cancellation response or any Job, Approval, Replay, Run, or
audit-event mutation.

The URL Run ID selects the locked record but does not grant authority. The cancellation reason,
OIDC claims, HTTP headers, mTLS certificate fields, Run input fields in isolation, current state,
and mutable lease or approval data do not select a rule.

### Keep denial generic and mutation-free

A mismatch returns generic HTTP `403`. It does not reveal which tuple element failed and does not
change Jobs, Approvals, Replay tickets or reservations, Runs, or events. The same check applies to
an already-cancelled exact Run so idempotency does not bypass policy admission.

## Consequences

- Deployments can precompute a digest from one exact approved submission tuple and restrict its
  kill switch to selected Operator subjects.
- Changing any bound submission field produces a different digest and fails closed.
- Replay, legacy, or internal Runs can be listed only by their exact stored authority digest; this
  policy does not reinterpret or broaden their separate execution authority.
- Policy omission preserves the previous Operator-only cancellation behavior.
- No database, API request/response, event, or existing approval-policy schema changes.
- Run submission, approval decisions, resume, maintenance, reads, export, and Worker routes remain
  outside this policy.

## Rejected alternatives

### Match campaign name or Job kind

Rejected because those broad, caller-selected labels can cover multiple unrelated Run authorities
and omit submitter, full input, idempotency, and retry bindings.

### Match only Run ID

Rejected as the primary deployment contract because generated IDs are not known before submission
and do not prove the original immutable submission tuple.

### Add cancellation rules to the approval policy

Rejected because approval and cancellation mutate different authority graphs and use different
resource evidence. Separate schemas preserve compatibility and prevent one policy from silently
acquiring another action.

### Authorize from the cancellation reason or identity claims

Rejected because the reason is caller-controlled and ADR-0166 keeps token claims and certificate
attributes outside local workload authority.

## Compatibility and rollback

The change is additive and opt-in. Removing `PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY` restores the
prior RBAC-only cancellation route. Existing approval ABAC, Human OIDC, Worker mTLS, Target TLS,
database schema, wire formats, and internal lifecycle cancellations are unchanged.

## Related documents

- [UX-007D contract](../orchestration/UX-007D-exact-run-cancellation-abac.md)
- [ADR-0168 approval decision ABAC](0168-authorize-approval-decisions-from-signed-attributes.md)
- [ADR-0024 cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
