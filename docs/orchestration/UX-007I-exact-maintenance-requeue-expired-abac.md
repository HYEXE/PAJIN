# UX-007I Exact Maintenance Requeue-Expired ABAC

## Status

Implemented as an additive, opt-in Control Plane authorization boundary.

## Purpose

Narrow the explicit Human `POST /v1/maintenance/requeue-expired` route from broad Operator RBAC
to one exact local Operator and action. The route may expire approvals, cancel Runs, requeue or
dead-letter Jobs, abandon Replay tickets, release reservations, and append audit events. Those
mutations must not follow from the Operator role alone when the policy is enabled.

## Policy contract

`PAJIN_CP_MAINTENANCE_ABAC_POLICY` contains strict bounded JSON with API version
`pajin.control-plane.maintenance-abac-policy/v1`. Each rule is one unique tuple:

```text
(principal_subject, maintenance.requeue-expired)
```

There are no wildcard, prefix, regular-expression, role, group, resource, or time rules. Policy
subjects must already resolve to authenticated local Operators. A configured policy denies every
missing exact tuple; policy omission preserves the previous Operator-only route behavior.

The request has no caller-selected resource or body. The server clock and records selected under
the existing transaction locks determine the expired set. The policy therefore does not invent a
Run, Job, Replay ticket, reservation, approval, digest, or timestamp attribute that a caller could
supply or predict.

## Explicit maintenance sequence

1. Authentication resolves one canonical local `Principal`.
2. RBAC requires `PrincipalRole.OPERATOR`.
3. The service matches the local subject and fixed action against deployment policy.
4. Only then may the server clock be captured or database state be observed.
5. Existing approval-expiry verification and cancellation rules run in their established locked
   transaction.
6. Existing Job and Replay lease expiry, retry/dead-letter, ticket abandonment, reservation
   release, Run/item/batch transition, and event rules run in their established locked transaction.

A denied request returns generic HTTP `403` before time capture, transaction entry, state
observation, idempotent empty result, or mutation.

## Internal cleanup separation

Worker Job and Replay claims retain the existing opportunistic lease sweep. That sweep is a
server-owned invariant executed inside the claim service and does not consult this Human route
policy. A Worker cannot invoke the public maintenance route because RBAC still requires Operator,
and a maintenance rule cannot grant Worker claim or lease authority.

Approval expiry is intentionally not moved into Worker claim. The explicit maintenance operation
continues to own both approval expiry and lease expiry, while opportunistic claim cleanup owns only
the existing lease sweep.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Operator authority.
- The authenticated Operator has no exact rule.
- The action differs from `maintenance.requeue-expired`.
- An Approver or Worker attempts to call the explicit route.

## Authority exclusions

- A rule does not grant authentication, Operator role, approval, cancellation, checkpoint resume,
  Run submission, Replay admission, Worker claim, lease, Capability, Tool Permit, or dispatch
  authority.
- URL, headers, bearer/OIDC claims, role/group/entitlement claims, certificate fields, caller time,
  and caller-authored resource identifiers are not maintenance authority.
- The policy does not change signed checkpoint, approval intent, retry, dead-letter, Replay
  fencing, reservation, idempotency, transaction, or audit-event contracts.

## Validation

- Strict parsing, unique tuples, startup subject validation, and environment loading are covered.
- An exact listed Operator can invoke and repeat the explicit operation.
- An unlisted Operator is denied before the lifecycle delegate runs.
- Approver and Worker principals remain rejected by RBAC.
- Policy omission preserves the existing Operator-only route.
- A Worker claim still sweeps and reclaims an expired generic Job lease without Human maintenance
  authorization.

## Related documents

- [ADR-0185](../adr/0185-authorize-explicit-maintenance-by-exact-action.md)
- [ADR-0011 durable Control Plane](../adr/0011-durable-control-plane.md)
- [UX-007H Replay batch admission ABAC](UX-007H-exact-replay-batch-admission-abac.md)
