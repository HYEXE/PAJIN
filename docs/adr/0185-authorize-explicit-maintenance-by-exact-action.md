# ADR-0185: Authorize Explicit Maintenance by Exact Action

## Status

Accepted

## Context

`POST /v1/maintenance/requeue-expired` is an authenticated Human mutation route. It can expire due
approvals and cancel their Runs, then sweep expired generic Job and Replay leases with their retry,
dead-letter, ticket, reservation, Run, item, batch, and event consequences. Operator RBAC proves a
caller category but does not constrain which Operator may initiate this broad server-selected
mutation.

The route has no body or caller-selected resource. The server clock and locked database records
select the expired set. Worker claim paths also invoke the existing lease-only sweep as a
server-owned recovery invariant, so placing Human authorization inside shared lifecycle code would
incorrectly make Worker recovery depend on Human maintenance policy.

## Decision

### Add a separate exact maintenance policy

`PAJIN_CP_MAINTENANCE_ABAC_POLICY` carries
`pajin.control-plane.maintenance-abac-policy/v1`. Each unique rule fixes one authenticated local
Operator subject and action `maintenance.requeue-expired`. No wildcard, prefix, role, group,
resource, digest, or time matching form exists.

The policy is optional for compatibility. When configured, an explicit maintenance request without
an exact subject/action rule is denied by default. A rule cannot grant authentication or the
Operator role and remains separate from every approval, Run, checkpoint, and Replay policy.

### Do not invent caller resource authority

The request contains no Run, Job, approval, Replay ticket, reservation, or time input. Adding any
such policy field would either be unusable before the server discovers the expired set or would
turn caller-provided selection data into false authority. Exact subject plus fixed action is the
complete caller-side authority for this endpoint; existing server-owned eligibility checks remain
the resource authority.

### Authorize at the explicit Human service boundary

The Control Plane authorizes immediately inside `ControlPlaneService.requeue_expired`, before the
lifecycle service captures time, starts either transaction, observes an empty result, or mutates
state. This keeps denied calls generic and prevents policy, time, or database oracles.

Authorization is deliberately not added to `ControlPlaneLifecycleService.expire_leases`. Generic
and Replay Worker claims retain the existing opportunistic lease-only sweep, transaction and
fencing rules. Workers still cannot call the public route because its RBAC dependency requires an
Operator.

After explicit authorization succeeds, all existing signed checkpoint, approval intent, expiry,
Run cancellation, lease retry/dead-letter, Replay fencing, reservation release, lock order, and
audit-event checks remain mandatory.

## Consequences

- Deployments can restrict the explicit broad maintenance trigger to selected local Operators.
- An unlisted Operator receives generic HTTP `403` before clock or database observation.
- The policy cannot narrow individual records because callers do not select them; server-owned
  expiry and locking rules remain authoritative.
- Worker recovery does not acquire or imply Human maintenance authority.
- No database, request/response, event, Artifact, or Worker protocol migration is needed.
- Removing `PAJIN_CP_MAINTENANCE_ABAC_POLICY` restores prior Operator-only behavior.

## Rejected alternatives

### Authorize inside shared lease-expiry lifecycle code

Rejected because Worker claim invokes that code as an internal recovery invariant. It would either
deny normal claim recovery or require granting Workers Human maintenance authority.

### Add resource IDs or an authority digest to the rule

Rejected because the route carries no caller-selected resource and the expired set is only known
from the server clock and locked records. A caller digest would not be authoritative and a
server-derived set digest would require the state observation that authorization must precede.

### Reuse another Human mutation policy

Rejected because approval, Run, checkpoint, and Replay admission actions have different subjects,
attributes, transactions, and consequences. None authorizes a global expired-state sweep.

## Compatibility and rollback

The change is additive and opt-in. Removing `PAJIN_CP_MAINTENANCE_ABAC_POLICY` restores the prior
RBAC-only explicit route. Internal Worker claim cleanup and all existing wire formats remain
unchanged.

## Related documents

- [UX-007I contract](../orchestration/UX-007I-exact-maintenance-requeue-expired-abac.md)
- [ADR-0011 durable Control Plane](0011-durable-control-plane.md)
- [ADR-0184 Replay batch admission ABAC](0184-authorize-replay-batch-admission-by-exact-request.md)
