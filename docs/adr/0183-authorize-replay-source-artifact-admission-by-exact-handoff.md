# ADR-0183: Authorize Replay Source Artifact Admission by Exact Handoff

## Status

Accepted

## Context

`POST /v1/replay/source-artifacts` imports a completed Campaign Job's sealed Run into managed
storage, creates an immutable Artifact record, and appends an audit event. Operator RBAC proves the
caller category but does not constrain which exact staging capability, producer Run/Job pair, or
idempotency authority that Operator may consume.

The request is already narrow: it cannot provide a filesystem path, Artifact identity, sealed Run
identity, content digest, Candidate, or Replay execution authority. A separate deployment-owned
policy can narrow the remaining handoff tuple without weakening existing producer and integrity
checks.

## Decision

### Add a separate exact source Artifact policy

`PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY` carries
`pajin.control-plane.replay-source-artifact-abac-policy/v1`. Each rule fixes one authenticated local
Operator subject, action `replay.source-artifact.admit`, and one exact
`source_artifact_admission_authority_digest`. Complete tuples are unique and no broad matching form
exists.

The policy remains separate from approval, Run submission/cancellation, and checkpoint resume
policies. It is optional for compatibility; when configured, every admission without an exact rule
is denied by default. A rule cannot grant authentication or the Operator role.

### Bind the complete opaque handoff request

The server derives a domain-separated canonical digest over authenticated subject, staging ID,
producer Run ID, producer Job ID, idempotency key, and the route's fixed sealed-Run media type and
schema kind. The request cannot supply or override that digest. Deployment policy is authority;
request fields only select a candidate tuple for exact comparison.

This is a new authorization digest, not a replacement for the persisted Artifact admission digest.
Changing the persisted digest would alter existing durable idempotency semantics and require a
migration without improving this pre-admission policy boundary.

### Authorize before observation or mutation

Exact ABAC authorization runs after request and actor validation but before repository requirement,
idempotency lookup, producer lookup, managed import, or durable mutation. A denied request therefore
returns generic HTTP `403`, imports no bytes, and creates no Artifact or event record.

After authorization succeeds, all existing checks remain mandatory: completed producer Run,
succeeded public Campaign Job, exact Job-to-Run binding, sealed engine Run identity, managed
repository verification, second producer check under the commit transaction, immutable Artifact
metadata, and post-commit exact staging consumption.

## Consequences

- Deployments can pre-authorize one complete source Artifact handoff for selected local Operators.
- Subject or request-field drift fails closed before state observation or mutation.
- Idempotent retry cannot bypass policy admission or reveal an existing Artifact to an unlisted
  Operator.
- Policy omission preserves previous Operator-only source admission behavior.
- No database, request/response, event, Artifact identity, or Worker protocol migration is needed.
- Replay batch admission remains a separate Human mutation boundary for subsequent audit.

## Rejected alternatives

### Match staging ID or producer IDs alone

Rejected because each omits authenticated principal or another handoff identity and can group
unrelated admissions.

### Reuse the persisted Artifact admission digest as policy authority

Rejected because that digest predates this policy, does not bind the idempotency key within its
canonical material, and is a storage/idempotency invariant rather than deployment authorization.

### Authorize only after producer or Artifact lookup

Rejected because an unlisted Operator could distinguish configured repositories, producer state,
or existing idempotency state before the policy decision.

### Treat campaign draft compilation as the same mutation class

Rejected because compilation returns a verified, nonpersisted Campaign value and creates no Run,
Artifact, Graph record, Capability, Permit, or dispatch authority. Adding ABAC there would create a
new authority category instead of closing a durable mutation gap.

## Compatibility and rollback

The change is additive and opt-in. Removing
`PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY` restores the prior RBAC-only source admission route.
Existing Artifact, Replay, OIDC, Worker mTLS, and other ABAC contracts remain unchanged.

## Related documents

- [UX-007G contract](../orchestration/UX-007G-exact-replay-source-artifact-admission-abac.md)
- [ADR-0029 Replay orchestration](0029-control-plane-replay-orchestration.md)
- [ADR-0182 Run submission ABAC](0182-authorize-run-submission-by-canonical-submission-authority.md)
