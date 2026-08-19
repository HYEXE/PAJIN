# ADR-0187: Bind Replay Worker Credential to Executor Profiles

## Status

Accepted

## Context

The Control Plane admits a dedicated Replay Worker through a distinct bearer credential and a
strict subject-to-executor-profile allowlist. Replay routes accept only allowlisted subjects, while
generic Worker routes reject those same subjects.

Startup already rejected an executor profile allowlist without a Replay Worker token. The inverse
partial configuration was accepted: a Replay Worker token without an allowlist created a Worker-only
principal, but the set excluded from generic Worker routes was derived from the empty allowlist. The
nominally dedicated credential therefore had generic Worker authority even though Replay routes
remained closed. This contradicted the documented symmetric route separation and made an incomplete
deployment input stronger than an unset opt-in.

## Decision

### Treat token and allowlist as one deployment unit

`PAJIN_CP_REPLAY_WORKER_TOKEN` and `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` must be either both absent or
both present. `ControlPlaneSettings.from_env()` rejects either partial state before adding the Replay
Worker principal.

When present, all existing constraints remain mandatory: the credential and subject are distinct
from every other role, the principal is Worker-only, the allowlist is strict bounded JSON with a
non-empty unique profile array, and its only subject is that dedicated Replay Worker.

### Preserve independent opt-in semantics

OIDC Human trust, Worker mTLS, and each exact Human mutation ABAC policy retain their existing
independent opt-in behavior. Unset means the documented compatibility boundary, not inferred exact
authorization. Blank or invalid policy material fails startup; configuring one action policy never
grants, configures, or disables another action family.

## Consequences

- A partial Replay Worker deployment can no longer classify its dedicated token as a generic Worker.
- Both Replay Worker variables unset continues to leave Replay routes fail closed.
- Valid deployments with both variables remain compatible.
- Token-only deployments must add an exact allowlist or remove the unused credential.
- No database, protocol, schema, or dependency change is required.

## Rejected alternatives

### Leave the token authenticated but deny only Replay routes

Rejected because the credential is deployment-separated as a Replay Worker and must not inherit
generic Worker authority from a missing allowlist.

### Derive the generic-route exclusion from every Worker credential

Rejected because it would also exclude the intended generic Worker and conflate two explicit role
surfaces.

### Require every Phase 9 ABAC policy as one aggregate bundle

Rejected because the policies intentionally narrow separate action families and existing
deployments may adopt them independently. The correction is limited to the two inputs that jointly
define one Replay Worker authority.

## Compatibility and rollback

The change affects only the previously ambiguous token-only environment. Removing both values
restores the existing no-Replay compatibility boundary; configuring both restores the dedicated
Replay Worker. Accepting the token alone again is not a safe rollback.

## Related documents

- [UX-007K contract](../orchestration/UX-007K-phase9-deployment-authority-ceiling.md)
- [ADR-0029 Replay orchestration](0029-control-plane-replay-orchestration.md)
- [ADR-0167 Worker mTLS](0167-bind-worker-subjects-to-direct-mtls-certificates.md)
