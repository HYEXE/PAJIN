# UX-007K Phase 9 Deployment Authority Ceiling

## Status

Implemented as the Phase 9 Identity and ABAC deployment-configuration exit gate.

## Purpose

Define the authority ceiling for every Phase 9 opt-in when its environment input is unset,
configured, blank, partial, or conflicting. Startup configuration may preserve a documented
compatibility boundary or narrow it, but malformed intent must never create another authority.

## Configuration matrix

| Boundary | Unset | Configured | Blank, partial, or conflicting |
| --- | --- | --- | --- |
| OIDC Human trust | Existing separated opaque Human bearer authorities remain | Strict offline policy adds only its mapped Human principals and ignores token role claims | Blank/invalid policy, missing effective Operator or Approver, Worker role, combined Operator/Approver role, or shared opaque/OIDC subject fails startup |
| Worker mTLS | Existing bearer-only Worker compatibility remains | Direct server certificate/key, Worker CA, and complete trust policy require bearer plus the exact leaf-SPKI binding | Blank/invalid policy, partial TLS group, proxy termination, or a policy that does not bind every and only Worker subject fails startup or Worker authentication |
| Exact Human mutation ABAC | The corresponding route retains its documented RBAC compatibility boundary | Each independent policy can only narrow one action family to exact authenticated subjects and server-derived attributes | Blank/invalid policy or a rule naming the wrong authenticated role fails startup; configuring one action policy does not implicitly configure another |
| Replay Worker | With both dedicated token and profile allowlist absent, Replay routes have no admitted Worker subject | The distinct Replay token and non-empty subject-to-profile allowlist form one deployment unit; the subject is rejected from generic Worker routes | Either member alone, a blank/ambiguous allowlist, shared credential/subject, non-Worker subject, or extra allowlist subject fails startup |

Unset optional policies are compatibility behavior, not evidence that exact production narrowing is
active. Operators must select and deploy every policy required by their environment. Environment
presence, a variable name, an identity claim, a URL, or a request never creates authority.

## Replay Worker atomicity

`PAJIN_CP_REPLAY_WORKER_TOKEN` and `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` must be configured together.
Previously the inverse dependency was incomplete: an allowlist without a token failed startup, but a
token without an allowlist became an authenticated Worker while the generic-route exclusion was
derived from the empty allowlist. The credential could therefore reach generic Worker routes even
though it was named and separated as the Replay Worker credential.

Startup now rejects either partial state before constructing credentials. When both are present,
the existing checks still require a distinct credential, a distinct Worker-only subject, a strict
non-empty allowlist, and exactly that subject as the only allowlist key. Replay and generic Worker
route separation remains derived from the validated allowlist.

## Validation

- The unset matrix produces no OIDC, Worker mTLS, ABAC, or Replay executor opt-in authority.
- Whitespace-only values for all nine policy inputs and the Replay executor allowlist fail startup.
- Replay token-only and allowlist-only configurations fail startup as one partial deployment unit.
- Existing positive OIDC, Worker mTLS, exact ABAC, and dedicated Replay Worker tests retain their
  configured authority and negative conflict coverage.

## Compatibility and rollback

Deployments that do not set either Replay Worker variable are unchanged. Deployments that set both
valid values are unchanged. A deployment that previously set only the token must either remove it or
add the exact allowlist; continuing to treat that credential as a generic Worker is not a safe
rollback because it reopens the authority-classification error.

No database, wire, public import, or dependency change is required.

## Related documents

- [ADR-0187](../adr/0187-bind-replay-worker-credential-to-executor-profiles.md)
- [ADR-0029 Replay orchestration](../adr/0029-control-plane-replay-orchestration.md)
- [UX-007A OIDC Human identity](UX-007A-oidc-mfa-human-identity.md)
- [UX-007B Worker mTLS](UX-007B-worker-mtls-subject-binding.md)
- [UX-007C approval ABAC](UX-007C-signed-approval-abac.md)
- [UX-007I maintenance ABAC](UX-007I-exact-maintenance-requeue-expired-abac.md)
