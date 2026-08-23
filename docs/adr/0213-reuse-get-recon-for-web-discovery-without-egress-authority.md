# ADR-0213: Reuse GET Recon for Web Discovery without Egress Authority

## Status

Accepted

## Context

WEB-001A provides an inert, content-addressed `web.http-operation` Surface with concrete endpoint
and URI-template locator variants. It does not provide a discovery Capability or Worker authority.
PAJIN already has the complete seven-role CAP-002
`pajin.pentest.http-get-recon@1.0.0` Capability. That Capability compiles one exact GET request,
limits response evidence to 4,096 bytes, requires a current signed lifecycle activation, and enters
the existing ActionPermit, Gateway, and deployment-bound Worker path.

Adding another Web-specific HTTP Tool or Capability would duplicate the existing compiler,
executor, normalizer, Oracle, Replay, and cleanup roles. Treating the DOMAIN-001 Web label,
WEB-001A locator metadata, or DOMAIN-004 Worker profile as selection authority would violate the
Profile/Domain/Capability/Tool separation. Calling the new composition a Campaign Profile would
also incorrectly make a Security Domain appear to define operating semantics.

## Decision

Add a content-addressed `WebReadOnlyDiscoveryBinding`, not a Campaign Profile. The binding pins:

- the exact WEB-001A locator registry and concrete `http-endpoint` registration;
- the existing code-backed Pentest GET Recon Capability and its DOMAIN-003 Web classification;
- the DOMAIN-004 minimum Web Worker profile;
- GET, one request unit, read-only side-effect semantics, and a 4,096-byte response ceiling; and
- requirements for current Capability activation, current Campaign Scope, ActionPermit, Gateway
  policy re-entry, deployment binding, and direct Worker mTLS.

`prepare_web_read_only_discovery` accepts only a canonical concrete WEB-001A GET Surface and a
current signed Pentest Recon activation. It delegates compilation to the existing CAP-002
materializer/action compiler and returns `prepared-not-authorized`. It does not materialize a
Worker job or egress policy and does not create an Observation, Evidence, Graph node, approval,
Permit, Worker selection, or execution authority.

URI-template materialization and non-GET methods fail closed. The pre-Gateway executor output
retains `NetworkMode.NONE`; only the existing Gateway may attach exact Scope-derived bounded egress
after current Policy, approval, Permit, deployment, and Worker identity checks.

## Consequences

- WEB-001B reuses all seven CAP-002 roles and does not add a parallel attack engine or Tool.
- Campaign Profiles remain orthogonal to the Web Security Domain. The new binding supplies no ROE,
  validation floor, authority ceiling, or Campaign selection.
- The DOMAIN-004 Web profile describes required isolation but does not select a Worker or prove a
  deployment conforms.
- A concrete Surface can be compiled only under an already current signed Capability activation;
  the binding cannot activate it.
- Redirect following, ambient credentials, URI-template expansion, arbitrary request arguments,
  scope expansion, and silent Tool execution remain unavailable.
- WEB-001C must separately normalize the result, seal Observation/Evidence, and admit
  registered-not-authorized knowledge through the existing Graph writer.

## Rejected alternatives

### Create a new Web discovery Capability

Rejected because the existing Pentest GET Recon Capability already expresses the exact read-only
action and complete CAP-002 lifecycle needed by this slice.

### Derive execution from Domain, Surface, or Tool metadata

Rejected because classification and discovery are knowledge, not current authority.

### Materialize URI-template routes in WEB-001B

Rejected because parameter values would introduce new target selection and Scope questions. A
later version must bind exact parameter materialization before compilation.

### Construct an egress-enabled Worker job during preparation

Rejected because egress is a Gateway decision derived from current Campaign Scope and Permit, not
a property that a Capability binding may grant.

## Compatibility and rollback

WEB-001B is additive. Existing Campaign Profile IDs, Pentest Capability/release identities,
WEB-001A Surface identities, DOMAIN-003/004 registries, Tool requests, Worker jobs, ActionPermits,
Gateway behavior, and Graph artifacts remain unchanged. Rollback removes the additive binding,
preparation helper, Surface reference, tests, and contract. Existing serialized artifacts require
no migration.

## Related documents

- [WEB-001B contract](../capability/WEB-001B-read-only-web-discovery-binding.md)
- [WEB-001A contract](../discovery/WEB-001A-typed-http-api-surface-locator-registry.md)
- [CAP-002](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
