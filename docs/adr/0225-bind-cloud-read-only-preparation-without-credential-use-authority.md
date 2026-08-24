# ADR-0225: Bind Cloud Read-only Preparation without Credential-use Authority

## Status

Accepted

## Context

CLOUD-001A provides exact, secret-free account, project, resource, IAM, and container Surface
identity. It intentionally provides no provider selection, endpoint, inventory or policy read,
credential, Scope, Worker, network, or execution authority. PAJIN also already has a complete
CAP-002 lifecycle, a DOMAIN-004 minimum Cloud Worker profile, Campaign HTTP(S) Scope, and an
in-memory `SecretBroker` that issues scoped, expiring leases. None of those independent contracts
defines the first provider-neutral Cloud read preparation.

CLOUD-001B must bind these authorities without treating a provider label as adapter selection,
placing a bearer lease ID or credential material in a durable preparation, or claiming a provider
runtime that does not exist. A syntactically valid `SecretLease` supplied by a caller is also not
sufficient evidence that the trusted broker currently owns the lease or that it remains active.
The established Campaign Scope wire accepts HTTP(S) targets, while a Cloud Surface is a typed
provider-local identity rather than a routable URL.

## Decision

Add the experimental T2 read-only Capability
`pajin.cloud.read-only-inventory-policy@1.0.0` and Tool identity
`cloud.read-only-inventory-policy@1.0.0`. Register all seven CAP-002 authority roles and require an
externally signed current Range release. Bind the complete code-backed Capability, the complete
CLOUD-001A locator registry, a local Cloud Domain classification, and the exact DOMAIN-004 minimum
Cloud Worker profile. Do not change the established global DOMAIN-003 inventory.

Support two operations:

- `inventory-read` for an exact account, project, resource, IAM, or container Surface; and
- `policy-read` only for an exact IAM Surface.

Require an explicitly supplied, content-addressed provider adapter definition. It pins one
provider/partition, one canonical HTTPS origin, a credential audience and binding, bounded
credential-TTL/runtime/response budgets, and sorted unique exact Surface-and-operation GET routes.
The adapter may only produce a secret-free `CloudProviderReadRequest`. It cannot select a provider,
follow redirects, add a body, invoke the provider, open a network connection, or authorize resource
or policy mutation. The Tool's Worker materialization and interpretation methods fail closed, and
its success Oracle remains inconclusive because CLOUD-001B has no runtime result.

Project each exact typed Surface to a non-routable HTTPS Scope token under
`cloud-scope.pajin.invalid`, and additionally require the exact registered provider GET target in
the current Campaign allow set. Treat the token only as a Scope coordinate, never as an endpoint.
Reject wildcard-only authorization, any matching deny rule, or absence of GET in Rules of
Engagement. This additive projection avoids changing the established Scope schema.

Require a one-use active `SecretLease` whose scope is
`campaign-cloud:<current Campaign digest>`, whose audience and binding match the explicit adapter,
and whose integral TTL is no greater than both the adapter limit and 60 seconds. Before binding,
use `SecretBroker.inspect` to re-read the current broker-owned lease metadata without consuming or
materializing its secret, and require exact equality with the supplied snapshot. Persist only a
SHA-256 lease-ID fingerprint, the existing secret-reference fingerprint, audience, binding, scope,
timestamps, use counts, and active status. Do not persist the raw lease ID, secret reference, or
credential material. Mark the reference as requiring a fresh broker recheck before later use.

Preparation revalidates the current signed release, exact Campaign and both exact Scope rules,
typed Surface, explicit adapter route, trusted current lease snapshot, and bounded request. It may
produce a `PreparedCapabilityAction`, but it grants no approval, ActionPermit, credential
materialization or use, provider invocation, Worker selection or job, egress, network, Observation,
Evidence, Graph admission, mutation, or execution authority.

## Consequences

- Cloud identity, provider routing, credential custody, Campaign Scope, and runtime authority remain
  distinct and independently reviewable.
- A provider adapter is an explicit request mapping, not evidence that the provider is supported or
  reachable and not permission to use its credentials.
- Persisted preparation remains secret-free and cannot be replayed as a bearer credential because
  it contains no raw lease ID; later execution must re-enter the broker with separate authority.
- A copied, fabricated, stale, consumed, revoked, expired, wrong-audience, wrong-scope, or multi-use
  lease cannot enter the preparation boundary.
- CLOUD-001C may admit resource or policy knowledge only from a separately authorized, sealed
  provider execution contract. CLOUD-001B itself supplies no such execution or evidence source.

## Rejected alternatives

### Infer a provider adapter from the Surface provider ID

Rejected because provider vocabulary classifies identity but does not prove endpoint registration,
runtime support, credential custody, or authorization.

### Store the raw lease ID in the prepared request

Rejected because a lease ID is a bearer handle for broker materialization. A preparation artifact
must remain unusable as credential authority.

### Trust any caller-supplied active-looking lease model

Rejected because model shape and timestamps do not prove current broker ownership, revocation
state, remaining uses, audience, or Campaign scope.

### Extend Campaign Scope with a Cloud-specific wire immediately

Rejected because the established HTTP(S) Scope can represent exact non-routable Surface tokens and
exact provider GET targets without a breaking schema change. The reserved token does not grant
network authority.

### Implement a placeholder provider client or successful Oracle

Rejected because no deployment-owned Cloud Worker/provider runtime or sealed result contract exists
in this slice. Claiming one would turn a preparation contract into fictitious execution support.

## Compatibility and rollback

CLOUD-001B is additive. Existing discovery, Scope, Capability, Tool, Worker, Secret, Graph,
provider, object-storage, and artifact wires retain their versions. `SecretBroker.inspect` adds a
read-only metadata operation and does not change `materialize` consumption semantics. Rollback
removes the additive Cloud module, test suite, contract, ADR, and the broker inspection method.
CLOUD-001A Surfaces and existing leases remain valid under their original contracts.

## Related documents

- [CLOUD-001B contract](../capability/CLOUD-001B-read-only-inventory-policy-capability.md)
- [CLOUD-001A contract](../discovery/CLOUD-001A-account-project-resource-iam-container-surface-model.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0224](0224-type-cloud-resources-without-credential-authority.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)

## Security-review amendment

A pre-commit diff review found that exact Scope allow/deny checks alone did not preserve the
independent `allowPrivateNetworks` Rule of Engagement. The Campaign projection therefore also
binds that boolean. Preparation rejects `localhost`, `host.docker.internal`, and loopback or other
non-global IP literals unless the flag is explicitly true, even when the route has an exact allow
entry. This static fail-closed check does not resolve DNS; the deployment-owned execution boundary
must still enforce the same rule against every DNS/connect-time address.
