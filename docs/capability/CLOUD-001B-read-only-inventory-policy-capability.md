# CLOUD-001B: Read-only Cloud Inventory and Policy Capability

- Status: Implemented, signed preparation and request adaptation only
- Capability: `pajin.cloud.read-only-inventory-policy@1.0.0`
- Tool: `cloud.read-only-inventory-policy@1.0.0`
- Binding API: `pajin.dev/cloud-read-only-inventory-policy-binding/v1alpha1`
- Preparation API: `pajin.dev/cloud-read-only-inventory-policy-preparation/v1alpha1`
- Provider adapter API: `pajin.dev/cloud-read-only-provider-adapter/v1alpha1`
- Credential reference API: `pajin.dev/cloud-credential-lease-reference/v1alpha1`
- Authority: `src/pajin/capabilities/cloud_inventory.py`
- Credential broker: `src/pajin/runtime/secrets.py`
- Decision: [ADR-0225](../adr/0225-bind-cloud-read-only-preparation-without-credential-use-authority.md)

## Purpose

CLOUD-001B binds one exact CLOUD-001A typed Surface to a complete signed read-only CAP-002
Capability, the current Campaign Scope, an explicitly registered provider GET route, an active
ephemeral credential-lease reference, fixed request/TTL/runtime/response budgets, and the
DOMAIN-004 minimum Cloud Worker boundary. It stops at `PreparedCapabilityAction`.

This slice does not implement a provider client, credential materialization, Worker job, Gateway
dispatch, network request, result normalization, Observation, Evidence, or Graph admission. The
bounded provider adapter only converts one exact Surface and operation into a secret-free request
description. It is not runtime or execution authority.

## Capability and supported operations

The Capability is experimental, T2, `READ_ONLY`, network-metadata-bearing, approval-required, and
costs one request unit. Its complete CAP-002 set binds materializer, action compiler, executor
adapter, result normalizer, success Oracle, Replay strategy, and cleanup handler roles. Replay and
cleanup are explicitly unavailable, Worker materialization and result interpretation fail closed,
and the Oracle always returns `INCONCLUSIVE` because this contract creates no provider result.

Activation accepts only an externally signed current Range release resolved through the existing
Capability lifecycle registry. The static binding pins the complete CLOUD-001A locator registry,
the complete code-backed CAP-002 identity, a local content-addressed Cloud classification, and
`pajin.worker-boundary.cloud.minimum`. The established global DOMAIN-003 inventory is unchanged.

The operations are:

| Operation | Accepted Surface | Meaning |
| --- | --- | --- |
| `inventory-read` | exact account, project, resource, IAM, or container Surface | Prepare one registered provider metadata GET |
| `policy-read` | exact IAM Surface only | Prepare one registered IAM policy GET without evaluating effective access |

Neither operation asserts resource existence, policy correctness, effective permissions, provider
support, or runtime availability.

## Explicit bounded provider adapter

`CloudReadOnlyProviderAdapterDefinition` is supplied explicitly; a Surface provider label never
selects one. The content-addressed definition binds:

- one canonical lowercase provider ID and partition matching the Surface ancestry;
- one canonical query-free HTTPS origin with no embedded credentials;
- one credential audience and the fixed `cloud-provider-credential` binding;
- credential TTL of at most 60 seconds and runtime of at most 60 seconds;
- one or more sorted, unique exact `(Surface, operation)` routes under that origin; and
- per-route response ceilings from 1,024 through 1,048,576 bytes.

Every route is a canonical query-free HTTPS `GET`, has no request body or redirect permission, and
sets resource and policy mutation to false. `BoundedCloudReadOnlyProviderAdapter.prepare_request`
requires an exact provider/partition, Surface, and operation match. It returns one
`CloudProviderReadRequest` with request count 1, provider write count 0, no reservation, no embedded
credential, and no provider-invocation or network authority. No HTTP client is called.

## Campaign Scope binding

Preparation requires two separate exact current Campaign allow rules:

1. the non-routable typed-Surface token
   `https://cloud-scope.pajin.invalid/surfaces/<surface-id>`; and
2. the exact provider GET target registered by the explicit adapter.

The first coordinate preserves exact Cloud identity in the existing HTTP(S) Scope wire; it is not
a provider endpoint and cannot grant egress. The second constrains the actual future request
coordinate. Wildcard coverage is insufficient, any matching deny rule rejects preparation, and
`GET` must be present in Rules of Engagement. The projection also binds
`allowPrivateNetworks`. When it is false, loopback and other non-global IP literals plus
`localhost` and the fixed Docker host name fail closed even if an exact allow rule exists. Public
DNS names remain subject to deployment-runtime DNS/connect-time private-address enforcement. Scope
is copied into a content-addressed Campaign projection but is not expanded.

## Ephemeral credential-lease reference

The caller supplies a `SecretBroker`, its current lease snapshot, the Campaign, and the explicit
adapter. Binding calls `SecretBroker.inspect` with the exact lease ID, adapter audience, and
`campaign-cloud:<Campaign digest>` scope. Inspection refreshes expiry and returns detached current
metadata without exposing or consuming the secret. The broker-owned result must equal the supplied
snapshot exactly.

The accepted lease must be active at preparation, single-use with one use remaining, have an
integral TTL from 1 second through the adapter limit and no more than 60 seconds, and match the
adapter audience, fixed binding, and exact Campaign scope. The resulting content-addressed
`CloudCredentialLeaseReference` stores only:

- SHA-256 of the lease ID;
- the broker's existing 16-hex secret-reference fingerprint;
- audience, binding, Campaign scope, issuance and expiry;
- exact one-use counts and active status; and
- false materialization/embedding markers plus `brokerRecheckRequired=true`.

The raw lease ID, secret reference, and credential material are absent. Therefore the preparation
cannot materialize the credential. A later authorized execution boundary must possess the bearer
lease ID separately and recheck the trusted broker immediately before use.

## Preparation and non-authority guarantees

`prepare_cloud_read_only_inventory_policy` revalidates the current signed activation, registered
binding, exact Campaign, both exact Scope rules, typed Surface, operation, provider adapter, trusted
lease snapshot, and request budgets. It creates a content-addressed
`CloudReadOnlyInventoryPolicyPreparation` whose Tool request and normalized parameters contain the
secret-free provider request.

The preparation records all of the following as false: provider runtime availability, raw lease-ID
embedding, credential materialization and use, provider invocation, policy/IAM/container mutation,
Worker job and egress-policy materialization, network activity, Observation production, Evidence
sealing, Graph admission, approval satisfaction, Permit issuance, Gateway dispatch, Worker
selection, and execution. The static binding likewise grants none of those authorities.

Actual provider execution would still require a separately reviewed runtime adapter, current
broker recheck and credential-use authority, Policy/Approval, one-use ActionPermit, Gateway policy
re-entry, deployment-owned Cloud Worker identity and direct mTLS, bounded receipt/evidence sealing,
and a result-admission contract. None is supplied by CLOUD-001B.

## Fail-closed behavior

Definitions, references, signed activation, Domain classification, static binding, provider
routes, provider adapter, Campaign projection, lease reference, request, and preparation are exact
or content-addressed values. Resolution and preparation reject provider/partition inference or
substitution, duplicate Surface/operation routes, origin or target drift, non-GET/query/body/
redirect/write semantics, policy reads on non-IAM Surfaces, missing exact Scope, matching deny
rules, absent GET RoE, private or loopback literals without explicit private-network RoE, stale
release, fabricated or foreign broker leases, audience/scope/binding/TTL/use/status drift,
consumed/revoked/expired leases, digest drift, extra fields, authority-marker escalation, and
boolean/integer coercion.

## Observation, Replay, and benchmark boundary

A prepared provider target or credential reference is not an Observation, Evidence, policy
evaluation, or resource assertion. CLOUD-001C must separately verify a sealed authorized provider
execution before admitting neutral resource or policy knowledge through the existing Graph writer.
CLOUD-001D owns deterministic policy re-evaluation and disposable provider/emulator Ground Truth.
CLOUD-001B creates no Replay result, benchmark measurement, validation-floor claim, Finding,
effective-permission conclusion, or negative security conclusion.

## Compatibility and rollback

The implementation is additive. Existing CLOUD-001A, discovery, Scope, Capability, Tool, Worker,
Secret, Graph, provider, object-storage, and artifact schemas remain unchanged. `SecretBroker.inspect`
adds non-consuming lease metadata inspection without changing issue, materialize, or revoke
semantics. Rollback removes the additive Cloud module, broker inspection method, tests, contract,
ADR, and consumers. Existing typed Surfaces and leases retain their original validity.

## Verification

`tests/test_cloud_read_only_inventory_policy.py` covers the complete CAP-002 role set, current
signed release activation, exact Surface/Domain/Worker binding, both operations, IAM-only policy
reads, explicit adapter and route matching, Scope allow/deny/RoE behavior, trusted broker ownership,
private-network rejection and explicit opt-in, secret-free one-use lease references, preparation
non-authority markers, runtime fail-closed behavior, inconclusive Oracle,
identity/digest/release/target/method drift, authority escalation, and boolean/integer coercion.
`tests/test_secrets.py` covers non-consuming current lease inspection, detached snapshots, audience
and scope checks, and expiry refresh.
