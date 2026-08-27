# SYS-001B: Read-only System Inspection Capability

- Status: Implemented, signed preparation and request adaptation only
- Capability: `pajin.system.read-only-inspection@1.0.0`
- Tool: `system.read-only-inspection@1.0.0`
- Binding API: `pajin.dev/system-read-only-inspection-binding/v1alpha1`
- Preparation API: `pajin.dev/system-read-only-inspection-preparation/v1alpha1`
- Host-agent deployment API: `pajin.dev/system-host-agent-deployment-binding/v1alpha1`
- Request API: `pajin.dev/system-host-agent-inspection-request/v1alpha1`
- Authority: `src/pajin/capabilities/system_inspection.py`
- Decision: [ADR-0229](../adr/0229-bind-system-read-only-inspection-without-host-access-authority.md)

## Purpose

SYS-001B binds one exact SYS-001A typed Surface to a complete signed read-only CAP-002
Capability, the current Campaign Scope, a deployment-configured mTLS host-agent trust anchor, an
explicit non-root run-as identity, metadata-only operation membership, bounded request/artifact/
runtime ceilings, and the DOMAIN-004 minimum System Worker boundary. It stops at
`PreparedCapabilityAction`.

This slice does not authenticate a bearer principal or client certificate, attest the configured
non-root identity, open an agent session or host connection, resolve a logical mount, inspect the
host, materialize a Worker job, perform a network request, normalize a result, or produce an
Observation, Evidence, Hypothesis, or Graph admission. The bounded adapter creates only a
secret-free request description. It is not runtime or host-access authority.

## Capability and metadata-only operations

The Capability is experimental, T2, `READ_ONLY`, network-disabled, approval-required, and costs
one request unit. Its complete CAP-002 set binds materializer, action compiler, executor adapter,
result normalizer, success Oracle, Replay strategy, and cleanup handler roles. Replay and cleanup
are unavailable, Worker materialization and result interpretation fail closed, and the Oracle
returns `INCONCLUSIVE` because SYS-001B creates no runtime result.

Activation accepts only an externally signed current Range release resolved through the existing
Capability lifecycle registry. The static binding pins the complete SYS-001A locator registry,
the complete code-backed CAP-002 identity, a local content-addressed System classification, and
`pajin.worker-boundary.system.minimum`. The established global DOMAIN-003 inventory is unchanged.

Each Surface class has exactly one operation:

| Operation | Exact Surface class | Bounded meaning |
| --- | --- | --- |
| `host-metadata-read` | `host` | Request sanitized host metadata only |
| `process-metadata-read` | `process` | Request metadata for the content-bound process snapshot; no PID signal or control |
| `filesystem-metadata-read` | `filesystem` | Request metadata for the exact logical entry; no file content |
| `service-status-read` | `service` | Request status metadata for the exact manager-qualified unit; no control action |
| `configuration-metadata-read` | `configuration` | Request metadata for the exact sanitized record; no configuration value |

An operation cannot be used with another class. A deployment may attenuate the supported set but
cannot add an operation. None of the operations proves that the host or resource exists, that the
stored SYS-001A digest remains current, or that an agent/runtime supports the request.

## Authenticated non-root host-agent deployment boundary

`SystemHostAgentDeploymentBinding` is supplied explicitly and is content-addressed. It binds:

- one deployment ID and the exact opaque SYS-001A host ID;
- the exact DOMAIN-004 System Worker profile;
- a complete public `WorkerMTLSTrustPolicy`, its policy ID and digest, and one selected subject/SPKI
  certificate binding that must occur in that policy;
- one host-agent executable SHA-256 digest;
- one explicit run-as identity that rejects root, Administrator, LocalSystem, SYSTEM, UID 0, and
  common qualified variants;
- a sorted unique non-empty subset of the five metadata operations; and
- artifact output from 1,024 through 1,048,576 bytes and runtime from 1 through 60 seconds.

The trust policy and SPKI are public-key configuration, not a client private key, bearer token,
certificate admission, or live identity proof. Unknown fields are forbidden. The model embeds no
private key, token, password, credential reference, raw host path, or raw configuration value.
Re-validating the serialized binding recomputes the policy digest and requires the selected
certificate to remain a member of the embedded policy.

The binding requires both bearer authentication and direct mTLS because the existing Worker
admission intersects those identities when the host agent initiates its Control Plane connection.
It also requires later non-root runtime attestation. Its live bearer, direct-mTLS, and non-root
verification markers remain false; it neither calls `WorkerMTLSAuthenticator` nor constructs
`WorkerMTLSAdmission`.

The run-as identity is a deployment declaration, not proof that the eventual process has the
claimed UID, SID, groups, capabilities, namespace, or filesystem permissions. A later execution
boundary must attest those properties immediately before admitting a Worker operation.

## Request and budget boundary

`BoundedSystemHostAgentAdapter.prepare_request` requires the exact typed Surface, its root host,
the class-specific operation, and deployment operation membership. It creates one
`SystemHostAgentInspectionRequest` with the complete secret-free typed Surface, exact deployment
reference, non-routable exact Surface target,
`GET`, and these fixed ceilings:

- request count 1;
- deployment-bounded artifact bytes and runtime;
- filesystem content reads 0;
- configuration value reads 0;
- process signals 0;
- service-control operations 0; and
- host-write operations 0.

The budget is attenuation-only and unreserved. The request has no body or credential material and
sets live authentication, agent invocation, host read, and network authority to false. No HTTP
client or host API is called.

## Campaign Scope binding

Preparation requires the exact non-routable typed-Surface token
`https://system-scope.pajin.invalid/surfaces/<surface-id>` in the current Campaign allow rules.
This is an identity coordinate in the existing HTTP(S) Scope wire and is never an endpoint.
Wildcard coverage is insufficient, any matching deny rule rejects preparation, and `GET` must be
present in Rules of Engagement. Preparation copies but never expands the Campaign Scope.

No agent URL is accepted. The existing host-agent Worker initiates its authenticated Control Plane
connection; SYS-001B does not define a second routable service, server certificate, DNS target, or
outbound Tool request. `allowPrivateNetworks` remains part of the exact Campaign projection but is
not treated as host-access authority, so either literal boolean value is accepted.

## Preparation and non-authority guarantees

`prepare_system_read_only_inspection` revalidates the current signed activation, registered
binding, current Campaign projection, the exact Surface Scope rule, typed Surface and host lineage,
class-specific operation, deployment trust configuration, and request ceilings. It creates a
content-addressed `SystemReadOnlyInspectionPreparation` whose Tool request and normalized
parameters contain the secret-free inspection request.

The preparation records all of the following as false: live host-agent runtime, bearer and direct
mTLS authentication, non-root runtime verification, agent session, host connection, host/process/
filesystem/service/configuration read, service control, host mutation, root or privilege
escalation, budget reservation, Worker job, network activity, Observation production, Evidence
sealing, Graph admission, approval satisfaction, Permit issuance, Gateway dispatch, Worker
selection, and execution. The static binding grants none of those authorities either.

Actual inspection would still require current Policy/Approval, one-use ActionPermit, Gateway
policy re-entry, live bearer/direct-mTLS intersection, exact deployment and executable identity,
attested non-root confinement, safe logical-resource resolution, bounded output custody, and a
sealed result-admission contract. None is supplied by SYS-001B.

## Fail-closed behavior

Definitions, references, activation, Domain classification, static binding, host-agent deployment,
Campaign projection, request, and preparation are exact or content-addressed values. Resolution
and preparation reject host substitution, cross-class operations, operations outside the
deployment subset, certificate or policy substitution, invented endpoint fields, common root/admin
identities, request/byte/runtime overflow or coercion, missing exact Scope, matching deny rules,
absent GET, stale release, digest drift, target or method drift,
secret/live-admission field injection, authority-marker escalation, and boolean coercion.

## Observation, Replay, and benchmark boundary

A prepared request is not proof that the agent, host, process, file, service, or configuration
exists or was inspected. SYS-001C must separately verify one sealed, authorized, authenticated
non-root execution before admitting neutral System Observation/Evidence or a bounded Hypothesis.
SYS-001D owns immutable snapshot or fresh-inspection Replay and disposable host Ground Truth.
SYS-001B creates no Replay result, fixture, metric, validation-floor claim, Finding, successful
inspection, or negative security conclusion.

## Compatibility and rollback

The implementation is additive. Existing SYS-001A, discovery, Scope, Capability, Tool, Worker,
mTLS, Docker, journal, Graph, and artifact schemas remain unchanged. No agent process, listener,
deployment registry, credential store, or data migration is added. Rollback removes the additive
module, tests, contract, ADR, and consumers; existing typed Surfaces and Worker trust policies
retain their original validity.

## Verification

`tests/test_system_read_only_inspection.py` covers all seven CAP-002 roles, current signed release
activation, exact Surface/Domain/System Worker binding, all five operation mappings, host and
operation substitution, deployment operation attenuation, embedded policy digest and selected
certificate membership, non-root identity rejection, route-injection and request ceilings, exact
Scope/deny/GET behavior, private-network non-authority, preparation non-authority markers, runtime fail-closed
behavior, inconclusive Oracle, stale release, target/method/digest substitution, secret or live
admission injection, authority escalation, and boolean/integer coercion.
