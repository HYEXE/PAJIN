# ADR-0229: Bind System Read-only Inspection without Host-access Authority

## Status

Accepted

## Context

SYS-001A supplies exact, secret-free host, process, filesystem, service, and configuration Surface
identity. It intentionally supplies no host existence claim, current state, Scope, inspection,
credential, authenticated agent, Worker, root, Graph, mutation, or execution authority. PAJIN also
has a complete CAP-002 lifecycle, the DOMAIN-004 authenticated non-root System Worker profile, and
a direct-mTLS Worker authenticator. Those contracts remain independent: a Surface is not an agent,
a minimum profile is not runtime conformance, and a trust policy is not a live TLS admission.

SYS-001B must bind the first read-only System preparation without converting a PID, path, service
ID, configuration digest, mTLS subject, public key, or declared run-as name into host access. The
repository has no general authenticated host-agent runtime or sealed System result contract.
Adding a placeholder client or claiming successful inspection would fabricate executable support.

## Decision

Add the experimental T2 read-only Capability `pajin.system.read-only-inspection@1.0.0` and Tool
identity `system.read-only-inspection@1.0.0`. Register all seven CAP-002 authority roles and require
an externally signed current Range release. Bind the complete code-backed Capability, complete
SYS-001A locator registry, a local System Domain classification, and the exact DOMAIN-004 minimum
System Worker profile. Do not change the established global DOMAIN-003 inventory.

Define one metadata-only operation per exact Surface class: host metadata, process metadata,
filesystem metadata, service status, and configuration metadata. Set file-content reads,
configuration-value reads, process signals, service control, and host writes to zero. Bind one
request plus explicit artifact-byte and runtime ceilings. A deployment may attenuate operation
membership but cannot add operations or use one class's operation against another Surface.

Require an explicitly supplied content-addressed host-agent deployment configuration. Bind an
exact opaque host ID, DOMAIN-004 profile, complete public
`WorkerMTLSTrustPolicy`, policy digest, selected subject/SPKI member, executable digest, explicit
non-root run-as identity, allowed operation subset, and output/runtime maxima. Persist no bearer
token, private key, credential reference, raw path, or configuration value. Treat the run-as name
only as a declaration and require later live bearer/direct-mTLS admission and non-root runtime
attestation.

Project each exact typed Surface to a non-routable HTTPS Scope token under
`system-scope.pajin.invalid` and require that exact token in the current Campaign allow set. Reject
wildcard-only authorization, any matching deny rule, or absence of GET. The reserved token is
identity only and grants no egress. Do not invent a routable agent endpoint: the existing Worker
daemon authenticates as a client and claims work from the Control Plane, while SYS-001B defines no
separate host-agent server or server-certificate contract. The Campaign private-network flag is
preserved in the content-addressed projection but does not grant or deny this host-local operation.

Allow preparation to create a secret-free host-agent request and `PreparedCapabilityAction`, but
do not authenticate, connect, resolve a logical mount, read the host, reserve a budget, materialize
a Worker job, invoke a Tool runtime, produce a result, or grant approval, Permit, Gateway, Worker,
network, Observation, Evidence, Graph, root, privilege-escalation, mutation, or execution authority.
The executor and result-normalizer roles fail closed and the Oracle remains inconclusive.

## Consequences

- Surface identity, Campaign Scope, deployment trust configuration, live Worker authentication,
  non-root conformance, and host-read authority remain distinct reviewable boundaries.
- A serialized deployment binding can revalidate its public trust policy digest and selected
  certificate membership without contacting a host or accepting a private key.
- `networkAccess=false` keeps host-local inspection distinct from Tool network egress. The
  Worker's authenticated Control Plane transport remains deployment infrastructure rather than a
  Campaign target.
- A declared non-root name does not prove UID/SID/groups/capabilities or prevent privilege
  escalation. Live attestation remains mandatory before execution.
- SYS-001C may admit neutral host knowledge only from a separately authorized and sealed execution
  that proves the required live authentication and runtime boundary.

## Rejected alternatives

### Reuse `WorkerMTLSAdmission` as deployment configuration

Rejected because `WorkerMTLSAdmission` represents one live bearer/direct-mTLS intersection. A
configuration artifact has no ASGI TLS evidence and must keep all live authentication flags false.

### Treat a certificate subject or run-as string as non-root proof

Rejected because names do not attest operating-system identity, groups, privileges, namespaces,
or executable provenance. They are exact deployment inputs that a later runtime must verify.

### Permit raw file or configuration reads in the first slice

Rejected because SYS-001A locators contain portable identity, not redaction or content-custody
policy. The first operation set is metadata-only and fixes content/value reads to zero.

### Infer an agent endpoint or operation from a host or resource label

Rejected because identity metadata does not prove a registered runtime route or allowed action.
The existing pull-based Worker path also provides no host-agent listener to authorize. Deployment
and operation membership must be explicit and exact, while any future separate agent protocol
must introduce its own endpoint and server-authentication contract.

### Implement a placeholder agent client or successful Oracle

Rejected because the repository has no authenticated host-agent protocol, safe logical-resource
resolver, confinement attestation, or sealed System result admission in this slice. Placeholder
success would turn preparation into fictitious runtime support.

## Compatibility and rollback

SYS-001B is additive. Existing SYS-001A, Campaign Scope, Capability, Tool, Worker identity, mTLS,
Docker, host journal, Graph, and artifact wires retain their versions. No deployment listener,
credential store, host read, or data migration is introduced. Rollback removes the additive
module, tests, contract, ADR, and consumers; existing System Surfaces and trust policies remain
valid under their original contracts.

## Related documents

- [SYS-001B contract](../capability/SYS-001B-read-only-inspection-capability.md)
- [SYS-001A contract](../discovery/SYS-001A-host-process-filesystem-service-configuration-surface-model.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0002](0002-tool-gateway-and-worker-isolation.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
- [ADR-0228](0228-type-system-host-resources-without-host-access-authority.md)
