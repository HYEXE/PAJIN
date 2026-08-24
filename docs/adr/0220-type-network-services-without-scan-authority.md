# ADR-0220: Type Network Services without Scan Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `network.host-service` and
`pajin.locator.network.host-service.v1` as semantic identifiers but intentionally does not
implement their locator schema. PAJIN already has URL-oriented Scope, egress policy, trusted HTTP
network receipts, and a DOMAIN-004 Network Worker profile requiring exact address family, host,
protocol, and port identity. None of those contracts is a general Network Surface model.

NET-001A must represent a host, an unclassified host/protocol/port coordinate, and an explicitly
named service before a service-identification Capability exists. Reusing a URL as the canonical
Network identity would exclude non-HTTP services and conflate application scheme defaults with
transport coordinates. Treating a discovered port or service label as Scope or scanner authority
would also allow discovery metadata to become an authority root.

## Decision

Add a content-addressed Network host/service locator registry with three code-owned classes:

- `network-host`: one explicit `dns-name`, `ipv4`, or `ipv6` host;
- `network-port`: one host plus TCP or UDP and a strict port from 1 through 65535; and
- `network-service`: one host/protocol/port coordinate plus an explicit stable service name.

Canonicalize DNS identity locally through IDNA and label validation without resolution. Validate
IP literals against their explicit family and serialize them canonically. Represent an unknown
service as `network-port`; do not infer a service name from a port number or accept mutable
`unknown`, `auto`, or `default` service aliases.

Add an inert `NetworkHostServiceSurface` wrapper that binds one locator to the exact Network
Domain and DOMAIN-002 type-set and starts as `registered-not-authorized`. Do not add the new
locators to the existing evidence-bound discovery `SurfaceLocator` union. Do not change
`AttackSurface`, Scope, Graph, Capability, Worker, egress, or artifact wires.

The registry and typed Surface explicitly deny DNS resolution, port enumeration, service probing,
raw-socket use, scanner/Tool/Worker selection, network or credential access, Scope expansion,
Capability activation, approval satisfaction, Permit issuance, Graph admission, runtime support,
and execution authority.

## Consequences

- NET-001B can accept an exact `network-port` identity without pretending the service is already
  known and can emit a separately verified service classification later.
- DNS and IP identities remain stable and secret-free without opening a resolver or network path.
- HTTP URLs, CIDRs, port ranges, wildcards, raw IP protocols, banners, product/version fingerprints,
  credentials, and packets are not smuggled into the typed classification layer.
- A declared `network-service` value is knowledge, not proof that the port is open or that the
  named service is present.
- NET-001B must introduce the exact read-only Capability and bounded Worker path. NET-001C must
  separately seal protocol Observation/Evidence before Graph admission.

## Rejected alternatives

### Reuse HTTP URLs or egress rules as Network locators

Rejected because URL scheme/default-port semantics do not represent arbitrary transport services,
and an egress rule is an authorization constraint rather than a Surface identity.

### Infer service names from well-known ports

Rejected because a port number does not prove which service is present. Such inference would make
mutable heuristics part of canonical identity before evidence exists.

### Resolve DNS names while constructing the Surface

Rejected because resolution is time-dependent network activity that can change target identity and
requires Scope, egress, budget, Worker, and evidence controls absent from NET-001A.

### Add the locators directly to the established discovery union

Rejected because Network discovery has no sealed Observation/Evidence contract in this slice. An
additive wrapper preserves existing readers and artifact identities.

### Treat TCP/UDP representation as protocol execution support

Rejected because schema vocabulary does not prove a Worker implementation, deployment review,
socket privilege, current Scope, Permit, or execution authority.

## Compatibility and rollback

NET-001A is additive and requires no migration. Existing public wires, canonical digests, readers,
and runtime behavior remain unchanged. Rollback removes the new module, exports, tests, contract,
ADR, and consumers. Future locator membership or transport support requires an explicit versioned
change rather than silent registry expansion.

## Related documents

- [NET-001A contract](../discovery/NET-001A-host-service-protocol-port-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
