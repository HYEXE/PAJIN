# ADR-0221: Bind Passive Service Identification without Network Authority

## Status

Accepted

## Context

NET-001A provides exact host, port, and declared-service identities but intentionally grants no
network or scan authority. PAJIN already has a signed CAP-002 lifecycle, Policy/Approval and
one-use Permit path, an egress proxy with host-observed CONNECT receipts, and a DOMAIN-004 Network
Worker profile. It does not have a code-backed Network Capability that can turn one unknown
`network-port` coordinate into bounded service-identification output.

A useful first Network action must distinguish typing a coordinate from probing it. General
service scanners combine DNS, ranges, multiple transports, application handshakes, fingerprints,
and retries; adopting one here would make the first slice too broad to bind to exact Scope and
budgets. A direct Worker socket would also bypass the established egress observation boundary.

## Decision

Add `pajin.network.tcp-passive-service-identification@1.0.0`, an experimental T2 read-only CAP-002
Capability with all seven authority roles and an externally signed current Range activation. Bind
it only to a NET-001A `network-port` containing a canonical IPv4 or IPv6 literal, TCP, and one
exact port. Reject DNS names rather than resolving them, reject UDP and declared-service Surfaces,
and do not enumerate neighboring ports.

Use a fixed `tcp-passive-banner-v1` protocol budget: one connection, zero target application-write
bytes, at most 1,024 response bytes, a 5-second connect timeout, and a 2-second banner-read
timeout. Reuse the existing HTTP egress proxy through CONNECT. The Worker may write the CONNECT
request to the proxy but no application-protocol bytes to the target, and trusted success requires
exactly one matching host-observed CONNECT receipt.

Project the IP/port into the existing HTTPS Scope engine only as an authorization constraint.
Require the exact host-wide allow rule, reviewed CONNECT Rules of Engagement, no deny rule sharing
the authority, and explicit private-network authority for any non-global IP. At Gateway re-entry,
narrow egress to that one rule and apply the Capability's 1,024-byte response ceiling.

Add a content-addressed binding to the DOMAIN-004 minimum Network Worker profile and a
content-addressed preparation that stops at `PreparedCapabilityAction`. The binding and
preparation do not satisfy approval, issue a Permit, choose a deployment, materialize a Worker or
egress policy, open a connection, seal Evidence, admit Graph knowledge, or authorize execution.

Keep the established DOMAIN-003 global Capability inventory unchanged. It is a fixed projection
of an earlier code-owned bundle set and does not contain the new Network bundle. Register a local,
resolvable NET-001B Domain classification that includes the complete code-backed Capability
authority reference and exact Network Domain reference, while explicitly recording that the
global inventory was not changed and no activation or Worker authority is granted.

## Consequences

- One exact unknown TCP service can be prepared and, only through the ordinary downstream
  authority path, probed without general scanning or application handshake privileges.
- Scope paths cannot falsely constrain a CONNECT tunnel: any same-authority deny rule fails closed.
- DNS drift, resolver access, UDP ambiguity, ambient credentials, raw sockets, port ranges, retries,
  and active protocol writes remain outside the first Capability.
- The Worker implementation is testable independently while deployment identity, direct mTLS,
  Policy/Approval, Permit consumption, and Gateway dispatch remain mandatory runtime authorities.
- A returned banner or service label is not admitted Observation/Evidence and cannot confirm a
  Finding. NET-001C owns that boundary; NET-001D owns Replay and measurement.
- The local Domain classification avoids falsely claiming membership in the older global
  inventory. A future inventory revision may add the Capability explicitly through a versioned
  contract.

## Rejected alternatives

### Reuse an HTTP GET Capability

Rejected because an arbitrary TCP service may not speak HTTP, and sending an HTTP request would
violate the zero application-write budget and misstate the Network protocol boundary.

### Add a general scanner or raw-socket Worker

Rejected because ranges, retries, multi-protocol probes, fingerprint databases, and raw socket
privileges cannot be represented by one exact Surface, request unit, response ceiling, and
reviewed protocol budget.

### Resolve DNS inside preparation or the Worker

Rejected because one name may produce multiple changing coordinates, making exact Scope,
address-family identity, receipt matching, and replay semantics ambiguous. DNS requires a separate
bounded Capability and evidence contract.

### Connect directly from the Worker

Rejected because direct target sockets would bypass the existing egress proxy's exact policy and
host-observed network receipt. The Worker connects only to its configured proxy coordinate.

### Treat HTTPS Scope projection as the Network Surface identity

Rejected because it is an authorization adapter for CONNECT, not a canonical transport Surface.
NET-001A remains the identity authority.

### Extend the existing global Capability Domain inventory in place

Rejected because its content-addressed membership is already an established contract. Silent
membership expansion would change identities and readers. NET-001B uses an explicit additive local
classification until a versioned global inventory revision is adopted.

## Compatibility and rollback

The change is additive. Existing non-CONNECT Gateway behavior, Tool interfaces, Scope semantics,
Capability definitions, discovery wires, Graph artifacts, and DOMAIN-003 identities are retained.
Rollback removes the Network Capability module, Tool and Worker action, response-budget hook,
CONNECT attenuation, tests, contract, ADR, and exports. NET-001A typed Surfaces remain valid and
non-executable.

## Related documents

- [NET-001B contract](../capability/NET-001B-passive-service-identification-capability.md)
- [NET-001A](../discovery/NET-001A-host-service-protocol-port-surface-model.md)
- [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0220](0220-type-network-services-without-scan-authority.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
