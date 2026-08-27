# ADR-0228: Type System Host Resources without Host-access Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `system.host-resource` and
`pajin.locator.system.host-resource.v1` as semantic identifiers but intentionally does not
implement their locator schema. PAJIN already has isolated Docker Worker patterns, host-local
journals, direct mTLS identities, and a DOMAIN-004 authenticated non-root System Worker profile.
Those contracts govern particular runtime, storage, or deployment boundaries; none is a neutral
System Surface model.

SYS-001A must represent host, process, filesystem, service, and configuration knowledge before a
read-only host Capability or authenticated agent session exists. Reusing Docker metadata, a
Worker identity, local absolute path, PID, service display name, journal record, or mTLS subject as
the Surface would import lifecycle, filesystem, credential, deployment, or execution semantics
into the representation layer. Raw paths and configuration values would also create portability
and privacy hazards.

## Decision

Add a content-addressed System host/resource locator registry with five code-owned classes:

- `system-host`: one opaque `host-<64 lowercase hexadecimal characters>` deployment-stable
  pseudonym plus OS family and architecture;
- `system-process`: one exact host parent plus process-instance and executable digests;
- `system-filesystem`: one exact host parent plus logical mount, portable relative path, bounded
  entry kind, and content digest;
- `system-service`: one exact host parent plus manager namespace, exact unit ID, and definition
  digest; and
- `system-configuration`: one exact host, process, filesystem, or service parent plus namespace,
  portable sanitized record ID, and configuration digest.

Nest parent locators rather than duplicating host strings so cross-host substitution changes
content identity. Reject mutable PID identity, host-local absolute paths, symlink entry kinds,
service display names, raw configuration values, URL/query/fragment syntax, wildcards, ambiguous
path segments, and unknown fields. Canonicalize case-insensitive Windows Service names and require
lowercase SHA-256 material digests.

Add an inert `SystemHostResourceSurface` wrapper that binds one locator to the exact System Domain
and DOMAIN-002 type-set and starts as `registered-not-authorized`. Do not add these locators to the
existing evidence-bound discovery `SurfaceLocator` union. Do not change `AttackSurface`, Scope,
Graph, Capability, Worker, Docker, host journal, or artifact wires.

The registry and typed Surface explicitly deny host access, process inspection, filesystem or
configuration read, service inspection or control, credential use, root authority, Scope
expansion, Capability activation, approval satisfaction, Permit issuance, authenticated host-agent
selection, Tool or Worker selection, network access, host mutation, Graph admission,
runtime-support assertion, and execution authority.

## Consequences

- SYS-001B can bind an exact host/resource identity to a separately reviewed read-only Capability
  and authenticated non-root Worker without deriving authority from locator metadata.
- A process PID may be retained in sealed evidence by a later producer if policy permits, but it is
  not canonical SYS-001A identity and cannot authorize live inspection.
- A logical mount and relative path remain portable identity only. Resolving them to a host-local
  absolute path requires a later authenticated Worker contract and exact Scope.
- A service unit ID and definition digest neither assert current state nor provide a service
  control handle.
- Configuration identity contains only a sanitized record ID and digest; raw values remain outside
  this representation boundary until sealed evidence and redaction rules exist.
- OS family and architecture classify expected identity and do not attest to a reachable or
  conformant host.

## Rejected alternatives

### Reuse Docker or Worker metadata as a host Surface

Rejected because container lifecycle and Worker authentication identify specific runtime
boundaries. They do not prove general host Scope, non-root inspection permission, or a canonical
host resource.

### Use PID and absolute path as canonical identity

Rejected because PIDs are reused and paths are host-local, mutable aliases that can leak operator
or deployment details. Digests plus explicit parent lineage and logical relative references are
stable and portable without granting access.

### Treat service display names or executable paths as service identity

Rejected because display names are mutable and paths are not manager-qualified control identities.
The v1 locator requires an exact manager namespace, unit ID, and sanitized definition digest.

### Store raw configuration values in locators

Rejected because values may contain secrets or personal and deployment-sensitive data. A later
Observation/Evidence contract must own collection, redaction, custody, and admission.

### Extend the established discovery locator union immediately

Rejected because System discovery has no sealed Observation/Evidence admission contract in this
slice. An additive typed wrapper preserves existing readers and artifact identities.

## Compatibility and rollback

SYS-001A is additive and requires no migration. Existing public wires, canonical digests, readers,
Docker and host journal contracts, and runtime behavior remain unchanged. Rollback removes the new
module, exports, tests, contract, ADR, and consumers. New locator membership, identity dimensions,
service managers, or digest algorithms require an explicit versioned change rather than silent
expansion.

## Related documents

- [SYS-001A contract](../discovery/SYS-001A-host-process-filesystem-service-configuration-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0002](0002-tool-gateway-and-worker-isolation.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
