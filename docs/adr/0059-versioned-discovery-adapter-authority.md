# ADR-0059: Versioned Discovery Adapter Authority

- Status: Accepted
- Date: 2026-07-28

## Context

PAJIN's trusted Surface admission already accepts candidates only from code-owned adapters after
verifying sealed Campaign and Gateway evidence. The adapter registration, however, was keyed only
by Tool ID. It did not bind an adapter version, implementation context, or exact reference into
admission authority and projection audit.

That boundary is insufficient for adding HTTP, OpenAPI, GraphQL, RAG, and Admin discovery. A Tool
result can be interpreted differently when adapter code or instance configuration changes even if
the Tool ID remains the same. Implicit plugin scanning or a `latest` lookup would also allow
deployment state to choose discovery semantics without an explicit reviewed reference.

## Decision

1. Every new discovery interpreter implements the common `DiscoveryAdapter` protocol and exposes
   stable adapter/producer/Tool identities, supported Surface kinds, an explicit non-secret stable
   execution context, and bounded candidate extraction.
2. `DiscoveryAdapterDefinition` binds adapter ID/version, producer, implementation type,
   supported Surface kinds, stable-context digest, and exact Tool ID/version/full-ToolSpec digest
   to bounded canonical JSON and a domain-separated SHA-256 digest.
3. `DiscoveryAdapterRegistry` is code-constructed and resolves exact ID/version/digest references
   only. It performs no filesystem scan, dynamic import, latest-version lookup, or compatible
   fallback.
4. Resolution re-snapshots the live adapter and Tool. Identity, context, implementation, or
   ToolSpec drift fails closed.
5. One explicit selection cannot contain duplicate references or multiple interpreters for the
   same Tool. The Registry and Trusted Surface Producer must share the same `ToolRegistry` object.
6. Stable context is strict, resource-bounded JSON. Secret-like keys are rejected because adapter
   authority and audit material must never become a credential store.
7. Registry-backed trusted admission binds the exact adapter reference into its process-local
   authority digest and projection audit event.
8. Adapter output remains a proposal. The existing sealed-evidence, Scope, Authorization, method,
   Tool-risk, chronology, and canonical Surface gates remain authoritative.

## Consequences

- Discovery semantics can be reviewed and reproduced against one exact adapter and Tool contract.
- Adapter or Tool drift is detected before interpreting a sealed result.
- Serialized definitions cannot instantiate code or expand the set of available adapters.
- Selecting more than one interpreter for a Tool requires a future explicit arbitration design.
- The current Registry is process-local and code-owned; signing, durable storage, distribution,
  and organization-issued activation are future work.

## Compatibility and rollback

The Registry-backed constructor is additive. The existing unversioned `TrustedSurfaceProducer`
constructor remains available so current callers are not silently migrated. The MCP Recon test and
reference runtime use the new path. Rollback is to stop selecting the versioned adapter and return
that opt-in composition to the legacy constructor; already sealed projection Runs retain their
adapter reference and must not be rewritten.

DISC-001 does not implement DISC-002 HTTP/OpenAPI Surface extraction, DISC-003 Auth/File
Upload/RAG/MCP adapters, dynamic plugin loading, multi-wave orchestration, or Planner integration.

## Related documents

- [DISC-001: Versioned Discovery Adapter Registry](../discovery/DISC-001-versioned-discovery-adapter-registry.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051: Versioned Capability Definition and Exact Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
