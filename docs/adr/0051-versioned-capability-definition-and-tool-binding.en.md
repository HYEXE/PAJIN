> Languages: [English](0051-versioned-capability-definition-and-tool-binding.en.md) | [한국어](0051-versioned-capability-definition-and-tool-binding.ko.md)

# ADR-0051: Versioned Capability Definition and Exact Tool Binding

- Status: Accepted
- Date: 2026-07-26

## Context

PAJIN already has `ToolSpec`, `ToolRegistry`, `CapabilityGrant`, and replay-specific compilation
contracts, but it did not have an independent **Versioned Capability Definition** for Architecture
v2 general attack execution. GRAPH-006's `RegisteredActionCapability` provides the minimum Permit
compiler binding, but it does not own the complete domain, maturity, surface, threat, parameter
schema, side-effect, evidence, approval, cost, and cleanup metadata.

Adding this metadata to `CapabilityGrant` would mix static execution semantics with attenuated
subject and call-budget authority. Treating `ToolSpec` itself as a Capability would not express the
higher-level reviewed behavior that a Tool exposes.

## Decision

1. `pajin.capabilities.CapabilityDefinition` is the canonical authority for static execution
   semantics.
2. A definition carries ID/version/domain/maturity, supported surfaces and threats, preconditions,
   parameter-schema digest, risk/side-effect, evidence, network/approval/cost/cleanup/parallel
   metadata, and an exact Tool binding.
3. Collections are sorted and unique. All material is bound to bounded canonical JSON and a
   domain-separated SHA-256 digest.
4. The Registry resolves exact `(capability_id, capability_version)` keys only. It provides no
   implicit `latest` lookup or version fallback.
5. The existing `ToolSpec` adapter binds Tool ID/version and a normalized full-ToolSpec digest.
   Surface, threat, side-effect, approval, and cleanup metadata is never inferred from names or
   categories; callers must provide an explicit `ToolCapabilityRegistration`.
6. GRAPH-006 `RegisteredActionCapability` gains a separate `definitionDigest`. Its
   `capabilityDigest` binds the Graph registration record while `definitionDigest` binds the full
   CAP-001 definition.
7. `CapabilityGrant` remains the attenuated runtime subject, target, and call-budget authority.
   CAP-001 neither bypasses the Tool Gateway nor automatically activates a Capability.

## Compatibility and migration

- Existing `Tool`, `ToolRegistry`, `CapabilityGrant`, CLI, and Artifact formats remain unchanged.
- An existing Tool appears in the CAP-001 Registry only when an explicit registration is supplied.
- GRAPH-006 remains non-stable. Its nested authority contracts move to `v1alpha2`, and requiring
  `definitionDigest` makes execution authority without a definition fail closed.
- Definitions are never inferred or backfilled into local pre-CAP-001 `v1alpha1` Permit rows.
  Preserve/archive such development ledgers and issue fresh authority in a new Campaign store.
- Code-backed compiler/executor/oracle/replay/cleanup authority interfaces are specified by
  CAP-002. Durable Registry storage, signing, and activation/rotation remain CAP-004 boundaries.

## Consequences

- Capability metadata and runtime Grants remain separate.
- Tool adapter drift and Capability definition drift are detected by independent digests.
- Graph ActionPermits bind the entire versioned Capability definition as well as the exact Tool.
- Existing Tools are not auto-classified; reviewable explicitness is preferred over convenience.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.en.md)
- [ADR-0047 MissionEnvelope and ActionPermit algebra](0047-mission-envelope-and-action-permit-algebra.en.md)
- [GRAPH-006 Atomic ActionPermit Authority](../graph/GRAPH-006-atomic-action-permit-authority.en.md)
- [CAP-001 Versioned Capability Definition](../capability/CAP-001-versioned-capability-definition.en.md)
- [ADR-0052 Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.en.md)
- [CAP-002 Metadata + Code-backed Authority Interfaces](../capability/CAP-002-metadata-code-backed-authority-interfaces.en.md)
