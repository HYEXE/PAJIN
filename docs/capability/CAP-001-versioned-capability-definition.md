# CAP-001: Versioned Capability Definition

- Status: locally implemented
- Date: 2026-07-26
- Prerequisites: ARCH-001, ADR-0047, GRAPH-006

## Purpose

Bind existing Tool execution to Architecture v2 Capabilities through reviewable versioned metadata
and an exact Tool-contract digest instead of names alone. This slice does not execute a Capability.
It creates the immutable definition that later deterministic compilers and ActionPermits consume.

## Implementation

### Canonical definition

`CapabilityDefinition` binds the following material to bounded canonical JSON and a
domain-separated SHA-256 digest:

- Capability ID/version/domain/maturity;
- supported surface types, threat classes, and preconditions;
- parameter-schema digest;
- exact Tool ID/version/full-ToolSpec digest;
- risk tier and side-effect class; and
- evidence types, network access, approval, request-unit cost, cleanup, and parallel-safety
  metadata.

Collections must be sorted and unique. Supplying existing identity fields with different material
is rejected during strict parsing.

### Exact registry

`CapabilityDefinitionRegistry` resolves exact `(ID, version, digest)` references only. It has no
`latest` lookup, compatible-version fallback, or automatic retired-version replacement. Returned
definitions are deep copies so caller mutation cannot alter registry authority.

### Existing Tool adapter

`ToolCapabilityRegistration` requires explicit security metadata.
`capability_registry_from_tools()` verifies through `ToolRegistry.tool()` that the live adapter has
not changed since registration, then digests the frozen ToolSpec.

Surface, threat, side-effect, approval, and cleanup semantics are never inferred from Tool names,
categories, or descriptions. Unknown or drifted Tools fail closed.

### GRAPH-006 adapter

`registered_action_capability()` converts a CAP-001 definition to the GRAPH-006 Permit compiler
contract:

- `definitionDigest` binds the complete CAP-001 definition;
- `capabilityDigest` binds the Graph registration record; and
- Tool ID/version/digest and risk tier are copied exactly.

MissionEnvelopes, ActionProposals, and ActionPermits therefore bind the full Capability definition
as well as its Tool contract.

## Verification

- canonical digest stability and collection-order rejection;
- definition-digest tamper and exact-version mismatch rejection;
- duplicate ID/version rejection;
- live ToolSpec drift and unknown Tool rejection;
- explicit-registration Tool mismatch rejection; and
- CAP-001 to GRAPH-006 authority-binding preservation.

## Compatibility and remaining boundaries

- Existing `CapabilityGrant` attenuation, revocation, and call-budget semantics are unchanged.
- The existing Tool Gateway and Policy Engine remain the only runtime execution boundary.
- Code-backed compiler/executor/oracle/replay/cleanup interfaces are implemented by
  [CAP-002](CAP-002-metadata-code-backed-authority-interfaces.md).
- Signed review, maturity activation, key rotation, and deprecation are implemented by
  [CAP-004](CAP-004-maturity-signing-review-deprecation.md). Durable Registry storage and runtime
  ActionPermit wiring remain follow-up work.
- CAP-001 does not claim benchmark coverage or a completed Hybrid walking skeleton.
