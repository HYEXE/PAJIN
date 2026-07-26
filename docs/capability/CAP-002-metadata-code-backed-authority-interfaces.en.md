> Languages: [English](CAP-002-metadata-code-backed-authority-interfaces.en.md) | [한국어](CAP-002-metadata-code-backed-authority-interfaces.ko.md)

# CAP-002: Metadata + Code-backed Authority Interfaces

- Status: locally implemented
- Date: 2026-07-26
- Prerequisites: ARCH-001, CAP-001, ADR-0051

## Purpose

CAP-001 declarative metadata is not connected to executable semantics by name alone. A Capability
may claim code-backed executability only when all seven authorities below are registered against
its exact definition reference and immutable digests.

1. Materializer
2. Deterministic Action Compiler
3. Executor Adapter
4. Result Normalizer
5. Success Oracle
6. Replay Strategy
7. Cleanup Handler

The implementation provides no pure YAML/JSON attack DSL, import-string dynamic loading, or
authority inference from names and categories.

## Task contract

- **Task ID:** CAP-002
- **Threat model:** metadata/code substitution, missing or duplicate roles, mutable adapter drift,
  secret-bearing stable context, compiler target expansion, and egress from a network-disabled
  Capability
- **Changed trust boundary:** CAP-001 Definition Registry to code-backed adapters
- **Schema/API version:** `pajin.dev/code-backed-capability/v1alpha1`
- **Audit artifact:** content-addressed `CodeBackedCapability` and `authoritySetDigest`
- **Benchmark impact:** none yet because the runtime path remains disconnected

## Implementation

### Exact adapter identity

Every adapter explicitly exposes its role, ID, version, exact `CapabilityDefinitionRef`, qualified
implementation type, and a directly implemented `stable_execution_context()`.

Stable context must be bounded canonical JSON and rejects fields carrying secret-, token-,
password-, or credential-like values. The implementation type, context digest, Capability
reference, role, ID, and version are bound into a domain-separated SHA-256 `authorityDigest`.
Identity, type, context, or role-interface drift after registration fails before and after calls.

### Complete authority set

`CodeBackedCapability` requires all seven roles exactly once in sorted order, with unique authority
ID/version pairs. The whole material is bound into content-derived `authoritySetId` and
`authoritySetDigest` values.

`CapabilityAuthorityRegistry` accepts only exact CAP-001 definitions, role-conforming adapters,
non-duplicate complete sets, and exact `CodeBackedCapabilityRef` resolution. It has no latest
fallback, partial set, runtime mutation, or automatic module discovery.

### Identity-checking wrapper

`RegisteredCapabilityAuthority` wraps each adapter rather than exposing it directly.

- Materializer input and output are bounded canonical JSON objects.
- The compiler cannot change request ID, Agent, target, or method, cannot add values outside the
  materialized arguments, and must select the exact CAP-001 Tool ID.
- The executor cannot enable network access for a network-disabled Capability.
- The normalizer cannot change request or Tool identity.
- The Oracle returns only `succeeded`, `failed`, or `inconclusive`.
- Replay and Cleanup return non-executable plans. A later Action still requires a new compilation
  and Permit.

## Verification

- deterministic complete authority-set digest and exact resolution
- positive invocation for all wrappers
- missing/duplicate roles and unregistered definitions
- wrong role interface, secret-like context, and non-JSON context
- adapter identity drift after registration and during a call
- compiler target expansion and network-disabled egress
- authority-set digest and exact-reference tampering
- confused-deputy invocation through the wrong role wrapper

## Compatibility, migration, and rollback

- Existing `Tool`, `ToolRegistry`, `CapabilityGrant`, Tool Gateway, and Replay runtime APIs remain
  unchanged.
- No persistent schema or Artifact reader migration is introduced.
- A CAP-001 definition without a CAP-002 authority set is not considered code-backed executable.
- Existing Tool and Replay implementations are not auto-registered. Explicit compatibility
  adapters remain CAP-005 work.
- Rollback means not constructing a CAP-002 registry and continuing to use the CAP-001
  metadata-only Registry. Existing runtime paths are unaffected.

## Follow-up boundaries

- CAP-003: Capability SDK, Scaffold, and role templates
- CAP-004: maturity signing, review, activation, deprecation, and rotation
- CAP-005: adapters for existing KISA, Bug Bounty, CTF Tool, and Replay components
- opt-in GRAPH-006 ActionPermit and Tool Gateway runtime wiring
- durable Capability Registry and Linux CI
