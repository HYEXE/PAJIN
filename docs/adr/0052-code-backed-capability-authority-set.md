# ADR-0052: Code-backed Capability Authority Set

- Status: Accepted
- Date: 2026-07-26

## Context

CAP-001 provides reviewable declarative metadata and an exact Tool contract, but it does not own the
code components that implement attack semantics. Import strings or free-form YAML steps would create
an unreviewed execution DSL. Treating existing `Tool.prepare()` and `interpret()` methods as a whole
Capability would instead leave Materializer, Compiler, Oracle, Replay, and Cleanup responsibilities
implicit and prevent exact review, rotation, and audit.

Existing Replay Materializer/Oracle registries and the resumable runtime
`stable_execution_context()` pattern provide a precedent for code-identity drift protection.
CAP-002 needs the same property in a general Capability boundary that is not tied to one Mode or
Replay.

## Decision

1. One code-backed Capability registers Materializer, Action Compiler, Executor Adapter, Result
   Normalizer, Success Oracle, Replay Strategy, and Cleanup Handler exactly once.
2. Every adapter exposes role, ID, version, exact `CapabilityDefinitionRef`, and a directly
   implemented `stable_execution_context()`.
3. Arbitrary object state and source files are not auto-introspected. Qualified type and explicit
   non-secret stable context are bound into canonical digests.
4. Secret-like values, non-JSON values, and oversized stable context fail registration.
5. The complete `CodeBackedCapability` has content-derived authority-set ID and digest values and
   resolves by exact reference only. There is no latest or partial-set fallback.
6. The Registry performs no dynamic imports or module scanning. Bootstrap code must pass trusted
   adapter instances explicitly.
7. Adapters are invoked only through identity-checking wrappers. Wrappers enforce pre/post drift
   validation, canonical inputs and outputs, role separation, and narrow authority-expansion checks.
8. Replay and Cleanup outputs are plans, not execution authority. A later Action requires separate
   compilation, Scope/Policy checks, and a fresh ActionPermit.
9. Compatibility adapters for existing Tool and Replay components are not auto-generated before
   CAP-005.

## Rejected alternatives

- **Pure YAML/JSON attack DSL:** creates a new execution language that bypasses bounded code review.
- **Python import-string Registry:** promotes metadata into code-loading authority.
- **Automatic class/source hashing:** confuses build and packaging differences with semantic
  authority and does not replace explicit behavior versioning.
- **Implicitly combining every role in Tool:** prevents independent Oracle, Replay, and Cleanup
  review and rotation.
- **Partial role registration:** makes missing and unsupported ambiguous and creates runtime
  fallback. Unsupported behavior must be represented by explicit code returning a non-executable
  plan.

## Compatibility, migration, and rollback

- Only additive public imports are introduced; existing Tool Gateway and Replay runtime behavior is
  unchanged.
- There is no persistent schema migration.
- Existing Capabilities with only CAP-001 definitions remain metadata-only.
- Not bootstrapping a CAP-002 registry is the rollback path and preserves current runtime behavior.
- `v1alpha1` is not claimed as a stable API. Changes before the Walking Skeleton wiring require an
  explicit version bump.

## Consequences

- Declarative metadata and actual code behavior gain an exact audit artifact.
- Missing, duplicate, substituted, mutable, and confused-deputy authorities fail before execution.
- CAP-003 has a fixed set of seven interfaces for generated templates.
- Signed review/activation is implemented by CAP-004. Durable storage, existing Tool adapters, and
  ActionPermit runtime wiring remain follow-up work.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051 Versioned Capability Definition and Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
- [CAP-001 Versioned Capability Definition](../capability/CAP-001-versioned-capability-definition.md)
- [CAP-002 Metadata + Code-backed Authority Interfaces](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [ADR-0053 Inert Deterministic Capability Scaffolds](0053-inert-deterministic-capability-scaffolds.md)
- [CAP-003 Capability Authoring SDK and Scaffold](../capability/CAP-003-capability-authoring-sdk-scaffold.md)
- [ADR-0054 Signed Reviewed Capability Lifecycle](0054-signed-reviewed-capability-lifecycle.md)
- [CAP-004 Maturity, Signing, Review, and Deprecation](../capability/CAP-004-maturity-signing-review-deprecation.md)
