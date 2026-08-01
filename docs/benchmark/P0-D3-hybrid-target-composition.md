# P0-D3: Non-runnable Hybrid Target Composition Authority

- Status: Implemented contract-only composition
- Component API: `pajin.dev/hybrid-target-component/v1alpha1`
- Bridge API: `pajin.dev/hybrid-target-bridge/v1alpha1`
- Composition API: `pajin.dev/hybrid-target-composition/v1alpha1`
- Private binding API: `pajin.dev/hybrid-target-ground-truth-binding/v1alpha1`
- Selection API: `pajin.dev/hybrid-target-selection/v1alpha1`
- Decision: [ADR-0090](../adr/0090-non-runnable-hybrid-target-composition.md)
- Predecessors: [P0-D1](P0-D1-traditional-web-api-target-catalog.md),
  [P0-D2B](P0-D2B-local-ai-rag-mcp-docker-provider.md)

## Scope

P0-D3 defines the first exact composition of the runnable Traditional Web/API Boolean-SQLi profile
and the runnable local AI/RAG/MCP profile. It records the intended order and a synthetic
SQLi-output-to-document-upload bridge without claiming that the two independent providers have run
under one coordinate.

The existing `BenchmarkManifest` names one Target Factory. P0-D3 does not overload that field with a
composition digest, invent a combined adapter, concatenate two observations, or report a completed
Hybrid chain. The result is fixed to `composition-contract-only`, has no registered Target Factory,
is not Benchmark-Manifest eligible, and cannot authorize provider execution or measurement
admission.

## Exact component authority

`HybridTargetComponent` embeds a complete existing `BenchmarkTargetProfileSelectionAuthority` and
binds its ordinal and role:

1. `entry-traditional-web-api` must be the revision-one
   `target-catalog:pajin-traditional-web-api` Boolean-SQLi Docker profile;
2. `follow-on-ai-rag-mcp` must be the revision-one
   `target-catalog:pajin-ai-rag-mcp-local-docker` upload/RAG/MCP Docker profile.

Each component must use profile and Factory version `1.0.0`, the exact provider-profile API,
Docker internal-bridge policy, no mutation profile, and equal provider-profile/Factory digests. The
two components must have distinct catalog, Factory, adapter, Manifest, and Ground Truth binding
identities. Reversal, repetition, partial composition, cross-family substitution, policy expansion,
or stale digest fails closed.

The registered builder also reopens each complete Manifest and catalog, provisioned Docker profile,
and adapter. Their canonical Manifest digest, registration, catalog digest/revision, image-bound
profile digest, adapter digest, Factory, Ground Truth, and mutation identity must exactly reconstruct
the embedded selection; a self-consistent selection object alone is insufficient.

Embedding the component selections does not authorize them. Their existing selection contract
still states `providerExecutionAuthorized=false`; registered adapters and the recoverable governed
Harness remain separate execution authorities.

## Declared bridge

`HybridTargetBridge` is code-owned and exact:

- source Finding and Surface: the Boolean-SQLi user lookup case;
- destination Finding and Surfaces: the upload/RAG/MCP internal-data case;
- transfer semantics: `synthetic-record-to-untrusted-document`;
- direction: component 1 to component 2; and
- state: `declared-not-executed`, with execution evidence required.

The bridge is an intended future data-flow contract. P0-D3 has no evidence that the SQLi response
was transformed into the exact untrusted document consumed by the AI Target. Neither component's
independent successful run can satisfy the bridge.

## Private Ground Truth binding

The public composition and selection contain component Ground Truth binding digests but no private
cases. `HybridTargetGroundTruthBinding` privately binds:

- the complete, exact seeded Boolean-SQLi case and Docker matcher;
- the complete, exact seeded AI/RAG/MCP case and Docker matcher;
- the composition and bridge digests; and
- `chain:hybrid-sqli-to-rag-mcp-internal-data` in state `declared-not-executed`.

The final selection revalidates every private registration and binding digest against its public
component. A self-consistent private binding with a substituted profile registration therefore
cannot be selected merely by copying the composition digest.

## Required rejection behavior

Tests reject:

- reversed, repeated, or missing components;
- component catalog, family, profile, Factory, version, provider API, network, mutation, and digest
  drift;
- private Surface expansion or matcher/case substitution;
- a private registration that differs from the selected component;
- cross-composition private binding replay;
- bridge Surface expansion and composition digest forgery; and
- attempts to enable provider execution, measurement admission, or Benchmark Manifest eligibility.

## Compatibility, migration, and rollback

The five contracts, builders, tests, and exports are additive. P0-D1, P0-D2, P0-D2B, Manifest,
provider lifecycle, measurement, and Harness artifacts do not change. The composition does not add a
new `targetFamily` or catalog registration because no combined provider exists.

Migration reconstructs both exact component selections, binds their private Ground Truth, creates
the public composition, then creates the non-runnable selection. Rollback stops selecting the
composition and preserves its content-addressed records. It must not reinterpret either component
run as Hybrid bridge evidence.

## Remaining work

A runnable successor must define one Hybrid Target Factory and Manifest identity, a shared or
coordinated isolation boundary, cross-provider fence and cleanup ordering, exact transfer artifact,
bridge execution receipt, combined Ground Truth matcher, and one measurement authority. It must
prove partial-start, partial-cleanup, repeated component, replay, and cross-coordinate failures
before any Hybrid metric is admitted.

## Related documents

- [P0-D1 contract](P0-D1-traditional-web-api-target-catalog.md)
- [P0-D2B contract](P0-D2B-local-ai-rag-mcp-docker-provider.md)
- [P0-C2A recovery contract](P0-C2A-durable-target-operation-recovery.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
