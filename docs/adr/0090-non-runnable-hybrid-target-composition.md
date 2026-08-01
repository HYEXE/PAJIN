# ADR-0090: Compose Exact Target Selections Before Implementing a Hybrid Provider

- Status: Accepted
- Date: 2026-08-01

## Context

P0-D1 and P0-D2B provide two independently runnable local-Docker Target profiles. A Hybrid Target is
not the same as listing both profiles or adding their successful observations. The current
`BenchmarkManifest`, Target coordinate, recoverable lifecycle, provider evidence, and measurement
attestation each bind one Target Factory and adapter.

There is also no implemented transfer from the SQLi Target's synthetic response into the exact
untrusted document consumed by the AI Target. Claiming a completed Hybrid chain now would invent
execution, cleanup, and measurement authority that does not exist.

## Decision

1. Add a separate, content-addressed Hybrid composition authority instead of changing the existing
   Manifest or catalog schemas.
2. Bind the complete exact P0-D1 selection as ordinal 1 and the complete exact P0-D2B selection as
   ordinal 2, including distinct catalog, Factory, adapter, Manifest, and private binding identities.
3. Define one code-owned directed bridge from the SQLi Finding/Surface to the AI Finding/Surfaces,
   fixed to `declared-not-executed` and requiring future execution evidence.
4. Keep complete component Ground Truth cases in a separate private binding and revalidate each
   private registration and binding digest during final selection.
5. Permanently deny Target Factory registration, Benchmark Manifest eligibility, provider execution,
   and measurement admission in this version.
6. Do not synthesize a Hybrid Finding, Observation, receipt, metric, or sealed Harness authority from
   independent component results.

## Consequences

- The first Hybrid profile has an exact, auditable structural identity without overstating runtime
  capability.
- Component order, duplication, scope expansion, private registration substitution, and cross-
  composition replay fail closed.
- Existing component profiles remain independently runnable under their own lifecycle authorities.
- A future runnable Hybrid provider needs a new Factory/Manifest identity, coordinated lifecycle,
  transfer evidence, matcher, cleanup policy, and measurement admission.

## Compatibility and rollback

The change is additive and does not modify P0-D1, P0-D2, P0-D2B, Manifest, provider, measurement, or
Harness wire formats. No new catalog family or runnable registration is introduced.

Rollback removes the P0-D3 composition from active selection while preserving content-addressed
historical records. It must not promote either independent component run into Hybrid bridge
evidence.

## Related documents

- [P0-D3 contract](../benchmark/P0-D3-hybrid-target-composition.md)
- [P0-D1 contract](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-D2B contract](../benchmark/P0-D2B-local-ai-rag-mcp-docker-provider.md)
- [ADR-0089](0089-local-ai-rag-mcp-docker-provider.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
