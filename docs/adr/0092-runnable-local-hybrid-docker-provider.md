# ADR-0092: Implement the First Hybrid Chain as a Separate Local Docker Factory

- Status: Accepted
- Date: 2026-08-01

## Context

P0-D3 and P0-D3B1 define an exact two-component composition and the required multi-container
topology, but intentionally grant no execution authority. The existing component images cannot be
joined causally: the SQLi response lacks a transferable document and the AI image accepts a fixed
independent upload. Existing provider evidence also binds one Target container.

## Decision

1. Introduce a separate Hybrid Factory, profile, catalog, Ground Truth matcher, adapter, and evidence
   contract instead of changing either predecessor into a combined provider.
2. Build Hybrid-specific Traditional and AI Target images plus one Worker on a single internal
   network under one coordinate and fence.
3. Require the malicious document to originate in the sealed SQLi response and preserve both raw
   SHA-256 and domain-separated transfer-artifact identity.
4. Bind the exact ordered bridge and complete decoded source, upload, and query responses into one
   execution receipt and provider evidence record. Preserve bounded complete bodies with their
   digests so a later reader can repeat exact validation.
5. Reuse the durable operation journal for idempotency, stale-fence rejection, partial-start
   recovery, and reverse cleanup.
6. Keep the predecessor P0-D3 selection non-runnable. Only the new Hybrid catalog selection plus the
   recoverable runner may execute the Factory.

## Consequences

- A successful run proves a causal SQLi-to-upload-to-RAG-to-MCP chain rather than two independent
  successes.
- The combined Ground Truth matcher supports exact two-Finding, four-Surface, one-chain Observation
  admission.
- Three new images and a separate evidence API increase local provider maintenance, but existing
  component wire identities remain stable.
- The provider is host-local and model-free. Production multi-service trust and cross-host fencing
  remain separate future work.

## Compatibility and rollback

The change is additive except for widening the existing target-family and catalog-ID enums with one
new Hybrid value each. Existing values, serialized records, and digests do not change. The internal
operation-cache evidence loader defaults to the original single-target parser.

Rollback disables the Hybrid catalog and removes its local images. It does not reinterpret or
delete historical content-addressed artifacts, and it does not make P0-D3 executable.

## Related documents

- [P0-D3B2 contract](../benchmark/P0-D3B2-local-hybrid-docker-provider.md)
- [P0-D3B1 contract](../benchmark/P0-D3B1-hybrid-provider-topology-contract.md)
- [ADR-0091](0091-hybrid-provider-topology-before-runtime.md)
- [P0-C2A recovery contract](../benchmark/P0-C2A-durable-target-operation-recovery.md)
