# P0-D3B2: Runnable Local Hybrid Docker Provider

- Status: Implemented runnable local-Docker profile
- Profile API: `pajin.dev/docker-hybrid-target-profile/v1alpha1`
- Transfer API: `pajin.dev/hybrid-transfer-artifact/v1alpha1`
- Bridge receipt API: `pajin.dev/hybrid-bridge-execution-receipt/v1alpha1`
- Evidence API: `pajin.dev/docker-hybrid-provider-evidence/v1alpha1`
- Decision: [ADR-0092](../adr/0092-runnable-local-hybrid-docker-provider.md)
- Predecessor: [P0-D3B1](P0-D3B1-hybrid-provider-topology-contract.md)

## Scope

P0-D3B2 implements the first runnable Hybrid Target under one Factory, Manifest, coordinate, fence,
operation journal, internal Docker network, and measurement authority. It uses three new images:

- `pajin-hybrid-traditional-target:dev` seeds a Boolean-SQLi response whose first expanded record
  contains the untrusted document;
- `pajin-hybrid-ai-rag-mcp-target:dev` accepts only that transferred document and exposes the
  deterministic RAG-to-MCP authorization failure; and
- `pajin-hybrid-benchmark-worker:dev` performs the ordered causal bridge and emits bounded response
  bodies and digests.

The implementation is a deterministic, model-free local security lab. It does not claim production
MCP service isolation, external provider trust, or cross-host fencing.

## Runnable profile and catalog

`DockerHybridTargetProfile` binds the P0-D3B1 topology and transfer-schema digests, three distinct
exact image IDs, the Hybrid profile identity, and the new
`target-factory:docker-hybrid-sqli-rag-mcp` Factory digest.

The additive `target-catalog:pajin-hybrid-local-docker` catalog registers family `hybrid` and binds
the exact profile, adapter, Manifest, network policy, and private Ground Truth. The existing P0-D3
selection remains `registered-composition-not-runnable`; runtime authority comes only from the new
catalog selection and recoverable lifecycle.

The code-owned Hybrid matcher binds two seeded component Findings, four Surfaces, one shared chain,
the Hybrid evidence/transfer/receipt API versions, and exact Observation counts. A Manifest must use
this private Ground Truth digest; the P0-D3B1 private predecessor digest alone is not sufficient for
measurement.

## Lifecycle and isolation

The adapter reuses the durable P0-C2A operation journal. All resources carry adapter, coordinate,
and fence labels. A stale fence fails before Docker mutation, while a strictly higher cleanup fence
may recover abandoned resources.

Isolation creates one unpublished internal bridge, then starts the Traditional Target followed by
the AI Target. Both containers and the Worker use a read-only root filesystem, dropped capabilities,
`no-new-privileges`, fixed memory/CPU/PID limits, a non-root user, and a bounded no-exec temporary
filesystem. Execution starts one Worker. Cleanup removes Worker, AI Target, Traditional Target, then
the network.

## Causal transfer and receipt

The Worker performs baseline, negative-control, and Boolean SQLi requests. It seals the complete
expanded response and extracts `/records/0/documentContent`. The canonical transfer fields are:

1. `schemaVersion`;
2. `sourceObservationDigest`;
3. `sourceResponseDigest`;
4. `documentId`; and
5. `documentContent`.

The Worker uploads that exact content, runs the AI query, and returns bounded Base64 response bodies
with SHA-256 values. The host re-decodes and compares every complete body; success flags alone are
insufficient. `HybridTransferArtifact` adds the registered schema digest and a domain-separated
artifact digest. `HybridBridgeExecutionReceipt` binds topology, schema, coordinate, operation,
fence, raw serialized transfer SHA-256, domain-separated artifact digest, source/upload/query
response digests, bounded complete response bodies, and exact ordered steps. Receipt validation
re-decodes all three bodies and requires exact body equality, so later audit does not depend on the
ephemeral Worker stdout.

`DockerHybridProviderEvidence` binds the receipt and artifact to exact images, both Target container
IDs, Worker ID, internal network, health, zero published ports, and stage operation. Evidence can be
retrieved only through its exact stage receipt.

## Required rejection behavior

Tests reject or recover:

- image, topology, schema, Manifest, adapter, catalog, matcher, and Ground Truth substitution;
- true success flags paired with a substituted transfer body;
- transfer/artifact/bridge digest changes and bridge-order reversal;
- service expansion, hardening drift, stale fence, and receipt substitution;
- partial startup when the AI Target cannot be created; and
- abandoned resources unless a higher-fence reverse cleanup succeeds.

The opt-in real-Docker test builds and runs all three images and verifies the completed bridge and
resource absence after cleanup.

## Compatibility, migration, and rollback

Existing single-target profile, evidence, Manifest, lifecycle, and measurement APIs do not change.
The shared operation cache now accepts a caller-supplied strict evidence loader so the new evidence
type can replay completed operations; existing callers retain the original evidence parser.

The catalog family and catalog-ID enums are widened additively with `hybrid` and the local Hybrid
catalog. Existing catalog values and digests are unchanged.

Migration builds the three images, records their exact IDs in the profile, creates the code-owned
Ground Truth and catalog, selects the profile, and runs it through the recoverable governed runner.
Rollback stops selecting the Hybrid catalog and removes the three local images. Historical receipts
remain verifiable and P0-D3/P0-D3B1 records remain non-executable.
