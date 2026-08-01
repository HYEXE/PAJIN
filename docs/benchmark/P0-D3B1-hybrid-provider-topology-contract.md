# P0-D3B1: Hybrid Provider Topology and Transfer Contract

- Status: Implemented contract-only topology
- Transfer schema API: `pajin.dev/hybrid-transfer-artifact-schema/v1alpha1`
- Topology API: `pajin.dev/hybrid-provider-topology/v1alpha1`
- Decision: [ADR-0091](../adr/0091-hybrid-provider-topology-before-runtime.md)
- Predecessor: [P0-D3](P0-D3-hybrid-target-composition.md)
- Runnable successor: [P0-D3B2](P0-D3B2-local-hybrid-docker-provider.md)

## Scope

P0-D3B1 defines the exact boundary that a runnable Hybrid Docker provider must implement. It binds
the complete P0-D3 selection and private Ground Truth binding to one planned Hybrid Factory, one
shared internal network, two Target services, one Worker, one ordered bridge, and one transfer
artifact schema.

This version does not bind Docker image IDs, register an adapter, create a `BenchmarkManifest`, run
containers, or admit measurement. It is fixed to `provider-contract-only` because the current
Traditional response exposes only `id` and `handle`, while the current AI Target accepts one fixed
document body. Treating those independent implementations as an executed data flow would invent
evidence.

## Exact predecessor binding

`registered_hybrid_provider_topology` reopens the complete public selection and private binding,
reconstructs the P0-D3 selection, and requires exact equality. The topology embeds the public
selection and its binding digest but never exposes private Ground Truth cases.

The transfer schema binds all three predecessor identities:

- the P0-D3 bridge digest;
- component 1's content digest as the source; and
- component 2's content digest as the destination.

Cross-composition private bindings, component substitution, forged predecessor digests, and bridge
substitution therefore fail closed.

## Transfer artifact schema

The future Worker must create canonical JSON with media type
`application/vnd.pajin.hybrid-transfer+json` and the exact ordered fields:

1. `schemaVersion`;
2. `sourceObservationDigest`;
3. `sourceResponseDigest`;
4. `documentId`; and
5. `documentContent`.

`documentContent` must be extracted from `/records/0/documentContent` in the sealed Traditional
response and uploaded to `/documents` as `document:hybrid-sqli-transfer`. The source response and
transfer artifact require separate digests. A runtime receipt is mandatory, but its state remains
`schema-registered-not-executed` in this version.

The explicit source pointer means the runnable successor needs Hybrid-specific seeded Traditional
data. It cannot silently reuse the current two-field SQLi response or inject a code-owned document
that was not derived from the source observation.

## Topology and lifecycle prerequisites

The planned Factory and adapter identities are respectively
`target-factory:docker-hybrid-sqli-rag-mcp` and
`target-adapter:docker-hybrid-sqli-rag-mcp`, version `1.0.0`. The topology requires:

- one shared internal bridge with no published ports;
- startup order: Traditional Target, AI Target, Worker;
- reverse cleanup order: Worker, AI Target, Traditional Target;
- bridge order: Traditional probe, sealed response, extraction, sealed transfer, upload, AI probe;
  and
- one Target coordinate and one fence across the complete ordered component journal.

Order reversal, extra services, transfer-field changes, repeated component identity, and digest
forgery fail closed.

## Non-execution boundary

The following values are immutable in P0-D3B1:

- `imageBindingState=required-not-bound`;
- `adapterRegistrationState=planned-not-registered`;
- `executionAvailability=provider-contract-only`;
- `providerExecutionAuthorized=false`;
- `benchmarkManifestEligible=false`;
- `measurementAdmissionEligible=false`; and
- `bridgeExecutionObserved=false`.

The topology authority is not a capability, receipt, provider evidence, Observation, result, or
Harness source.

## Compatibility, migration, and rollback

The contracts and exports are additive. P0-D1, P0-D2B, P0-D3, `BenchmarkManifest`, single-target
Docker evidence, lifecycle, recovery, and measurement wire formats do not change.

Migration reconstructs an exact P0-D3 selection and private binding, then registers the topology.
The runnable successor must bind real image IDs and adapter identity to this authority rather than
changing its non-execution flags. Rollback stops producing the topology while retaining its
content-addressed historical record.

## Remaining work

P0-D3B2 must implement the three images and one recoverable multi-container adapter, produce a
sealed transfer artifact and bridge receipt, prove ordered cleanup and higher-fence recovery, and
pass real-Docker positive and partial-failure conformance before registering a runnable Factory or
Manifest.
