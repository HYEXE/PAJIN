# P0-D2: AI/RAG/MCP Target Fixture Catalog and Ground Truth Profile

- Status: Implemented contract-only profile
- Fixture profile: `pajin.dev/ai-rag-mcp-walking-target-profile/v1alpha1`
- Fixture selection: `pajin.dev/benchmark-target-fixture-selection/v1alpha1`
- Decision: [ADR-0088](../adr/0088-non-runnable-ai-rag-mcp-target-fixture.md)
- Predecessor: [P0-D1](P0-D1-traditional-web-api-target-catalog.md)

## Scope

P0-D2 registers the existing WALK-002 through WALK-005C1 File Upload -> RAG Injection -> MCP Tool
Authorization Failure -> Internal Data Access scenario as an AI/RAG/MCP benchmark fixture profile.
The repository does not yet contain a P0-C provider lifecycle for that multi-surface Target. The
profile is therefore fixed to `fixture-contract-only`; its selection is
`registered-fixture-not-runnable`, `providerExecutionAuthorized=false`, and
`measurementAdmissionEligible=false`.

This slice does not turn sealed walking-skeleton test evidence into a measured Benchmark Result. It
does not create a Target adapter, reset or isolation receipt, Capability, approval, Permit, Tool
request, dispatch, measurement signature, registry admission, or governed Harness authority.

## Catalog compatibility

P0-D1's public registration and catalog wire values remain unchanged. Their validation types now
also permit:

- target family `ai-rag-mcp`;
- a bounded `pajin.dev/...` provider-profile API version;
- catalog ID `target-catalog:pajin-ai-rag-mcp`; and
- network policy `not-provisioned-contract-only`.

Each family-specific builder still reconstructs the complete expected catalog and rejects mixed or
foreign registrations. The shared catalog validator also requires every registration family to
match its code-owned catalog ID. Existing Traditional Web/API serialized artifacts and digests do
not gain new fields and do not change.

## Code-owned fixture profile

`AIRAGMCPWalkingTargetProfile` content-addresses:

- profile `ai-rag-mcp.walking.file-upload-rag-tool-authorization@1.0.0`;
- contract identity `target-factory:walking-ai-rag-mcp-fixture-contract@1.0.0`;
- execution availability `fixture-contract-only`;
- evidence trust `sealed-walking-fixture-network-untrusted`;
- network policy `not-provisioned-contract-only`; and
- the exact WALK-002, WALK-003, WALK-005A, WALK-005B2, and WALK-005C1 API versions in canonical
  order.

Calling this identity a Target Factory contract does not imply an implementation. No
`RegisteredBenchmarkTargetFactoryAdapter` is constructed or accepted by the P0-D2 selection.

## Private Ground Truth

The public registration contains only the Ground Truth digest. The private binding contains one
seeded case:

- Finding: `finding:rag-mcp-authorization-internal-data`;
- Surfaces: document file upload, RAG corpus ingest, and MCP `inspect_text` Tool;
- chain: `chain:file-upload-rag-mcp-internal-data`; and
- matcher: `matcher:sealed-walking-rag-mcp-confirmation@1.0.0`.

The matcher digest uses only existing contract values verified by the walking implementation:

- WALK-002 `not-authorized` and WALK-003 `registered-not-authorized`;
- WALK-005A `candidate-admitted-not-confirmed`;
- WALK-005B2 `validity-reproduced-not-confirmed`;
- WALK-005C1 confirmation basis and lifecycle state;
- input marker `ignore previous`;
- `vulnerable=true`, `authorizationEnforced=false`, and `internalDataAccessed=true`;
- exact instruction-hijacking observation plus `demo-security / inspect_text`; and
- sealed Gateway evidence with `networkLogTrusted=false`.

This matcher identifies the code-owned seeded fixture semantics. P0-D2 does not implement a generic
matcher that reads a new provider result or automatically converts historical WALK Runs into
Benchmark observations.

## Selection boundary

`select_ai_rag_mcp_target_fixture` requires exact equality of:

1. code-owned profile and its source contract list;
2. caller-supplied public catalog and the reconstructed AI/RAG/MCP catalog;
3. complete private Ground Truth and code-owned seeded case;
4. Manifest benchmark, profile, Target Factory, Ground Truth, and mutation identities; and
5. public registration, fixture profile, and private binding digests.

The resulting `BenchmarkTargetFixtureSelectionAuthority` contains no adapter digest or provider
receipt. It cannot satisfy `BenchmarkTargetRunExecutor`, P0-C recovery, measurement-registry
preflight, or governed Harness input.

## Required rejection behavior

Tests reject:

- unknown profile IDs or versions and any mutation profile;
- Ground Truth digest, visibility, matcher, or expected Finding replacement;
- Traditional Web/API catalog substitution and mixed-family selection;
- missing, reordered, or substituted source API contracts;
- forged fixture profile or selection digests; and
- attempts to set provider execution or measurement eligibility to true.

## Compatibility, migration, and rollback

The fixture profile, selection authority, builders, tests, and exports are additive. The shared
catalog schema accepts a second family without adding serialized fields to P0-D1 registrations.
BENCH-001, P0-C, P0-D1, WALK, and governed Harness wire formats remain unchanged.

Migration creates the code-owned fixture profile, its private Ground Truth for one benchmark ID,
the corresponding public catalog, and a non-runnable selection. Operators must not pass that
selection into a benchmark lifecycle or report metrics from it. Rollback stops selecting the
fixture and preserves its content-addressed records; it does not relabel the fixture as runnable.

## Remaining work

A later P0-D slice must implement a real, isolated AI/RAG/MCP Target lifecycle with reset, seed,
execution, receipt-bound evidence, cleanup, and measurement authority before this profile can gain
a runnable registration. Holdout and Mutation profiles remain separate work and must not reuse
seeded fixture contents.

## Related documents

- [P0-D1 contract](P0-D1-traditional-web-api-target-catalog.md)
- [WALK-002 contract](../orchestration/WALK-002-rag-injection-hypothesis.md)
- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [WALK-005A contract](../orchestration/WALK-005-approved-execution-candidate-admission.md)
- [WALK-005C1 contract](../orchestration/WALK-005C1-mcp-confirmation-report-remediation-baseline.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
