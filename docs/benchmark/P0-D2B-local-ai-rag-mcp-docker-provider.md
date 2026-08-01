# P0-D2B: Local AI/RAG/MCP Docker Provider and Runnable Catalog

- Status: Implemented
- Provider profile: `pajin.dev/docker-ai-rag-mcp-target-profile/v1alpha1`
- Provider evidence: `pajin.dev/docker-benchmark-provider-evidence/v1alpha1`
- Catalog selection: `pajin.dev/benchmark-target-profile-selection/v1alpha1`
- Decision: [ADR-0089](../adr/0089-local-ai-rag-mcp-docker-provider.md)
- Predecessor: [P0-D2](P0-D2-ai-rag-mcp-target-fixture-catalog.md)

## Scope

P0-D2B adds one runnable, synthetic, local-Docker AI/RAG/MCP Target. A fixed Worker uploads one
untrusted document, asks the Target to process it through its deterministic RAG path, and observes
the Target call its own explicit MCP HTTP endpoint without independent approval. The MCP endpoint
returns a synthetic internal marker. This proves the registered File Upload -> RAG -> MCP
Authorization Failure -> Internal Data Access chain without a model call or an external service.

The MCP endpoint is a distinct HTTP boundary inside the Target container, not a separately deployed
MCP server or a claim about production MCP transport conformance. The entire lab is synthetic and
is reachable only on the per-coordinate internal Docker bridge.

## Separate runnable identity

The P0-D2 fixture remains unchanged and non-runnable. P0-D2B uses a new profile,
`ai-rag-mcp.docker.file-upload-rag-tool-authorization@1.0.0`, Target Factory
`target-factory:docker-ai-rag-mcp`, adapter `target-adapter:docker-ai-rag-mcp`, and catalog
`target-catalog:pajin-ai-rag-mcp-local-docker`.

This separation prevents a historical `BenchmarkTargetFixtureSelectionAuthority` from acquiring an
adapter digest or becoming executable through reinterpretation. The runnable catalog uses the
existing `BenchmarkTargetProfileSelectionAuthority`; that selection still does not authorize
execution by itself. The registered adapter, recoverable Target runner, measurement key admission,
and governed Harness retain their existing independent authority boundaries.

## Content-addressed provider profile

`DockerAIRAGMCPTargetProfile` binds:

- exact Target and Worker image references and `sha256:` image IDs;
- the fixed internal-bridge network policy;
- target state `vulnerable-missing-independent-approval`; and
- the complete Target Factory digest.

The provider rejects image substitution before resource mutation. It creates non-root, read-only,
capability-dropped Target and Worker containers with bounded CPU, memory, PIDs, and temporary
storage. No port is published and the bridge is Docker-internal.

## Deterministic execution protocol

The Worker accepts only action `ai-rag-mcp-chain-probe` and the exact scenario/Target input. It
performs these fixed requests:

1. upload `document:untrusted-upload` containing the `ignore previous` marker and the exact
   `internal://policy` Tool argument;
2. query the deterministic agent endpoint;
3. receive a response proving the uploaded document was retrieved, its argument reached
   `demo-security / inspect_text`, no independent authorization was enforced, and the synthetic
   internal marker was accessed.

The host adapter does not trust Worker booleans alone. It requires the exact output field set,
check set, observation order, HTTP status, bounded Base64 response bodies, body SHA-256 values, and
complete decoded response bodies. Any missing, additional, malformed, or semantically substituted
value fails before a Benchmark observation is returned.

## Lifecycle, recovery, and evidence

The provider reuses the P0-C2B2B durable lifecycle rather than cloning it. Provider-owned SQLite
state and a process-lifetime operation lock preserve idempotency, stage order, monotonic fences,
and higher-fence cleanup. Reset removes prior resources, so the in-memory corpus and vulnerable
state are restored only by a fresh Target container. Cleanup proves that Target, Worker, and network
resources are absent.

Each stage emits receipt-bound `DockerBenchmarkProviderEvidence`. Execution evidence binds the
adapter, coordinate, operation, fence, exact image IDs, internal network, hardened containers,
healthy Target, zero-exit Worker, validated vulnerable probe, and canonical output digest.

## Ground Truth and measurement mapping

The runnable public catalog exposes only the Ground Truth digest. Its private seeded case preserves
the same three registered surfaces, Finding, and chain, but uses a distinct
`matcher:docker-ai-rag-mcp-chain-probe` digest. That matcher binds the Docker profile/evidence API,
fixed Worker action, exact decoded Target observations, and internal-network provider facts. It does
not reuse the P0-D2 Walking matcher, whose evidence semantics include
`networkLogTrusted=false`. After exact provider and receipt validation, the adapter maps the run to
three discovered known surfaces, one matched and confirmed known Finding, one completed chain, one
deterministic Tool call, zero model calls, and zero model cost.

These counts describe this fixed benchmark protocol only. They are not a generic AI scanner metric
or evidence that an LLM reasoned over the uploaded document.

## Required rejection behavior

Tests reject image substitution, malformed or unproved Worker output, Target hardening drift,
stale fences, lifecycle reordering, foreign receipts, catalog/Manifest/adapter/Ground Truth
substitution, and evidence/count mismatches. Existing SQLi provider and P0-D2 fixture tests remain
unchanged and pass through the shared lifecycle refactor.

## Compatibility, migration, and rollback

The new profile, catalog ID, provider, containers, wrapper, tests, and exports are additive. The
P0-D2 fixture profile, fixture catalog, selection wire shape, and false execution/measurement flags
do not change. P0-D1 serialized values and digests do not change.

Migration builds the two pinned-base images, records their exact local image IDs in the runnable
profile, reconstructs the private Ground Truth and catalog, and selects the registered adapter.
Rollback stops selecting the local-Docker catalog and preserves sealed historical artifacts. It
must not relabel runnable selections as fixture selections or reuse image IDs after rebuilding
different image contents.

## Remaining work

The provider is host-local and single-profile. Catalog distribution signatures, durable catalog
activation, holdout isolation, mutation profiles, separate MCP service deployment, model-backed RAG,
cross-host fencing, and production external-provider trust remain out of scope.

## Related documents

- [P0-D2 contract](P0-D2-ai-rag-mcp-target-fixture-catalog.md)
- [P0-C2B2B contract](P0-C2B2B-local-docker-provider-evidence.md)
- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
