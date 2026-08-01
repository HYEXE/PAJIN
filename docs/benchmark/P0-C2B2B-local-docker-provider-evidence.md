# P0-C2B2B: Local Docker Provider Evidence and Network Enforcement

- Status: Implemented contract and live conformance
- Target profile: `pajin.dev/docker-bug-bounty-target-profile/v1alpha1`
- Provider evidence: `pajin.dev/docker-benchmark-provider-evidence/v1alpha1`
- Decision: [ADR-0086](../adr/0086-local-docker-benchmark-provider.md)
- Predecessors: [P0-C2A](P0-C2A-durable-target-operation-recovery.md),
  [P0-C2B2A2](P0-C2B2A2-mandatory-registry-governed-harness.md)

## Scope

P0-C2B2B supplies one concrete `RecoverableBenchmarkTargetFactoryAdapter` for the synthetic local
Bug Bounty Boolean-SQLi lab. It is deliberately not a generic arbitrary-image runner. The profile
fixes the scenario and vulnerable Target mode and content-addresses the Target Factory over the
human-readable image references, exact local image IDs, and `internal-bridge` network policy.

The adapter receives the exact Benchmark Manifest and measurement Trust Anchor at construction.
The Manifest Target Factory identity must equal the profile-derived identity. The Ed25519 private
measurement key remains caller-provisioned and is never written to provider state or evidence.

## Provider-side fencing and idempotency

The P0-C2A operation ID and fence are enforced in a separate provider-owned SQLite state store,
not inferred from the core journal. State uses `synchronous=FULL`, `journal_mode=DELETE`, safe
single-link paths, an exact adapter/coordinate scope, and these rules:

1. a lower fence is rejected before any Docker command;
2. one fence belongs to one attempt and follows reset, isolation, execution, cleanup order;
3. a completed operation returns its exact persisted receipt and Observation without another
   Docker call;
4. a failed or in-progress operation is not replayed under the same ID; recovery requires the
   P0-C2A higher cleanup fence; and
5. a second SQLite operation-lock database serializes provider mutations across local processes.

The operation lock is held while Docker is mutated, while the accepted fence remains durably
committed in the provider state database. A process crash releases the SQLite lock automatically
but retains the fence. A higher recovery cleanup can therefore take ownership without racing a
still-running lower-fence mutation.

This is a host-local provider boundary. It does not claim cross-host or remote Docker ownership.

## Docker lifecycle and network policy

Resource names are deterministic from the full coordinate digest and every resource carries
managed, adapter, coordinate, fence, and role labels. A truncated name collision fails ownership
validation because the complete coordinate digest remains in the labels.

- reset verifies both mutable image references still resolve to the profile's exact image IDs,
  validates ownership of any prior deterministic resources, removes them, and proves absence;
- isolation creates one Docker `--internal` bridge with no published ports and starts the exact
  vulnerable Target image as UID/GID 65532 with a read-only root, all capabilities dropped,
  `no-new-privileges`, bounded CPU, memory, PIDs, and a bounded `noexec` temporary filesystem;
- execution creates the dedicated standard-library-only `pajin-benchmark-worker:dev` image under
  the same restrictions and internal network, runs only `bug-bounty-sqli-probe`, and accepts only
  the fixed synthetic target, scenario,
  checks, three observations, and `networkPerformed=true` result; and
- cleanup and recovery remove Worker, Target, then network, validate ownership and non-newer
  resource fences before deletion, and return success only after all three are absent.

Docker reports only running endpoints in `network inspect`; after the Worker exits the sole active
network member is the Target. The adapter therefore proves one active Target member, the Worker's
exact NetworkMode, and the successful network-performed probe together rather than incorrectly
requiring a stopped Worker endpoint to remain active.

## Provider evidence and measurement mapping

Every stage produces bounded `DockerBenchmarkProviderEvidence` containing the exact operation,
fence, adapter/coordinate/environment, Docker server version, image IDs, applicable resource IDs,
internal-network and published-port observations, health/exit/probe facts, or final absence fact.
Its domain-separated digest is the stage receipt's `providerEvidenceDigest`.

Evidence retrieval requires the exact stage receipt, revalidates the cached receipt and evidence,
and requires digest equality. The final P0-C1 attestation therefore remains the immutable caller
anchor for mutable local provider state.

The single supported synthetic vulnerable scenario maps its exact baseline, false-control, and
expanded Boolean-probe triplet to one known Surface, Candidate, atomic confirmation/replay success,
and completed ground-truth chain; one deterministic Worker Tool call; no model call or cost; one
registered adjudication opportunity with no human intervention; and no open-world Finding. The
adapter verifies every response body's base64 encoding, SHA-256, synthetic marker, record count,
and query mode before applying that fixed mapping. P0-C1 still derives final cleanup flags and signs
the full lifecycle. These fixed counts are not a general Web/API adjudicator.

## Negative boundaries and conformance

Tests reject stale fences, lifecycle reordering, image substitution, foreign or newer resource
labels, malformed or oversized CLI output, failed probe semantics, forged receipt-to-evidence
bindings, and abandoned-resource reuse before a higher-fence cleanup. The fake CLI suite covers
deterministic failure and recovery without requiring a daemon.

An opt-in live test ran against Docker Desktop 4.78.0 / Engine 29.5.3 with the repository's
`pajin-benchmark-worker:dev` and `pajin-bug-bounty-target:dev` images. The dedicated Worker has no
third-party packages or generic Tool actions and builds without fetching Python dependencies. The
test proved a complete reset, internal isolation, real HTTP probe, cleanup, sealed Target Run,
registry-governed Harness admission and reader, and no remaining `pajin-bench-*` container or
network. Standard test runs skip only this daemon-dependent case.

## Compatibility and remaining work

All P0-C1, P0-C2A, P0-C2B1, P0-C2B2A1/A2, BENCH-003B, receipt, Observation, and sealed Harness wire
formats remain unchanged. The new profile, evidence model, adapter, command boundary, and public
exports are additive. The existing registry-governed Harness accepts the recoverable Docker runner
without a special integration path.

P0-D1 now places this one synthetic Traditional Web/API profile behind a public catalog/private
Ground Truth split and an additive exact-selection wrapper. P0-D must still define separately
catalogued AI/RAG/MCP, Hybrid, Holdout, and Mutation Target Factories. Remote provider fencing,
independently sealed provider evidence, and cross-host ownership remain outside this local slice.

## Related documents

- [P0-C2B2A2 contract](P0-C2B2A2-mandatory-registry-governed-harness.md)
- [P0-C2A contract](P0-C2A-durable-target-operation-recovery.md)
- [P0-C1 contract](P0-C1-provider-neutral-target-factory-lifecycle.md)
- [P0-D1 contract](P0-D1-traditional-web-api-target-catalog.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
