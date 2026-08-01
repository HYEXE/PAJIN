# ADR-0086: Enforce the First Concrete Benchmark Provider on a Local Docker Boundary

- Status: Accepted
- Date: 2026-08-01

## Context

P0-C1 defines the Target lifecycle and measurement signature, P0-C2A adds durable core-side
operation fencing and cleanup recovery, and P0-C2B2A2 makes measurement-registry admission
mandatory. None of them proves that a real provider enforces the supplied fence, isolates the
Target, returns retrievable provider facts, or cleans resources after execution.

Reusing `DockerWorkerBackend` would conflate a short-lived Tool sandbox with the longer Target
reset/isolation/execution/cleanup lifecycle. Treating Docker labels alone as a fence would also
leave concurrent local processes able to race cleanup and resource creation.

## Decision

1. Implement a separate recoverable Docker adapter for only the fixed synthetic Bug Bounty
   Boolean-SQLi profile.
2. Bind the Target Factory digest to exact Target and Worker image IDs and an internal-bridge
   policy; verify mutable references against those IDs before reset, isolation, and execution.
3. Persist operation IDs, attempt ownership, stage order, completed results, and the monotonic
   fence in a provider-owned SQLite database before Docker side effects.
4. Serialize local provider mutations with a second SQLite operation lock. The durable fence and
   process-lifetime lock are deliberately separate so a crash retains ownership history while
   releasing execution exclusion.
5. Use deterministic, fully labelled resources; reject foreign-coordinate or newer-fence
   resources before deletion.
6. Create an internal Docker network with no published ports and run both Target and Worker with a
   non-root user, read-only root, dropped capabilities, `no-new-privileges`, and bounded resources.
7. Content-address bounded Docker/image/container/network/probe observations and bind the digest to
   each existing stage receipt. Retrieve evidence only through that exact receipt.
8. Keep P0-C1/P0-C2A and registry-governed Harness contracts unchanged.

## Consequences

- The first real Target lifecycle is exercised and measured through the same public contracts as
  deterministic test adapters.
- A stale local operation fails before Docker, completed operation replay is side-effect free, and
  higher-fence cleanup cannot race a live lower-fence mutation on the same host state.
- Provider facts remain inspectable without putting Docker's large, unstable inspect payloads into
  the sealed benchmark schema.
- The adapter is intentionally coupled to one synthetic vulnerable lab. Its fixed measurement
  mapping must not be interpreted as generic Web/API adjudication.
- SQLite and Docker Desktop are in the same trusted local-host boundary. Cross-host fencing and an
  independently anchored provider evidence service remain future work.

## Compatibility and rollback

The implementation is additive. Existing manifests that name another Target Factory cannot select
the adapter, and all earlier readers ignore the new provider evidence type.

Rollback stops selecting the Docker adapter and preserves already sealed P0-C1/P0-C2A and governed
Harness Runs. Local `pajin-bench-*` resources may be removed only after validating their complete
managed labels; the provider state database must not be silently reset to bypass a recorded fence.

## Related documents

- [P0-C2B2B contract](../benchmark/P0-C2B2B-local-docker-provider-evidence.md)
- [P0-C2A contract](../benchmark/P0-C2A-durable-target-operation-recovery.md)
- [P0-C2B2A2 contract](../benchmark/P0-C2B2A2-mandatory-registry-governed-harness.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
