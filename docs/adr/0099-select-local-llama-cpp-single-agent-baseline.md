# ADR-0099: Select a Local llama.cpp Single-Agent Baseline

## Status

Accepted.

## Context

P0-E3A deliberately left the Provider, model, executable, prompt, Tool catalog, sampling, pricing,
and data policy undecided. A paid remote Provider would add credentials, external data transfer,
mutable pricing, and vendor retention policy to the benchmark authority. The available benchmark
host has an NVIDIA RTX 3090 with 24 GiB VRAM, Docker Desktop, and the NVIDIA container runtime, so a
local reproducible Provider is feasible.

The repository already has a governed Provider Gateway and a bounded `PolicyToolLoopRunner`. Adding
another agent framework would duplicate its capability, policy re-entry, Secret Lease, budget,
checkpoint, and cleanup boundaries.

## Decision

1. Reuse `PolicyToolLoopRunner` as the one model-backed agent; do not use the PAJIN multi-role
   runtime or deterministic fallback.
2. Serve `Qwen/Qwen3-4B-Instruct-2507` as the exact Q8_0 GGUF artifact through a digest-pinned
   llama.cpp CUDA server image.
3. Bind the observed local image ID and GGUF SHA-256 in addition to their remote immutable
   references.
4. Use the registered OpenAI-compatible Provider Tool. The local HTTP endpoint requires explicit
   private-network authorization and a Secret Lease; direct SDK calls are not benchmark evidence.
5. Bind temperature zero, top-p one, the benchmark coordinate seed, two turns, zero retries, and no
   fallback. A seed controls sampling input but does not claim deterministic model output.
6. Bind a single fixed boolean SQLi Tool. The model selects the Tool but cannot author attack input;
   the Tool executes three code-owned minimum-impact requests and validates host receipts.
7. Record an opt-in canonical raw model/tool trace before benchmark normalization. Require exact
   request/result/usage, Tool request/receipt/result, and cleanup events with no secret values.
8. Set marginal token pricing to zero for the local Provider. Do not claim that electricity,
   hardware, operator time, or amortized infrastructure cost is zero.
9. Keep data handling local to Docker and do not send benchmark prompts or Target evidence to a
   remote model Provider.
10. Split the concrete runtime/trace boundary from fresh Target measurement. This checkpoint is not
    a completed P0-E3 result until the next slice binds every P0-D1 lifecycle and emits the sealed
    registry-governed `BenchmarkResult`.

## Consequences

- The benchmark can reproduce executable and model inputs without credentials or external model
  charges.
- Existing Provider/Tool Loop security controls remain the execution authority instead of being
  bypassed by a benchmark-only client.
- Raw evidence makes refusal, malformed calls, missing usage, altered sampling, replayed Tools, and
  cleanup failure observable and fail-closed.
- The Q8_0 4B model is a deliberate local baseline, not a claim of state-of-the-art security
  performance.
- Resource cost currently excludes hardware and energy accounting and must remain documented when
  interpreting cost metrics.

## Compatibility and rollback

The new Provider request sampling fields and Tool Loop trace are optional. Existing callers and
wire readers continue to omit them. Removing the registration, reader, and opt-in trace leaves prior
Provider and Tool Loop behavior intact; no measured Result exists at this checkpoint to migrate.

## References

- [P0-E3A plan](../benchmark/P0-E3A-single-agent-baseline-plan.md)
- [P0-E3B runtime contract](../benchmark/P0-E3B-local-single-agent-runtime.md)
- [ADR-0009](0009-provider-backed-agent-runtime.md)
- [ADR-0098](0098-bind-single-agent-identity-before-measurement.md)
