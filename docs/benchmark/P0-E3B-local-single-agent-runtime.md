# P0-E3B Local Single-Agent Runtime and Raw Trace

## Status

The concrete runtime and raw-trace vertical slice is implemented. It selects one local
OpenAI-compatible Provider, pins its executable and model artifacts, extends the existing governed
`PolicyToolLoopRunner` with exact sampling and secret-free raw JSONL evidence, and admits only a
successful two-model-call/one-Tool trace. Fresh P0-D1 Target lifecycle and completed
`BenchmarkResult` binding remain the next slice; this document does not claim a baseline
measurement yet.

## Concrete identity

| Input | Bound value |
| --- | --- |
| Agent implementation | `pajin.workflow.policy-tool-loop@model-tool-trace-v1` |
| Runtime | `ghcr.io/ggml-org/llama.cpp:server-cuda13-b9445` pinned by OCI digest |
| Provider API | local llama.cpp OpenAI-compatible `/v1/chat/completions` |
| Base model | `Qwen/Qwen3-4B-Instruct-2507` |
| GGUF repository revision | `ggml-org/Qwen3-4B-Instruct-2507-Q8_0-GGUF@3b0392219163df872850175fbf7d2bea11c66cbf` |
| GGUF file | `qwen3-4b-instruct-2507-q8_0.gguf` |
| GGUF SHA-256 | `ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1` |
| Model alias | `qwen3-4b-instruct-2507-q8_0` |
| Sampling | temperature `0`, top-p `1`, coordinate seed, two turns, no retry |
| Tool | fixed `bug-bounty.boolean-sqli-probe` binding; model cannot author a payload |
| Pricing | local Provider marginal token price fixed to USD `0`; hardware amortization excluded |
| Data handling | local Docker only; no remote model Provider |

The OCI manifest digest, observed local image ID, GGUF revision and file digest, Provider
registration, prompt bundle, Tool catalog, and runtime configuration are independently bound into
`LocalLlamaCppSingleAgentRegistration`. A changed endpoint, model alias, secret-ref name, image ID,
prompt, Tool schema, sampling value, or model file cannot reuse that registration.

## Raw evidence

Opt-in traced Tool Loop runs write `evidence/pajin-model-tool-trace.jsonl` using
`pajin-model-tool-trace-jsonl/v1`. The first record contains all eight P0-E3A identity fields. A
successful local trace has this exact event sequence:

1. identity;
2. model request, model result, and Provider usage;
3. Tool request, host receipt, and Tool result;
4. second model request, final model result, and Provider usage; and
5. cleanup with zero active Secret Leases.

Every line is canonical UTF-8 JSON, rejects duplicate and unknown properties, and is bounded before
parsing. Provider credentials are leased to Workers and are never trace fields. Sampling parameters
are forwarded through the registered Provider Tool instead of being advisory metadata.

`parse_local_llama_cpp_single_agent_trace` additionally requires the exact registered function,
fixed SQLi scenario arguments, trusted host network receipt, successful fixed probe with
`vulnerable=true`, strict final finding JSON, complete usage, completed status, and cleanup. Refusal,
transport failure, malformed tool calls, alternate targets, missing usage, extra events, and final
answer drift remain failed Runs and cannot be normalized as a successful trace.

## Local conformance

On 2026-08-02, the pinned llama.cpp image and GGUF completed one local GPU conformance Run through
the real Docker Worker and host-observed egress receipts. The model made two calls, requested the
fixed Tool exactly once, consumed 1,374 prompt and 62 completion tokens, returned the strict finding,
and finished with zero active Secret Leases. The admitted trace digest was
`b6591dfd82fa36019e31730c91a360fb889d0c8036d0067f2d6f1bddd1c0763e`.

This conformance proves that the selected executable/model can satisfy the registration and trace
reader. Its dedicated Target/network lifecycle is not a P0-D1 measurement operation, and the local
ignored Run is not a governed benchmark source or a completed Result.

## Compatibility and rollback

Provider sampling fields are optional and are omitted for existing callers. Raw trace generation is
also opt-in; existing Tool Loop Runs keep their prior artifacts and behavior. The concrete benchmark
types are additive exports. Rollback removes the local registration/reader and opt-in trace support;
it does not reinterpret older Runs.

## Next runnable boundary

The next P0-E3B slice must run this exact registration for every P0-E3A coordinate inside a fresh
P0-D1 Target lifecycle, reciprocally bind Target operation/cleanup receipts to the raw trace, reopen
both sealed Runs, normalize one observation per coordinate, and emit a registry-governed completed
`BenchmarkResult`. Until then, candidate comparison and Supervisor activation remain ineligible.

## References

- [P0-E3A plan](P0-E3A-single-agent-baseline-plan.md)
- [ADR-0098](../adr/0098-bind-single-agent-identity-before-measurement.md)
- [ADR-0099](../adr/0099-select-local-llama-cpp-single-agent-baseline.md)
- [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Qwen3-4B-Instruct-2507 model card](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507)
