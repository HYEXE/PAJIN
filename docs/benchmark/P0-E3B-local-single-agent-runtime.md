# P0-E3B Local Single-Agent Runtime and Raw Trace

## Status

The concrete runtime, raw-trace, and governed measurement vertical slices are implemented. The
runtime selects one local OpenAI-compatible Provider, pins its executable and model artifacts,
extends the existing governed `PolicyToolLoopRunner` with exact sampling and secret-free raw JSONL
evidence, and admits only a successful two-model-call/one-Tool trace. The measurement adapter runs
that exact registration inside every fresh P0-D1 Target lifecycle, binds its Tool Loop Run and raw
trace to the Target execution receipt, and seals a completed baseline `BenchmarkResult`.

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
answer drift remain failed Runs and cannot be normalized as a successful trace. The normalization
also exposes the exact model seed, which must equal the P0-E3A Target coordinate seed.

The Campaign must admit three Worker dispatches (first Provider call, fixed Tool call, final Provider
call), two model calls, and enough model tokens for the configured worst-case reservation before
each Provider dispatch. The registered conformance Campaign therefore uses a 32,768-token ceiling;
an undersized budget fails closed before the final model call instead of admitting a partial trace.

## Governed measurement

`DockerSingleAgentTargetFactoryAdapter` reuses the P0-D1 fenced reset, isolation, execution,
cleanup, recovery, and attestation lifecycle. The local Provider action reaches the host llama.cpp
service through the default Docker bridge. The fixed SQLi Tool action selects the active P0-D1
internal network through an action-specific `DockerWorkerBackend` route. Both actions still receive
fresh per-dispatch internal Worker networks and the same hardened, host-observed egress proxy
receipts; the model Worker never joins the Target network directly.

The execution receipt binds all of the following facts in `DockerBenchmarkProviderEvidence`:

- the P0-E3A plan, Campaign, and P0-E3B1 registration after exact equality with the sealed Tool
  Loop execution;
- the normalized trace digest, raw trace SHA-256, and byte length;
- the Tool Loop Run ID and sealed root digest;
- the exact PAJIN Worker and egress-proxy image IDs; and
- the still-healthy Target container and exact internal network after agent cleanup.

`SingleAgentBaselineMeasurementRunner` reopens the signed registry-governed Harness, sealed Target
Run, execution evidence, Provider trace, and every coordinate before it emits a completed Result.
The measurement Run copies each exact raw trace under
`evidence/raw-model-tool-traces/{seed}-{repetition}.jsonl`, binds the normalized observations and
Result, and reopens all original sources on read. Missing, repeated, cross-plan, cross-coordinate,
mutated, or partially cleaned sources fail closed. Candidate comparison and Supervisor activation
remain explicitly ineligible; this slice measures only the baseline arm.

## Local conformance

On 2026-08-02, the pinned llama.cpp image and GGUF completed a full B2 local GPU measurement through
the real Docker Worker, host-observed egress receipts, fresh P0-D1 Target lifecycle, measurement
registry, and final authority reader. The model made two calls, requested the fixed Tool exactly
once, consumed 1,371 prompt and 62 completion tokens, returned the strict finding, and finished with
zero active Secret Leases. The normalized trace digest was
`317b362d506f7e46502245e199d53398027fd3bbc7dc1855ec12d7b4eb50591a`; the copied raw trace SHA-256
was `7cb390effaccf293b4b1f44a1611458a8bcf285bc052ff85c9473c74dad67de1`.

The governed Result was
`benchmark-result:298db8b9e8176e1ed91cb9758e3e457087d33c61f5b65e2c1f6f2ac8a2bc878d`
under measurement authority
`single-agent-baseline-measurement:981fac2cf002ace8b4e14d63e26869d90510ebb9510949edbe416370b5c44e17`.
It measured attack-surface recall, finding recall, and finding precision as `1.0`, cleanup success as
`1.0`, and preserved unavailable semantic denominators as explicit `not-applicable` metrics.

## Compatibility and rollback

Provider sampling fields are optional and are omitted for existing callers. Raw trace generation is
also opt-in; existing Tool Loop Runs keep their prior artifacts and behavior. Action-specific Docker
network routing is opt-in, preserves the v1 stable execution context when absent, and emits a v2
context only when routes exist. `modelSeed` is additive in the v1alpha1 normalization: current raw
trace parsing always emits it, B2 requires it, and a pre-B2 normalization without the field retains
its original digest. The provider evidence fields and concrete benchmark types are additive.
Rollback removes the B2 adapter/measurement types and route configuration; it does not
reinterpret older Runs or downgrade a B2 authority to the B1 conformance trace.

## Remaining boundary

The completed Result is host-local and depends on trusted provisioning of the exact Docker image
IDs plus a locally available pinned llama.cpp/GGUF service. It does not establish remote Provider
trust, cross-host fencing, hardware-amortized cost, statistical comparison, or Supervisor activation.

## References

- [P0-E3A plan](P0-E3A-single-agent-baseline-plan.md)
- [ADR-0098](../adr/0098-bind-single-agent-identity-before-measurement.md)
- [ADR-0099](../adr/0099-select-local-llama-cpp-single-agent-baseline.md)
- [ADR-0100](../adr/0100-bind-single-agent-run-to-governed-target-measurement.md)
- [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Qwen3-4B-Instruct-2507 model card](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507)
