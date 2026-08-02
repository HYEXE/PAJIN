# ADR-0100: Bind the Single-Agent Run to a Governed Target Measurement

## Status

Accepted

## Context

P0-E3A defined a non-runnable generic single-agent plan. P0-E3B1 selected an exact local
llama.cpp/Qwen runtime and admitted a strict two-model-call/one-Tool raw trace, but its conformance
Run used a dedicated temporary Target. It therefore could not prove that the agent invocation
belonged to a fresh P0-D1 coordinate, survived the governed cleanup lifecycle, or contributed to a
completed benchmark Result.

The Provider call and the fixed Target Tool also require different reachable networks. Giving the
agent Worker direct membership in both networks would weaken the existing host-observed egress
boundary and make network provenance ambiguous.

## Decision

PAJIN will execute the registered P0-E3B1 Policy Tool Loop as the execution stage of the existing
recoverable P0-D1 Docker Target Factory.

The exact `DockerWorkerBackend` remains the trusted host receipt boundary. It may receive an
optional, action-name-to-external-network routing table. Provider actions use the default bridge;
the fixed SQLi action uses the current P0-D1 internal network. Each dispatch still creates a fresh
internal Worker network and attaches only the hardened egress proxy to the selected external
network. When no routing table is supplied, the v1 stable execution context and behavior are
unchanged. A non-empty table is bound as a v2 stable execution context.

The adapter requires the Tool Loop execution to report the exact planned Campaign and registration
digests before it constructs evidence. The Target execution evidence then binds the P0-E3A plan,
P0-E3B1 registration, model seed, normalized trace, raw trace hash and size, Tool Loop Run/root,
exact PAJIN Worker and proxy image IDs, and the post-invocation Target/network state. A
registry-governed measurement runner must reopen the
Harness, Target Run, execution evidence, raw trace, and every planned coordinate before sealing a
completed baseline Result. The Result is not eligible for candidate comparison or Supervisor
activation.

## Consequences

- The single-agent baseline now has the same fresh Target, durable recovery, signed registry,
  attestation, cleanup, and Result boundary as the deterministic and Scanner baselines.
- Model and Tool traffic remain mediated by fresh egress proxies; no Worker receives direct
  multi-network membership.
- Coordinate-seed substitution, cross-plan trace replay, raw-trace mutation, repeated Run roots,
  stale evidence, and partial cleanup fail closed.
- Exact local Worker and proxy image IDs become trusted provisioning inputs alongside the pinned
  llama.cpp image and GGUF checksum.
- The Result remains host-local. Remote Provider trust, cross-host fencing, hardware cost, and
  comparison or activation policy require later authorities.

## Compatibility and rollback

All schemas and exports are additive. Existing `DockerWorkerBackend` callers without routes retain
their previous stable execution context. Existing Docker provider evidence remains valid because
the new workload fields are optional and forbidden outside single-agent execution evidence.

Rollback removes the single-agent Docker adapter, measurement authority, and optional route map.
Previously sealed B2 measurements remain historical evidence and must not be reinterpreted as B1
conformance Runs or as comparison-eligible Results.
