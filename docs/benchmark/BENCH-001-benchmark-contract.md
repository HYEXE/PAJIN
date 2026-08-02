# BENCH-001: Benchmark Contract and Result Schema

- Status: Implemented contract
- Date: 2026-07-26
- Implementation: `pajin.benchmark`

## Purpose

This versioned data contract compares PAJIN's deterministic baseline and a future adaptive
candidate under the same target, Campaign, ground truth, seeds, budgets, and run protocol. Later
contracts implement the Target lifecycle, registry-governed Harness, and the first P0-E1 measured
PAJIN baseline. Supervisor activation remains outside this contract.

## Artifacts

| Artifact | API version | Role |
| --- | --- | --- |
| `BenchmarkManifest` | `pajin.dev/benchmark-manifest/v1alpha1` | Public target/compiler/protocol/arm contract |
| `BenchmarkGroundTruth` | `pajin.dev/benchmark-ground-truth/v1alpha1` | Private seeded/holdout cases and matchers |
| `BenchmarkResult` | `pajin.dev/benchmark-result/v1alpha1` | Isolated Run set and aggregate metrics for one arm |
| `BenchmarkComparison` | `pajin.dev/benchmark-comparison/v1alpha1` | Metric deltas for identical baseline/candidate conditions |

Every Artifact rejects unknown fields, has a bounded canonical UTF-8 JSON encoding, and exposes a
domain-separated SHA-256 digest. The public Manifest carries only the exact Ground Truth digest,
not holdout contents.

## Run protocol

- Seeds are unique and sorted.
- Repetitions per seed and time, cost, Tool-call, and model-call limits are fixed.
- Target reset before each Run, per-Run isolation, and cleanup after each Run are mandatory.
- Valid Candidates absent from ground truth remain in an open-world adjudication queue.
- The baseline is always the first arm; an adaptive candidate is an optional second arm.
- The baseline cannot use an adaptive Supervisor, while the adaptive arm declares it explicitly.

## Required metrics

The 11 metric lines in Notion split Finding Recall and Finding Precision into separate values, for
12 ordered fields:

1. Attack Surface Recall
2. Finding Recall
3. Finding Precision
4. Unexpected Valid Finding Yield
5. Cross-surface Chain Completion Rate
6. Time to First Valid/Confirmed Finding
7. Cost per Confirmed Finding
8. Replay Success Rate
9. Policy Rejection/Violation Count
10. Human Intervention/Overturn Rate
11. Run-to-run Variance
12. Cleanup Success Rate

Ratios are 0-1, counts are non-negative integers, and time/cost/coefficient values are finite and
non-negative. A supplied numerator/denominator must exactly match its ratio. A completed Result
contains every metric and may use `not-applicable` only with an explicit reason when Finding
precision, time to first valid/confirmed Finding, cost per confirmed Finding, replay success, or
human intervention has no semantic denominator. Metrics whose denominator is guaranteed by a
completed protocol remain measured. This records an unavailable metric without inventing a
numeric value. Failed or cancelled Results may also use `not-applicable`. Cleanup success is
recalculated from exact per-Run outcomes.

## Comparison contract

A deterministic baseline and adaptive candidate can be compared only when all of these match:

- benchmark and Manifest digest;
- Target Factory, Campaign, and Ground Truth digests;
- protocol ID/version;
- seed/repetition coordinates; and
- completed status with all metrics measured (comparisons reject `not-applicable` inputs).

The comparison preserves source Result digests and `candidate - baseline` deltas. Improvement
direction, weighting, and Supervisor activation thresholds remain undecided until baseline
measurement.

## Required rejection behavior

- missing, duplicate, or reordered metrics, seeds, arms, or Runs;
- candidate-only manifests or arm/Supervisor semantic mismatch;
- wrong units, ranges, fractions, or cleanup aggregates;
- naive timestamps, non-normal evidence paths, or unknown fields; and
- composition of results from different manifests, protocols, or seeds.

## Implementation sequence

1. P0-C reset/isolation/cleanup harness and sealed Benchmark Run Artifact
2. P0-D Web/API, AI/RAG/MCP, hybrid, and holdout Target Factory
   ([P0-D4 Holdout authority](P0-D4-holdout-target-factory-authority.md))
   and Mutation Target Factory
   ([P0-D5 Mutation authority](P0-D5-mutation-target-factory-authority.md))
3. [P0-E1 deterministic PAJIN baseline measurement](P0-E1-deterministic-pajin-baseline-measurement.md)
4. [P0-E2A generic Scanner baseline plan](P0-E2A-generic-scanner-baseline-plan.md)
5. [P0-E2B OWASP ZAP Scanner baseline measurement](P0-E2B-zap-scanner-baseline-measurement.md)
6. [P0-E3A single-agent baseline plan](P0-E3A-single-agent-baseline-plan.md), followed by the
   [P0-E3B local runtime and raw-trace boundary](P0-E3B-local-single-agent-runtime.md) and fresh
   Target measurement
7. exact CAP-006 Capability benchmark mappings and sealed Oracle/Replay observations
