> Languages: [English](BENCH-001-benchmark-contract.en.md) | [한국어](BENCH-001-benchmark-contract.ko.md)

# BENCH-001: Benchmark Contract and Result Schema

- Status: Implemented contract
- Date: 2026-07-26
- Implementation: `pajin.benchmark`

## Purpose

This versioned data contract compares PAJIN's deterministic baseline and a future adaptive
candidate under the same target, Campaign, ground truth, seeds, budgets, and run protocol. This
slice does not implement the benchmark harness, vulnerable Target Factory, measured baselines, or
Supervisor activation.

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
measures every metric; only failed or cancelled Results may use `not-applicable` with a reason.
Cleanup success is recalculated from exact per-Run outcomes.

## Comparison contract

A deterministic baseline and adaptive candidate can be compared only when all of these match:

- benchmark and Manifest digest;
- Target Factory, Campaign, and Ground Truth digests;
- protocol ID/version;
- seed/repetition coordinates; and
- completed status with all metrics.

The comparison preserves source Result digests and `candidate - baseline` deltas. Improvement
direction, weighting, and Supervisor activation thresholds remain undecided until baseline
measurement.

## Required rejection behavior

- missing, duplicate, or reordered metrics, seeds, arms, or Runs;
- candidate-only manifests or arm/Supervisor semantic mismatch;
- wrong units, ranges, fractions, or cleanup aggregates;
- naive timestamps, non-normal evidence paths, or unknown fields; and
- composition of results from different manifests, protocols, or seeds.

## Next steps

1. P0-C reset/isolation/cleanup harness and sealed Benchmark Run Artifact
2. P0-D Web/API, AI/RAG/MCP, hybrid, and holdout Target Factory
3. measurement of the current deterministic PAJIN baseline
4. GRAPH-001 Minimum Graph Model
