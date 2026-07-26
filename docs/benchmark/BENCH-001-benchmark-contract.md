# BENCH-001: Benchmark Contract와 Result Schema

- 상태: Implemented contract
- 날짜: 2026-07-26
- 구현: `pajin.benchmark`

## 목적

PAJIN의 결정론적 baseline과 향후 adaptive candidate를 같은 target, Campaign, ground truth,
seed, budget과 run protocol에서 비교하기 위한 versioned data contract다. 이 단계는 benchmark
harness, 취약 Target Factory, 실제 기준값 또는 Supervisor activation을 구현하지 않는다.

## Artifact

| Artifact | API version | 역할 |
| --- | --- | --- |
| `BenchmarkManifest` | `pajin.dev/benchmark-manifest/v1alpha1` | 공개 target/compiler/protocol/arm 계약 |
| `BenchmarkGroundTruth` | `pajin.dev/benchmark-ground-truth/v1alpha1` | seeded/holdout case와 matcher를 가진 비공개 정답 |
| `BenchmarkResult` | `pajin.dev/benchmark-result/v1alpha1` | 한 arm의 격리 Run 집합과 aggregate metric |
| `BenchmarkComparison` | `pajin.dev/benchmark-comparison/v1alpha1` | 동일 조건의 baseline-candidate metric delta |

모든 Artifact는 unknown field를 거부하고 canonical UTF-8 JSON 크기를 제한하며
domain-separated SHA-256 digest를 제공한다. public Manifest에는 Ground Truth 내용 대신
exact digest만 포함해 holdout을 노출하지 않는다.

## Run protocol

- seed는 중복 없이 정렬한다.
- seed별 repetition, timeout, cost, Tool call, model call 상한을 고정한다.
- 매 Run 전 target reset, Run별 isolation, 매 Run 뒤 cleanup을 반드시 요구한다.
- ground truth에 없는 valid Candidate를 버리지 않고 open-world adjudication 대상으로 보존한다.
- baseline arm이 항상 첫 번째이며 adaptive candidate는 선택적인 두 번째 arm이다.
- baseline은 adaptive supervisor를 사용할 수 없고 adaptive arm은 이를 명시해야 한다.

## 필수 metric

Notion의 11개 metric 행 중 Finding Recall/Precision을 별도 수치로 분리해 총 12개 field를
정해진 순서로 기록한다.

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

ratio는 0~1, count는 음이 아닌 정수, time/cost/coefficient는 음이 아닌 유한값이다.
numerator/denominator가 있으면 ratio와 정확히 일치해야 한다. 완료 Result는 모든 metric을
측정해야 하며 실패·취소 Result만 reason과 함께 `not-applicable`을 사용할 수 있다. Cleanup
metric은 각 Run의 cleanup outcome에서 다시 계산해 exact 결박한다.

## 비교 계약

baseline과 adaptive candidate 비교는 다음 값이 모두 같을 때만 허용한다.

- benchmark와 Manifest digest
- Target Factory, Campaign, Ground Truth digest
- protocol ID/version
- seed/repetition 좌표
- 완료 상태와 전체 metric

비교는 source Result digest와 `candidate - baseline` delta를 보존한다. metric 개선 방향,
가중치와 Supervisor activation threshold는 기준값 측정 전에는 정하지 않는다.

## 필수 거부 동작

- 누락·중복·순서가 바뀐 metric, seed, arm, Run
- candidate-only manifest 또는 arm/supervisor 의미 불일치
- 잘못된 unit, 범위, 분수와 cleanup aggregate
- naive timestamp, 비정규 evidence path, unknown field
- 다른 Manifest/protocol/seed의 결과 조합

## 다음 단계

1. P0-C reset/isolation/cleanup harness와 sealed Benchmark Run Artifact
2. P0-D Web/API, AI/RAG/MCP, hybrid, holdout Target Factory
3. 현재 결정론적 PAJIN baseline 측정
4. GRAPH-001 Minimum Graph Model
