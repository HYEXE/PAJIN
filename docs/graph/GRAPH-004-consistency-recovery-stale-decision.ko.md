> 언어: [English](GRAPH-004-consistency-recovery-stale-decision.en.md) | [한국어](GRAPH-004-consistency-recovery-stale-decision.ko.md)

# GRAPH-004: Consistency·Recovery·Stale Decision

- 상태: Reference conformance slice 구현 및 로컬 검증 완료, Linux CI 확인 대기
- 날짜: 2026-07-26
- 구현: `pajin.graph.consistency`, `pajin.graph.admission`
- 테스트: `tests/test_graph_consistency.py`

## 결과

GRAPH-004는 GRAPH-001부터 GRAPH-003까지 만든 process-local consistency 경계를 실제로
검증한다. Hypothesis admission 경로, deterministic duplicate/contradiction 분석, bounded
projection reconciliation, exact Snapshot-bound decision preflight를 추가한다.

이 조각은 durable crash recovery나 cross-process dispatch transaction을 구현했다고 주장하지
않는다. 후속 durable Graph Store adapter가 보존해야 할 reference semantics와 negative
test를 제공한다.

## 실제 도달 가능한 contradiction vocabulary

최소 vocabulary에는 이미 `Hypothesis`, `supports`, `contradicts`가 있었지만 최초 세 Proposal
형식으로는 Hypothesis를 admission할 수 없었다. `HypothesisProposal`이 이 끊긴 경로를
닫는다.

```text
admitted Surface 또는 Observation
  -> Surface motivates Hypothesis
     또는 Observation enables Hypothesis
  -> 등록 Hypothesis producer와 exact lineage
  -> 단일 Admission Authority
  -> Hypothesis admission event
```

Hypothesis producer ID/version/digest는 outer Proposal과 일치해야 한다. 모든 edge는 exact
Hypothesis를 target으로 하며 같은 Campaign에서 admission된 node로 resolve돼야 한다.
Dangling motivation은 거부된다.

`ObservationProposal`은 Hypothesis를 support 또는 contradict할 수 있지만 한 Observation이
같은 Hypothesis에 두 입장을 동시에 주장할 수 없다. 서로 다른 Observation 간 의견 충돌은
허용한다.

## Duplicate와 contradiction semantics

`GraphConsistencyAnalyzer`는 exact Event Log를 다시 검증하고 제공된 projection을 정확히
재구성할 때만 분석한다.

- 같은 Proposal ID와 digest는 Event 하나만 남기는 멱등 retry다.
- 같은 Proposal ID와 다른 digest의 동시 요청은 한 recorded winner와 한
  `proposal-equivocation` rejection으로 직렬화되며 material을 overwrite하지 않는다.
- 다른 Proposal ID가 같은 canonical node를 제출하면 admission Event 둘을 모두 보존한다.
  Projection material은 canonical identity 하나로 접고
  `duplicateNodeOccurrenceCount`/`duplicateEdgeOccurrenceCount`가 보존된 occurrence를
  표시한다.
- Hypothesis state는 부여하거나 mutate하지 않고 relation에서 파생한다.

```text
입장 없음                    -> open
support만 존재               -> supported
contradiction만 존재         -> contradicted
서로 다른 support + conflict -> contested
```

Supporting/contradicting Observation ID는 content-addressed `GraphConsistencyView`에 정렬해
남긴다. Contested 상태도 이전 Observation, Edge, Event를 삭제하지 않는다.

## Concurrent admission과 projection

Reference Admission Authority는 single-writer lock 안에서 Proposal 제출을 직렬화한다.
Conformance test는 exact retry와 same-ID/different-content 요청을 서로 다른 thread에서
동시에 시작하고, lost update 없는 연속 Event Log hash chain을 요구한다.

Projection publish는 계속 revision/head CAS다. Concurrent reconciler가 경합하면 하나가
publish하고 다른 하나는 새 revision에서 재시도한다. Bounded retry를 모두 소진하면 fail
closed한다.

## Partial-write reconciliation

`GraphProjectionReconciler`는 Event append는 성공했지만 projection publish가 실행되지
않았거나 CAS race에서 진 process-local 복구 가능 상태를 처리한다.

1. 현재 projection과 authority Event Log를 capture한다.
2. Event Log보다 앞선 projection을 거부한다.
3. 현재 revision까지 Event Log prefix를 재구성해 exact projection digest를 요구한다.
4. 뒤처졌다면 captured full prefix를 revision/head CAS로 publish한다.
5. CAS conflict를 bounded 횟수만큼 재시도한다.

정확히 최신이면 `in-sync`, 복구했으면 replay Event 수와 함께 `recovered`를 반환한다.
Divergent projection은 조용히 교체하지 않는다.

이는 reference replay recovery이지 durable two-store crash atomicity가 아니다.
[GRAPH-005](GRAPH-005-durable-sqlite-graph-store.ko.md)는 별도 single-Campaign SQLite store에
cross-process host-local CAS와 reopen persistence를 적용했다. multi-host leadership,
process-kill fsync fault injection, 검증된 backup restore는 남아 있다.

## Snapshot-bound stale decision preflight

`GraphDecision`은 다음을 결박한 non-executable content-addressed record다.

- Campaign과 decision kind
- opaque decision payload digest
- exact `GraphSnapshotRef`
- actor ID/digest
- UTC creation time

`GraphDecisionGuard.validate_for_dispatch()`는 다음을 수행한다.

1. Decision identity를 재검증한다.
2. immutable Snapshot을 exact resolve한다.
3. Event Log에서 latest projection을 직접 재구성한다.
4. published projection이 recovery가 필요한 상태면 거부한다.
5. Snapshot revision/head/projection identity가 latest가 아니면 거부한다.

성공 시 audit-only check record인 `GraphDecisionPreflight`를 반환한다. 이 값은
ActionPermit이 아니며 실행 권위를 부여하지 않는다.

Reference guard는 아직 projection되지 않은 Event를 포함해 check 전에 이미 존재한 graph
change를 잡는다. Preflight 뒤 외부 Worker dispatch 전의 race는 닫지 못한다. Durable adapter와
deterministic ActionPermit compiler가 dispatch transaction 안에서 비교하거나 최종 authority
경계에서 다시 검사해야 한다.

## 검증된 negative 계약

통합 focused suite는 현재 로컬에서 46개 테스트를 통과한다.

- unresolved Hypothesis motivation과 Hypothesis producer mismatch
- 한 Observation의 동시 support/contradict 주장
- canonical projection folding과 duplicate provenance 보존
- deterministic `open -> supported -> contested` state
- concurrent exact retry와 same-ID/different-digest admission
- CAS retry를 포함한 concurrent projection reconciliation
- lag recovery, idempotent reconciliation, divergent-prefix 거부
- Event Log가 projection보다 앞선 상태의 stale Decision
- projection catch-up 뒤에도 stale한 Decision
- Decision identity 변조

## 남은 경계

GRAPH-005가 첫 durable Event/Projection/Snapshot adapter와 host-local CAS 경계를 닫았다.
다음은 남아 있다.

- multi-host leader fencing·lease expiry·PostgreSQL/HA storage
- fsync 경계의 process-kill/fault-injection test
- atomic preflight + ActionPermit 발급/소비
- semantic CampaignFact corroboration/invalidation workflow
- retention, compaction, backup, restore, 외부 integrity anchoring
- sealed Run/Scope/Capability live adapter, B2.9 Handoff projection, Supervisor 실행

Runtime dispatch 통합은 별도 trust-boundary 변경으로 남는다. 이전 preflight를 신뢰하지 말고
ActionPermit 발급·소비 안에서 latest durable revision을 다시 검사해야 한다.
