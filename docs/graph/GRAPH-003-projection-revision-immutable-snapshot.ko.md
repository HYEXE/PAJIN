> 언어: [English](GRAPH-003-projection-revision-immutable-snapshot.en.md) | [한국어](GRAPH-003-projection-revision-immutable-snapshot.ko.md)

# GRAPH-003: Projection·Revision·Immutable Snapshot

- 상태: Reference spike 구현 완료, 로컬 commit `c8268e3`, CI 대기
- 날짜: 2026-07-26
- 구현: `pajin.graph.projection`
- 테스트: `tests/test_graph_projection.py`

## 결과

GRAPH-003은 GRAPH-002 Event Log에서만 재구성되는 deterministic Canonical Graph read model을
추가한다. `GraphProjection`은 Campaign, graph schema version, revision, Event Log head
digest, canonical node/edge digest와 content-derived projection ID/digest로 Event Log의 정확한
prefix 하나를 식별한다.

`GraphSnapshot`은 전체 projection을 append-only content-addressed checkpoint chain으로
봉인한다. 의사결정에서 사용하는 `GraphSnapshotRef`는 저장된 snapshot ID/digest, Campaign,
schema, revision, Event Log head, projection digest와 exact match해야 한다.

## Projection 계약

```text
authority-owned Event Log prefix
  -> 모든 admission/rejection event 재검증
  -> Campaign, sequence, predecessor, event digest 검증
  -> admitted node와 edge만 materialize
  -> canonical identity 유일성과 edge endpoint closure 검증
  -> node/edge 및 전체 projection digest 계산
  -> revision + Event Log head compare-and-set
```

- Revision은 rejection을 포함한 정확한 prefix의 전체 event 개수다. Rejection은 감사
  연속성을 위해 revision과 head를 전진시키지만 node/edge material은 변경할 수 없다.
- 같은 canonical node/edge material은 read model에서 하나로 접는다. 원본 event는 Event
  Log에 모두 남는다. 같은 canonical identity가 다른 material을 가리키면 fail closed한다.
- Projection material은 canonical ID 순으로 정렬되며 모든 edge endpoint는 그 exact
  projection 안에서 resolve되어야 한다.
- Event의 `campaignId`는 Admission Authority가 소유한다. 신뢰하지 않는 foreign Proposal
  Campaign은 `proposalCampaignId`에 별도로 기록하므로 rejection도 authority Campaign
  log에서 재생할 수 있다.
- 빈 genesis는 head가 없는 revision `0`이다. 양수 revision은 항상 exact head를 가진다.

## Atomic revision publish

`InMemoryGraphProjectionStore`는 저장소 중립 `GraphProjectionStore` protocol의 reference
구현이다. Event Log의 captured full prefix를 받아 다음 조건에서만 candidate를 publish한다.

1. caller의 `expected_revision`과 `expected_head_digest`가 현재 상태와 일치한다.
2. candidate가 revision을 rollback하지 않는다.
3. candidate의 current-revision prefix가 현재 projection을 정확히 재구성한다.

Projection 객체, revision, head, digest는 한 lock 안에서 함께 교체된다. Stale caller,
rollback, 분기된 Event Log prefix는 상태를 바꾸지 않고 거부된다. 정확한 현재 prefix의
재생은 멱등이다.

GRAPH-002 Event Log와 이 reference projection store는 아직 분리된 in-memory component다.
따라서 `GraphProjectionCoordinator.refresh()` 전까지 Event Log가 projection보다 앞설 수
있지만, projection은 검증된 prefix에 없는 event를 publish할 수 없다. Cross-store durable
transaction과 crash recovery는 GRAPH-004 및 durable adapter 범위로 남긴다.

## Immutable Snapshot 계약

`GraphSnapshotAuthority`만 Snapshot writer가 된다. 각 snapshot은 다음을 결박한다.

- Campaign과 graph schema version
- projection revision과 Event Log head digest
- projection ID/digest와 node/edge projection digest
- 전체 canonical projection
- `checkpoint`, `handoff`, `replan`, `recovery` creation reason
- creator ID/digest와 authority-owned UTC creation time
- previous Snapshot digest

`InMemoryGraphSnapshotStore`는 opaque single-writer capability, append-only predecessor 검증,
exact append 멱등성, content-derived snapshot identity, defensive read copy, exact reference
resolve를 제공한다. 반환된 nested model을 caller가 변경해도 stored authority는 변하지
않으며 append/resolve 경계에서 모든 값을 다시 검증한다.

## 검증된 negative 계약

GRAPH-003 테스트는 다음을 검증한다.

- deterministic replay, genesis, exact-prefix 멱등성과 canonical duplicate folding
- material 변경 없는 rejected-event revision/head 전진
- partial publish 없는 stale CAS, rollback, divergent-prefix 거부
- 변조·불연속 event와 foreign-Proposal Campaign event
- projection identity 변조와 dangling edge
- Snapshot과 projection의 exact binding 및 predecessor chain
- invalid/second writer capability와 stale predecessor
- 변조된 Snapshot reference
- 반환된 Snapshot material의 caller-side 변조

GRAPH-001/002/003 focused suite는 현재 로컬에서 36개 테스트를 통과한다.

## 의도적으로 남긴 경계와 다음 단계

GRAPH-003은 durable database/Event Store를 선택하지 않으며 cross-process fencing 또는 Event
Log와 projection store를 아우르는 atomic transaction을 주장하지 않는다.

[GRAPH-004](GRAPH-004-consistency-recovery-stale-decision.ko.md)는 concurrent
admission/projection CAS, duplicate·contradiction semantics, 복구 가능한 projection lag,
Snapshot decision staleness, graph-change-before-dispatch를 검증한다.
[GRAPH-005](GRAPH-005-durable-sqlite-graph-store.ko.md)는 별도 single-Campaign SQLite
store에 이 계약과 host-local CAS·reopen recovery를 적용했다. multi-host leadership과
atomic ActionPermit 발급·dispatch는 남아 있다.
