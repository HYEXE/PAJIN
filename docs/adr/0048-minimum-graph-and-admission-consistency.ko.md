> 언어: [English](0048-minimum-graph-and-admission-consistency.en.md) | [한국어](0048-minimum-graph-and-admission-consistency.md)

# ADR-0048: Minimum Graph와 Admission 일관성

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

현재 `TaskGraph`는 실행 의존성을, A5 `ObservationGraphSnapshot`은 제한된 후속 replanning을
표현한다. Architecture v2에는 여러 Specialist와 surface가 공유할 수 있으면서도 provenance,
중복, 모순, 동시성, stale decision을 결정론적으로 처리하는 canonical campaign state가
필요하다. Agent가 공유 dictionary나 free-form memory를 직접 수정하게 하면 last-write-wins,
권위 혼동과 재현 불가능한 계획이 생긴다.

## 결정

### 1. 최소 vocabulary

canonical node는 `Surface`, `Hypothesis`, `Action`, `Observation`, `Evidence`,
`CampaignFact` 여섯 가지다.

canonical edge는 다음 일곱 가지다.

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports/contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

새 node/edge kind는 schema version과 benchmark 근거를 가진 별도 변경으로만 추가한다.

### 2. 단일 write authority

Specialist와 Supervisor는 `ObservationProposal`, `SurfaceProposal`,
`CampaignFactProposal` 같은 typed proposal만 제출한다. Admission Queue의 단일
`GraphAdmissionAuthority`만 proposal을 검증하고 append-only Canonical Event Log에
admission/rejection event를 기록할 수 있다. Graph Projection과 Snapshot은 그 log에서만
파생한다.

### 3. proposal binding

각 proposal은 다음을 canonical digest에 포함한다.

- schema와 proposal kind/ID
- campaign, run, agent, task identity
- source request/action와 Capability/Permit identity
- node/edge payload
- evidence reference와 digest
- producer timestamp가 아닌 authority-assigned admission ordering에 필요한 metadata

untrusted producer timestamp는 provenance일 수 있으나 canonical ordering 권위가 아니다.

### 4. consistency

- 동일 proposal ID와 동일 digest 재제출은 멱등이며 새 semantic event를 만들지 않는다.
- 동일 ID와 다른 digest는 equivocation으로 거부하고 감사한다.
- 내용이 같은 별도 proposal은 provenance를 잃지 않으며 deterministic dedup relation으로
  표현할 수 있지만 기존 event를 삭제하지 않는다.
- 모순되는 Observation과 CampaignFact는 함께 보존하고 각 validation state와 lineage를
  유지한다. silent overwrite와 last-write-wins는 금지한다.
- 하나의 admission transaction은 이전 revision을 compare-and-set하고 event sequence,
  projection revision과 digest를 원자적으로 전진시킨다.
- 부분 기록 뒤 projection만 전진하거나 event 없이 revision이 전진할 수 없다.

### 5. immutable snapshot과 stale decision

Checkpoint Snapshot은 campaign ID, graph schema, revision, event-log head digest, canonical
node/edge projection digest와 생성 사유를 가진 immutable object다. Planner/Supervisor
decision은 exact snapshot ID, revision, digest에 결박한다. dispatch 직전 current revision이
다르면 revalidation 후 새 decision/Permit을 만들거나 거부한다.

### 6. 기존 자료의 migration

기존 `SurfaceObservation`, `AttackSurfaceSet`, A5 `ObservationGraphSnapshot`과 sealed Artifact는
trusted adapter가 proposal로 변환할 수 있다. 원본 digest와 legacy schema를 provenance로
보존하며, adapter를 통과했다는 이유만으로 자동 admission하지 않는다.

B2.9 facts/snapshot/handoff는 Event Log의 projection이다. 별도 free-form memory는 canonical
권위로 사용하지 않는다.

## 저장소 선택

첫 Event Store를 기존 RunStore에 둘지 별도 Graph 모듈로 둘지는 이 ADR에서 결정하지 않는다.
구현체는 위 ordering, idempotency, equivocation, contradiction, atomic revision과 snapshot
계약에 대한 공통 conformance test를 통과해야 한다. 저장소 선택은 spike 측정과 rollback
비용을 근거로 후속 결정한다.

## 필수 negative test

- duplicate exact retry와 same-ID/different-digest equivocation
- contradiction coexistence와 silent overwrite 거부
- foreign campaign/run/evidence lineage
- evidence digest 또는 registered producer 불일치
- concurrent admission race와 revision CAS 실패
- event/projection partial write recovery
- stale snapshot decision과 graph-change-before-dispatch

## 결과

에이전트 간 정보 공유가 검증된 공통 사실과 snapshot으로 가능해지고, 모든 변경을 event에서
재구성할 수 있다. 대신 single-writer admission 병목과 projection 운영 비용이 생긴다.
성능 최적화는 의미 일관성을 완화하지 않고 batching, partitioning, read model로 해결한다.

## 구현 상태

[GRAPH-002](../graph/GRAPH-002-single-admission-event-log.ko.md)는 process-local 단일 writer,
append-only hash chain, 등록 producer와 exact lineage gate, retry, equivocation,
materialization, dangling-edge 검사를 구현했다. Projection/revision/Snapshot, cross-process
CAS, contradiction transition, partial-write recovery, stale-decision test는 GRAPH-003/004
범위로 남아 있다.

## 관련 문서

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.ko.md)
- [ADR-0046: 공통 엔진과 Campaign Profile](0046-common-engine-and-campaign-profiles.ko.md)
- [ADR-0047: MissionEnvelope와 ActionPermit 대수](0047-mission-envelope-and-action-permit-algebra.ko.md)
