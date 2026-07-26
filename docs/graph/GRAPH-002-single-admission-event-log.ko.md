> 언어: [English](GRAPH-002-single-admission-event-log.en.md) | [한국어](GRAPH-002-single-admission-event-log.ko.md)

# GRAPH-002: 단일 Admission Authority와 Append-only Event Log

- 상태: Reference spike 구현 완료, 로컬 WIP
- 날짜: 2026-07-26
- 구현: `pajin.graph.admission`

## 결과

GRAPH-002는 검증된 GRAPH-001 Proposal을 append-only admission 또는 rejection event로
변환한다. Event Log writer capability는 `GraphAdmissionAuthority`만 받는다. Producer,
Specialist, Agent, Supervisor는 권위 없는 Proposal 제출자로 남으며 canonical CampaignFact
validation state를 부여하거나 canonical event를 직접 append할 수 없다.

이 spike는 저장소 중립 `GraphEventLog` 계약과 `InMemoryGraphEventLog` reference 구현을
제공한다. 영구 Graph 저장소는 아직 선택하지 않는다.

## Admission pipeline

```text
typed Proposal
  -> authority 경계에서 재파싱
  -> proposal ID/digest retry 검사
  -> 등록 producer/version/digest/kind 검사
  -> trusted lineage exact 검사
  -> canonical node materialize
  -> 이번 attempt 또는 기존 admitted node에 대한 edge resolve
  -> authority-owned append
```

Event ordering 시각은 authority-owned clock이 부여한다. Producer 시각은 provenance일 뿐
ordering 권위가 아니다. 모든 event는 proposal/lineage digest, Campaign/Run/Agent/Task/request,
CapabilityGrant와 Capability, optional ActionPermit, source-root와 evidence, producer 계약,
decision/reason, admitted canonical material을 기록한다.

## 일관성 계약

### 단일 writer

Reference Event Log는 opaque writer capability 하나만 발급한다. 두 번째 writer claim,
발급되지 않은 writer object, claimed writer와 authority가 다른 event는 fail-closed로
거부한다. 이는 spike의 process-local single-writer 증명이며, 영구 배포에는 DB 또는
service-level leadership fencing이 추가로 필요하다.

### Append-only hash chain

Event는 단조 증가 sequence, previous-event digest, authority-assigned timestamp, canonical
event digest, content-derived event ID를 가진다. Log는 stale sequence/predecessor, 중복 semantic
attempt, 중복 event identity, validation 이후 object 변조를 거부한다. Read API는 deep copy만
반환하며 update/delete API를 제공하지 않는다.

### Retry와 equivocation

- 같은 proposal ID + 같은 digest는 원 event를 `idempotent=true`로 반환하고 append하지 않는다.
- 같은 proposal ID + 다른 digest는 `proposal-equivocation` rejection event 하나를 append한다.
- 그 equivocation의 exact retry도 기존 rejection event를 반환한다.

첫 기록 digest는 첫 attempt가 rejected여도 proposal ID를 예약한다. 수정한 내용은 새
proposal ID를 사용해야 한다.

### Trusted producer와 lineage

`GraphProducerRegistry`는 application code에서 producer ID, version, digest, 허용 Proposal
kind를 고정한다. Observation과 CampaignFact payload의 producer 필드는 outer Proposal
producer 계약과 exact match해야 한다.

`TrustedGraphLineageRegistry`는 sealed-Run adapter가 이미 인증한 source를 위한 reference
verifier다. Campaign, Run, Agent, Task, request ID/digest, CapabilityGrant ID/digest,
Capability ID/version/digest, optional ActionPermit ID/digest, source-root digest, evidence
reference/digest, producer time을 exact match한다. 같은 source identity에 다른 lineage를
등록하면 trusted-source equivocation으로 거부한다.

### Materialization과 edge resolution

- `SurfaceProposal`은 Surface와 허용된 discovery edge를 admission한다.
- `HypothesisProposal`은 source가 resolve된 exact motivation/enablement edge와 등록
  producer의 Hypothesis를 admission한다.
- `ObservationProposal`은 전체 Action, Observation, Evidence node와 typed edge를 admission한다.
  Action은 request, Capability, execution-authority lineage와 정확히 일치해야 한다.
- `CampaignFactProposal`은 `validation_state=admitted`인 canonical CampaignFact로
  materialize한다. Producer는 이 상태를 제출할 수 없다.

모든 edge endpoint는 같은 attempt에서 admission하는 node 또는 Event Log에 이미 admission된
exact node로 resolve되어야 한다. Dangling edge는 거부하고 event로 감사한다.

## 검증된 negative 계약

GRAPH-001/002 test는 다음을 검증한다.

- 변조된 Proposal 재검증과 canonical identity tampering
- unknown producer, version/digest mismatch, kind denial, payload-producer mismatch
- foreign Campaign, 미등록 또는 equivocated trusted lineage
- 불완전한 Action/request/Capability/authority binding
- dangling edge
- exact retry와 same-ID/different-digest equivocation
- rejected event material 주입과 event digest 변조
- stale sequence/predecessor append
- invalid 또는 두 번째 writer capability
- Event Log read copy의 caller-side 변조

## 의도적으로 남긴 경계

이 spike는 다음을 구현하지 않는다.

- 영구 RunStore 또는 별도 Graph Store adapter
- cross-process leader election, database transaction/CAS, crash recovery
- durable Graph Projection/Snapshot 저장소, snapshot-bound decision
- semantic duplicate folding, contradiction state transition, stale-decision 처리
- sealed Run, Scope, Capability Registry, legacy A5 artifact의 live adapter
- Supervisor scheduling과 B2.9 fact/snapshot/handoff projection

RunStore는 이미 private append, lock, hash chain, sealed integrity를 증명했지만 한 Run에
결박되어 있다. 별도 Graph Store는 Campaign-wide revision과 projection transaction을 더
자연스럽게 소유할 수 있다. `GraphEventLog` protocol은 durable adapter 측정과 conformance
test가 나오기 전까지 두 선택지를 열어 둔다.

## 다음 단계

[GRAPH-003](GRAPH-003-projection-revision-immutable-snapshot.ko.md)은 전체 admission/rejection
Event Log에서 재구성하는 in-memory reference Projection, revision/head CAS, immutable
Snapshot chain을 구현했다.
[GRAPH-004](GRAPH-004-consistency-recovery-stale-decision.ko.md)는 duplicate·contradiction
semantics, concurrent admission/projection, 복구 가능한 projection lag, stale-decision
preflight를 검증한다. Durable transaction과 crash 경계는 아직 남아 있다.
