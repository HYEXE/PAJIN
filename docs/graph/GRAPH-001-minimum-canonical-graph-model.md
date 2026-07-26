# GRAPH-001: Minimum Canonical Graph Model

- 상태: Implemented contract
- 날짜: 2026-07-26
- 구현: `pajin.graph`

## 목적

여러 Specialist와 공격 표면이 공유할 최소 campaign knowledge vocabulary를 비실행 typed
contract로 고정한다. 이 조각은 Event Store, Admission Queue, Graph Projection, Snapshot,
Supervisor를 구현하지 않는다. Agent가 만든 값은 Proposal이며 canonical state가 아니다.

## Node

| Kind | 핵심 결박 |
| --- | --- |
| `Surface` | Campaign, Target, surface type, locator schema/digest, origin |
| `Hypothesis` | statement, expected observable, producer version/digest, origin, confidence |
| `Action` | request, Capability/Permit authority, registered Capability, Tool, target digest, 결과 시각 |
| `Observation` | typed summary/value digest, producer version/digest, taint origin, confidence, 시각 |
| `Evidence` | normalized relative reference, content/root digest, media type, data classification |
| `CampaignFact` | fact key/value digest, validation state, producer provenance, origin, 시각 |

Node ID는 Campaign과 전체 semantic payload의 domain-separated canonical digest다. provenance가
다르거나 모순되는 값은 다른 Node ID를 가지므로 overwrite하지 않고 함께 보존할 수 있다.
Target-derived text는 `origin=target-derived`로 표시해 이후 Supervisor input taint 처리가
가능하다.

## Edge

다음 여덟 relation만 허용하며 각 relation은 source/target kind를 고정한다.

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports Hypothesis
Observation contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

Edge는 Campaign, typed endpoint, relation, authority ID/digest에 결박된 canonical ID를 가진다.
반대 방향, 잘못된 endpoint kind, self-edge, cross-campaign endpoint와 ID 변조를 거부한다.

## Proposal

Agent와 Specialist가 제출할 수 있는 write intent는 세 가지뿐이다.

### `SurfaceProposal`

- exact campaign/run/agent/task/request/evidence lineage에 결박
- seed Surface는 edge 없이 제출 가능
- edge가 있으면 `Observation discovers Surface`만 허용

### `ObservationProposal`

- exact Action 전체, 한 Observation과 한 개 이상의 Evidence node
- 정확히 한 `Action produces Observation`
- 모든 Evidence에 대한 `Observation supported-by Evidence`
- Action의 request, Capability, Grant/Permit authority와 lineage의 exact 일치
- Proposal lineage의 evidence reference/digest와 Evidence node의 source-root exact 일치
- 추가 support/contradict/discover/enable edge도 항상 제안 Observation에 연결

### `CampaignFactProposal`

- canonical `validation_state`가 없는 `CampaignFactPayload`만 제출
- Agent는 fact를 제안할 수 있지만 `admitted`, `corroborated`, `contested`, `invalidated`
  상태를 부여할 수 없음
- GRAPH-002 Admission Authority가 accepted payload를 canonical `CampaignFact`로 materialize

모든 Proposal은 등록 producer ID/version/digest와 campaign, run, agent, task, request
ID/digest, CapabilityGrant ID/digest, Capability ID/version/digest, source root, evidence,
produced time에 결박한다. ActionPermit은 아직 일반 실행에 도입되지 않았으므로 optional
pair지만 ID와 digest 중 하나만 제출할 수 없다. Proposal digest는 ID를 포함한 전체 canonical
내용에 결박해 같은 ID/내용의 exact retry와 same-ID/different-content equivocation을
GRAPH-002가 구분할 수 있게 한다.

## A5 호환 경계

현재 `SurfaceObservation`, `AttackSurfaceSet`, `AttackHypothesis`,
`ObservationGraphSnapshot`은 변경하지 않는다. 이들은 sealed legacy Artifact이며, 후속
trusted adapter가 원본 schema/root/artifact digest를 보존한 Proposal로 변환한다. 변환
성공만으로 admission하지 않는다.

`TaskGraph`도 별도다. `TaskGraph`는 실행 의존성이고 Minimum Canonical Graph는 admitted
campaign knowledge와 provenance다.

## 검증된 거부 계약

- unknown field, naive timestamp, control character, unsafe evidence path
- canonical Node/Edge ID 변조
- relation endpoint kind/direction 불일치와 cross-campaign edge
- Proposal node/edge의 foreign campaign
- Evidence reference/content/source-root lineage 불일치
- 누락된 Action production 또는 Evidence support edge
- Agent가 CampaignFact validation state를 직접 제출
- partial ActionPermit ID/digest
- 모순 Observation의 overwrite 대신 별도 identity 보존

## 다음 단계

[GRAPH-002](GRAPH-002-single-admission-event-log.md)는 단일 Admission Authority와
append-only Event Log reference spike를 구현했다. GRAPH-003은 projection, atomic revision,
immutable Snapshot 계약을 추가한다. 영구 저장소 선택, cross-process CAS, partial-write
recovery는 adapter가 공통 conformance test를 통과할 때까지 미결정이다.
