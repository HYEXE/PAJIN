# ADR-0047: MissionEnvelope와 ActionPermit 대수

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

현재 `CampaignManifest`, `CapabilityGrant`, `ToolRequest`, `ReplayCapabilityGrant`는 강한
권한 경계를 제공한다. Architecture v2에서는 Agent나 Supervisor가 여러 등록 Capability
중 다음 행동을 제안하므로, 제안과 실제 실행 권위를 분리하고 모든 조합에서 권한이 단조
감쇠한다는 공통 계약이 필요하다.

## 결정

1. `MissionEnvelope`는 승인된 Campaign을 실행 가능한 상한으로 컴파일한 immutable,
   digest-bound authority object다. 최소한 campaign/profile/compiler identity, authorization
   window, targets/scope, allowed Capability constraints, max risk, budget, rate, autonomy와
   source Campaign digest를 가진다.
2. `ActionProposal`은 실행 요청이 아니라 의도다. proposer, exact snapshot ID/digest,
   Capability ID/version, target, normalized input, 예상 risk/cost와 근거 lineage를 가진다.
3. deterministic Compiler와 기존 Policy Gate만 `ActionPermit`을 발급할 수 있다. LLM,
   Specialist, Supervisor, Profile은 Permit을 자체 발급할 수 없다.
4. `ActionPermit`은 exact proposal, MissionEnvelope, registered Capability, target,
   normalized parameter digest, budget reservation, expiry, request와 snapshot에 결박된
   non-delegable single-use 권위다.
5. 권위 대수는 다음을 항상 만족해야 한다.

   ```text
   authority(ActionPermit)
     ⊆ authority(registered Capability)
     ∩ authority(MissionEnvelope)
     ⊆ authority(approved Campaign)
   ```

6. child envelope 또는 subtask 권위는 scope/tool/target set의 교집합, risk의 최솟값,
   remaining budget/rate/time의 상한으로 계산한다. 합집합, 누락값의 허용 해석, 새 credential
   또는 새 egress 추가는 금지한다.
7. Permit 소비는 저장소에서 원자적 compare-and-set으로 한 번만 성공한다. exact retry는
   이미 소비된 동일 결과를 조회할 수 있지만 다시 실행하지 않는다.
8. proposal 이후 graph revision이 바뀌면 compiler 또는 dispatcher가 exact snapshot
   binding을 재검증한다. stale decision은 자동 실행하지 않고 재컴파일 또는 거부한다.
9. 발급, 거부, 소비, 만료, 취소는 canonical digest와 사유를 audit event에 기록한다.

## 기존 계약과의 관계

- `CapabilityGrant`는 MissionEnvelope 안에서 Agent가 보유한 감쇠 권위로 계속 사용한다.
- 기존 `ToolRequest`는 향후 `ActionProposal`을 컴파일한 실행 payload가 되며 당장 wire
  format을 변경하지 않는다.
- `ReplayCapabilityGrant`와 single-use replay ticket은 더 좁은 기존 Permit 사례로 유지한다.
- 새 algebra가 구현되기 전에는 기존 Policy/Tool Gateway가 계속 유일한 실행 경계다.

## 거부 조건

unknown 또는 비활성 Capability, version/digest 불일치, Scope 밖 target, risk/budget/rate
초과, expired authorization, stale snapshot, 다른 campaign/run의 lineage, 재사용된 Permit,
Permit과 ToolRequest digest 불일치는 모두 fail closed 한다.

## 결과

Agent의 탐색 자유도는 등록된 권위 공간 안에서 커질 수 있지만 실제 실행 권위는 더 명시적이고
좁아진다. 저장소의 원자적 소비와 snapshot 재검증 비용이 추가된다. 구체 wire schema와
Capability Registry 저장 방식은 후속 수직 조각에서 결정하되 이 대수를 완화할 수 없다.

## 관련 문서

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0046: 공통 엔진과 Campaign Profile](0046-common-engine-and-campaign-profiles.md)
- [ADR-0048: Minimum Graph와 Admission 일관성](0048-minimum-graph-and-admission-consistency.md)
