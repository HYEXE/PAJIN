> 언어: [English](0051-versioned-capability-definition-and-tool-binding.en.md) | [한국어](0051-versioned-capability-definition-and-tool-binding.ko.md)

# ADR-0051: Versioned Capability Definition과 Exact Tool Binding

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

기존 PAJIN은 `ToolSpec`, `ToolRegistry`, `CapabilityGrant`와 Replay 전용 compilation 계약을
가지지만, Architecture v2의 일반 공격 실행이 참조할 수 있는 독립적인
**Versioned Capability Definition**은 없었다. GRAPH-006의 `RegisteredActionCapability`은
Permit compiler가 사용할 최소 실행 결박을 제공했지만 domain, maturity, surface, threat,
parameter schema, side effect, evidence, approval, cost와 cleanup metadata 전체를 소유하지
않는다.

`CapabilityGrant`에 이 metadata를 추가하면 감쇠·호출 예산 권위와 정적 실행 의미가 섞인다.
반대로 `ToolSpec`만 Capability로 취급하면 하나의 Tool이 제공하는 고수준 의미와 review
상태를 표현할 수 없다.

## 결정

1. `pajin.capabilities.CapabilityDefinition`을 정적 실행 의미의 canonical authority로 둔다.
2. definition은 ID/version/domain/maturity, 지원 surface와 threat, precondition,
   parameter-schema digest, risk/side-effect, evidence, network/approval/cost/cleanup/parallel
   metadata와 exact Tool binding을 가진다.
3. 모든 collection은 sorted unique이고 전체 material은 bounded canonical JSON과
   domain-separated SHA-256 digest에 결박한다.
4. Registry는 `(capability_id, capability_version)` exact key만 resolve한다. 암묵적
   `latest` lookup이나 version fallback은 제공하지 않는다.
5. 기존 `ToolSpec` adapter는 Tool ID/version과 normalized full ToolSpec digest를 결박한다.
   surface, threat, side effect, approval와 cleanup metadata는 이름이나 category에서 추론하지
   않고 명시적 `ToolCapabilityRegistration`으로만 받는다.
6. GRAPH-006 `RegisteredActionCapability`에는 별도 `definitionDigest`를 추가한다.
   `capabilityDigest`는 Graph 등록 레코드 자체를, `definitionDigest`는 CAP-001 전체 정의를
   결박한다.
7. `CapabilityGrant`는 runtime subject·target·call-budget 감쇠 권위로 그대로 유지한다.
   CAP-001은 Tool Gateway 실행을 우회하거나 새 Capability를 자동 활성화하지 않는다.

## 호환성과 migration

- 기존 `Tool`, `ToolRegistry`, `CapabilityGrant`, CLI와 Artifact 형식은 변경하지 않는다.
- 기존 Tool은 명시적 registration을 제공한 경우에만 CAP-001 Registry에 나타난다.
- GRAPH-006은 아직 외부 stable API가 아니다. nested authority 계약을 `v1alpha2`로 올리고
  새 `definitionDigest`를 필수로 만들어 정의가 없는 실행권위를 fail closed한다.
- CAP-001 이전 로컬 `v1alpha1` Permit row에 definition을 추정·backfill하지 않는다. 그런
  개발용 ledger는 보존 archive 후 새 Campaign store에서 다시 발급해야 한다.
- durable Capability Registry, signing, activation/rotation과 code-backed compiler/executor
  authority는 CAP-002/CAP-004 후속 경계다.

## 결과

- Capability metadata와 runtime Grant가 분리된다.
- Tool adapter drift와 Capability definition drift를 각각 독립 digest로 탐지한다.
- Graph ActionPermit이 exact Tool뿐 아니라 전체 versioned Capability definition에도
  결박된다.
- 기존 Tool을 자동 분류하지 않으므로 편의성보다 review 가능한 명시성을 우선한다.

## 관련 문서

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.ko.md)
- [ADR-0047 MissionEnvelope와 ActionPermit 대수](0047-mission-envelope-and-action-permit-algebra.ko.md)
- [GRAPH-006 Atomic ActionPermit Authority](../graph/GRAPH-006-atomic-action-permit-authority.ko.md)
- [CAP-001 Versioned Capability Definition](../capability/CAP-001-versioned-capability-definition.ko.md)
