> 언어: [English](CAP-001-versioned-capability-definition.en.md) | [한국어](CAP-001-versioned-capability-definition.ko.md)

# CAP-001: Versioned Capability Definition

- 상태: 로컬 구현 완료
- 날짜: 2026-07-26
- 선행 조건: ARCH-001, ADR-0047, GRAPH-006

## 목적

기존 Tool 실행과 Architecture v2 Capability를 이름만으로 연결하지 않고, review 가능한
versioned metadata와 exact Tool contract digest로 결박한다. 이 조각은 Capability를 실행하지
않는다. 이후 deterministic compiler와 ActionPermit이 참조할 immutable definition만 만든다.

## 구현

### Canonical definition

`CapabilityDefinition`은 다음 material을 bounded canonical JSON과 domain-separated SHA-256에
결박한다.

- Capability ID/version/domain/maturity
- supported surface type, threat class와 precondition
- parameter schema digest
- exact Tool ID/version/full ToolSpec digest
- risk tier와 side-effect class
- evidence type, network access, approval, request-unit cost, cleanup, parallel-safe metadata

모든 collection은 sorted unique다. caller가 기존 digest와 다른 material을 제출하면 strict
parse 단계에서 거부한다.

### Exact registry

`CapabilityDefinitionRegistry`는 exact `(ID, version, digest)` reference만 resolve한다.
`latest`, compatible-version fallback이나 retired version 자동 교체는 없다. 반환값은 deep
copy이므로 caller mutation이 registry authority를 바꾸지 않는다.

### Existing Tool adapter

`ToolCapabilityRegistration`은 Capability에 필요한 보안 metadata를 명시적으로 받는다.
`capability_registry_from_tools()`는 live Tool adapter가 등록 당시 `ToolSpec`에서 변하지
않았음을 `ToolRegistry.tool()`로 확인한 뒤 frozen ToolSpec을 digest한다.

Tool 이름, category 또는 description에서 surface·threat·side effect·approval·cleanup을
추론하지 않는다. 존재하지 않거나 drift한 Tool은 fail closed한다.

### GRAPH-006 adapter

`registered_action_capability()`은 CAP-001 definition을 GRAPH-006 Permit compiler 형식으로
변환한다.

- `definitionDigest`: CAP-001 전체 definition digest
- `capabilityDigest`: Graph 등록 레코드 digest
- Tool ID/version/digest와 risk tier: exact copy

따라서 MissionEnvelope·ActionProposal·ActionPermit은 Tool binding뿐 아니라 전체 Capability
definition에도 결박된다.

## 검증

- canonical digest stability와 collection ordering rejection
- definition digest tamper와 exact-version mismatch rejection
- duplicate ID/version registry rejection
- live ToolSpec drift와 unknown Tool rejection
- explicit registration Tool mismatch rejection
- CAP-001 → GRAPH-006 authority binding 보존

## 호환성·남은 경계

- 기존 `CapabilityGrant`의 감쇠·revocation·call-budget 의미는 변경하지 않는다.
- 기존 Tool Gateway와 Policy Engine이 계속 유일한 runtime 실행 경계다.
- durable Registry, signing/review/maturity activation, compiler/executor/oracle/cleanup
  code-backed interface, runtime ActionPermit wiring은 후속이다.
- CAP-001은 benchmark coverage나 실제 Hybrid walking skeleton 완료를 주장하지 않는다.
