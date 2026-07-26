> 언어: [English](CAP-002-metadata-code-backed-authority-interfaces.en.md) | [한국어](CAP-002-metadata-code-backed-authority-interfaces.ko.md)

# CAP-002: Metadata + Code-backed Authority 인터페이스

- 상태: 로컬 구현 완료
- 날짜: 2026-07-26
- 선행 조건: ARCH-001, CAP-001, ADR-0051

## 목적

CAP-001의 선언형 Capability Definition을 실제 실행 의미론과 이름만으로 연결하지 않는다.
Capability 하나가 실행 가능하다고 주장하려면 다음 일곱 코드 권위를 exact definition reference와
불변 digest로 함께 등록해야 한다.

1. Materializer
2. Deterministic Action Compiler
3. Executor Adapter
4. Result Normalizer
5. Success Oracle
6. Replay Strategy
7. Cleanup Handler

순수 YAML/JSON 공격 DSL, import 문자열 기반 동적 로딩, 이름이나 category를 사용한 권위 추론은
제공하지 않는다.

## Task 계약

- **Task ID:** CAP-002
- **Threat Model:** metadata/code substitution, 누락·중복 역할, mutable adapter drift,
  secret-bearing stable context, compiler target 확장, network-disabled Capability의 egress 활성화
- **변경 Trust Boundary:** CAP-001 Definition Registry와 code-backed adapter 사이
- **Schema/API Version:** `pajin.dev/code-backed-capability/v1alpha1`
- **Audit Artifact:** content-addressed `CodeBackedCapability`와 `authoritySetDigest`
- **Benchmark 영향:** 실행 경로를 아직 연결하지 않으므로 측정값 변화 없음

## 구현

### Exact adapter identity

모든 adapter는 다음을 명시적으로 제공한다.

- authority role, ID, version
- exact `CapabilityDefinitionRef`
- qualified implementation type
- 직접 구현한 `stable_execution_context()`

stable context는 bounded canonical JSON이어야 하며 secret·token·password·credential과 같은
민감한 값을 담는 field를 거부한다. implementation type과 context digest, Capability reference,
role, ID/version은 domain-separated SHA-256 `authorityDigest`에 결박된다.

등록 뒤 identity, type, context 또는 role interface가 바뀌면 resolve와 호출 전·후 검사가
fail closed한다.

### Complete authority set

`CodeBackedCapability`은 일곱 역할을 sorted exact-once tuple로 요구한다. authority ID/version도
set 안에서 중복될 수 없다. 전체 material은 content-derived `authoritySetId`와
`authoritySetDigest`에 결박된다.

`CapabilityAuthorityRegistry`는 다음만 허용한다.

- CAP-001 Registry가 exact ID/version/digest로 resolve한 definition
- 각 role을 실제로 구현하는 adapter
- role과 authority identity가 중복되지 않은 완전한 set
- exact `CodeBackedCapabilityRef` resolution

`latest` fallback, runtime mutation, 부분 authority set, 자동 module discovery는 없다.

### Identity-checking wrapper

`RegisteredCapabilityAuthority`는 adapter를 직접 노출하지 않고 role별 호출을 감싼다.

- Materializer input/output은 bounded canonical JSON object다.
- Compiler는 request ID, Agent, target, method를 바꾸거나 materialized argument 밖의 값을
  추가할 수 없고 exact CAP-001 Tool ID를 사용해야 한다.
- Executor는 network-disabled Capability에서 network-enabled Worker job을 만들 수 없다.
- Normalizer는 request와 Tool identity를 바꿀 수 없다.
- Oracle은 `succeeded`, `failed`, `inconclusive`만 반환한다.
- Replay와 Cleanup은 비실행 plan만 반환한다. 실제 후속 Action은 새 compilation과 Permit이
  필요하다.

## 검증

- 일곱 역할의 deterministic authority-set digest와 exact resolution
- 모든 wrapper의 positive invocation
- missing/duplicate role과 unregistered definition rejection
- 잘못된 role interface, secret-like context, non-JSON context rejection
- 등록 후와 호출 중 adapter identity drift rejection
- compiler target expansion과 network-disabled egress rejection
- authority-set digest와 exact reference tamper rejection
- 다른 role wrapper를 사용한 confused-deputy 호출 rejection

## 호환성·migration·rollback

- 기존 `Tool`, `ToolRegistry`, `CapabilityGrant`, Tool Gateway, Replay runtime API는 바꾸지 않는다.
- persistent schema나 Artifact reader migration은 없다.
- CAP-001 definition이 존재해도 CAP-002 authority set이 없으면 code-backed 실행 가능하다고
  간주하지 않는다.
- 기존 Tool·Replay 구현을 자동 등록하지 않는다. 명시적 compatibility adapter는 CAP-005에서
  추가한다.
- rollback은 CAP-002 registry를 구성하지 않고 CAP-001 metadata-only Registry를 계속 사용하는
  것이다. 기존 실행 경로에는 영향이 없다.

## 후속 경계

- CAP-003: Capability SDK·Scaffold와 역할별 template
- CAP-004: maturity signing, review, activation, deprecation, rotation
- CAP-005: 기존 KISA·Bug Bounty·CTF Tool과 Replay component adapter
- GRAPH-006 ActionPermit와 Tool Gateway의 실제 opt-in runtime wiring
- durable Capability Registry와 Linux CI
