> 언어: [English](0052-code-backed-capability-authority-set.en.md) | [한국어](0052-code-backed-capability-authority-set.ko.md)

# ADR-0052: Code-backed Capability Authority Set

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

CAP-001은 review 가능한 declarative metadata와 exact Tool contract를 제공하지만 실제 공격
의미론을 수행하는 code component를 소유하지 않는다. Metadata에 import 문자열이나 자유형 YAML
step을 넣으면 unreviewed 실행 DSL이 생긴다. 반대로 기존 `Tool.prepare()`와 `interpret()`만
Capability로 간주하면 Materializer, Compiler, Oracle, Replay, Cleanup 책임이 암묵적이 되어
정확한 review·rotation·audit가 불가능하다.

기존 Replay Materializer/Oracle Registry와 resumable runtime의 `stable_execution_context()`
패턴은 code identity drift를 방어하는 선례를 제공한다. 다만 CAP-002는 특정 Mode나 Replay에
묶이지 않는 일반 Capability 권위 집합이 필요하다.

## 결정

1. 하나의 code-backed Capability는 Materializer, Action Compiler, Executor Adapter, Result
   Normalizer, Success Oracle, Replay Strategy, Cleanup Handler 일곱 역할을 모두 exact-once로
   등록한다.
2. 각 adapter는 role, ID, version, exact `CapabilityDefinitionRef`, 직접 구현한
   `stable_execution_context()`를 제공한다.
3. arbitrary object state나 source file을 자동 introspection하지 않는다. qualified type과 명시적
   non-secret stable context를 canonical digest에 결박한다.
4. stable context의 secret-like value, non-JSON value, 과도한 크기는 registration에서 거부한다.
5. `CodeBackedCapability` 전체는 content-derived authority-set ID/digest를 가지며 exact
   reference로만 resolve한다. `latest`와 부분 set fallback은 없다.
6. registry는 동적 import나 module scan을 하지 않는다. bootstrap code가 trusted adapter
   instance를 명시적으로 전달해야 한다.
7. adapter는 identity-checking wrapper를 통해서만 호출한다. wrapper는 전·후 identity drift,
   canonical input/output, role confused deputy와 제한된 authority expansion을 검사한다.
8. Replay/Cleanup output은 실행 권위가 아닌 plan이다. 후속 Action은 별도 compiler, Scope/Policy
   검사와 새 ActionPermit가 필요하다.
9. 기존 Tool과 Replay component의 compatibility adapter는 CAP-005까지 자동 생성하지 않는다.

## 거부한 대안

- **순수 YAML/JSON 공격 DSL:** code review와 bounded authority를 우회하는 새 실행 언어가 된다.
- **Python import 문자열 Registry:** metadata를 code loading authority로 승격한다.
- **class/source 자동 hash:** build 재현성과 packaging 차이를 authority 의미로 오인하고 explicit
  behavior versioning을 대체하지 못한다.
- **Tool 하나에 모든 역할 암묵적 결합:** Oracle·Replay·Cleanup review와 독립 rotation이
  불가능하다.
- **필요한 역할만 부분 등록:** 누락과 “지원하지 않음”을 구분할 수 없고 runtime fallback을 만든다.
  지원하지 않는 동작도 명시적 code adapter가 non-executable plan으로 표현해야 한다.

## 호환성·migration·rollback

- additive public import만 추가하며 기존 Tool Gateway와 Replay runtime을 변경하지 않는다.
- persistent schema migration은 없다.
- CAP-001 Definition만 존재하는 기존 Capability는 metadata-only 상태로 유지한다.
- CAP-002 registry를 bootstrap하지 않으면 기존 runtime behavior가 그대로 rollback 경로다.
- `v1alpha1` interface가 stable API라는 주장은 하지 않는다. 실제 Walking Skeleton wiring 전까지
  field와 method 변경은 explicit version bump로 수행한다.

## 결과

- declarative metadata와 실제 code behavior 사이에 exact audit artifact가 생긴다.
- 누락·중복·변조·mutable drift·confused deputy가 실행 전 fail closed한다.
- CAP-003 Scaffold가 생성해야 할 일곱 template의 공통 interface가 고정된다.
- durable signing/activation, existing Tool adapter, ActionPermit runtime wiring은 계속 후속이다.

## 관련 문서

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.ko.md)
- [ADR-0051 Versioned Capability Definition과 Tool Binding](0051-versioned-capability-definition-and-tool-binding.ko.md)
- [CAP-001 Versioned Capability Definition](../capability/CAP-001-versioned-capability-definition.ko.md)
- [CAP-002 Metadata + Code-backed Authority 인터페이스](../capability/CAP-002-metadata-code-backed-authority-interfaces.ko.md)
- [ADR-0053 Inert Deterministic Capability Scaffolds](0053-inert-deterministic-capability-scaffolds.ko.md)
- [CAP-003 Capability Authoring SDK·Scaffold](../capability/CAP-003-capability-authoring-sdk-scaffold.ko.md)
