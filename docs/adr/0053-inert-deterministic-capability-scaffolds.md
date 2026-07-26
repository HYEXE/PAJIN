> 언어: [English](0053-inert-deterministic-capability-scaffolds.en.md) | [한국어](0053-inert-deterministic-capability-scaffolds.ko.md)

# ADR-0053: Inert Deterministic Capability Scaffolds

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

CAP-002는 일곱 code-backed authority interface를 고정했지만 새 Capability를 만들 때 identity,
metadata, parameter schema, benchmark mapping, role class, negative test와 문서를 각각 손으로
작성하면 drift와 누락이 저작 속도의 상한이 된다.

반대로 template에 자유형 code, import 경로, shell step 또는 YAML attack sequence를 넣으면
scaffold generator가 검토되지 않은 실행 언어와 code-loading authority가 된다. 생성 직후 stub가
CAP-002 Registry에 등록될 수 있어도 fail-late runtime 오류와 가짜 coverage가 생긴다.

## 결정

1. authoring input은 strict JSON `CapabilityScaffoldSpec` 하나로 제한한다.
2. spec은 exact CAP-001 definition, canonical standalone parameter schema, exact benchmark
   mapping, 안전한 package/class identifier와 authority version만 담는다.
3. parameter schema는 strict object·`additionalProperties: false`·sorted required·bounded local
   `$defs` reference를 요구하고 CAP-001 digest와 exact match한다.
4. SDK는 CAP-002 일곱 role의 abstract base template를 제공한다.
5. generated class는 자신의 body에 `stable_execution_context()`를 명시하지만 역할 method는
   abstract로 남는다. 따라서 미구현 stub는 인스턴스화·등록·실행할 수 없다.
6. generator는 code template, metadata instance/schema, parameter schema, benchmark mapping,
   negative test, README와 typed-package marker를 deterministic하게 생성한다.
7. scaffold identity는 spec digest와 sorted per-file path/media-type/SHA-256에서 content-derived로
   만든다.
8. writer는 새 destination만 허용하고 no-follow atomic file writer를 사용한다. root manifest는
   마지막에 써서 commit marker로 사용한다.
9. generator는 runtime Registry를 수정하거나 생성물을 자동 import·등록하지 않는다.

## 거부한 대안

- **Jinja/사용자 template code:** template injection과 임의 code 생성 표면을 넓힌다.
- **YAML Capability DSL:** metadata와 실행 의미를 섞어 CAP-002 code review 경계를 우회한다.
- **Python entry-point/module scan:** package metadata를 activation authority로 승격한다.
- **완성된 pass-through stub 생성:** 미구현 의미를 정상 Capability로 등록할 수 있다.
- **기존 directory merge/force overwrite:** path 혼동, stale file, symlink와 사용자 변경 손실을
  만든다.
- **manifest 선기록:** partial file set을 완성 산출물로 오인할 수 있다.
- **실패 시 recursive cleanup:** 경로 race 상황에서 의도하지 않은 파일을 삭제할 위험이 있다.

## 결과

- author는 반복 boilerplate 대신 role method와 보안 의미 검토에 집중한다.
- generated artifact는 exact metadata/schema/benchmark/file digest로 감사할 수 있다.
- incomplete scaffold는 실행 전에 fail closed한다.
- write 실패는 manifest 없는 directory를 남긴다. 이는 자동 복구보다 명확한 불완전 상태를
  선택한 것이다.
- CAP-004 signing/review/activation 전에는 생성물의 maturity가 자동 상승하지 않는다.

## 호환성·migration·rollback

- additive SDK·CLI이며 기존 runtime/persistent schema migration은 없다.
- 생성물을 사용하지 않으면 기존 CAP-001/002 behavior가 그대로다.
- `v1alpha1` output은 향후 field/file 변경 시 명시적 version bump가 필요하다.
- generated source의 장기 API 안정성은 주장하지 않는다. manifest와 exact input을 보존해 새
  generator version으로 별도 directory에 재생성한다.

## 관련 문서

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051 Versioned Capability Definition과 Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052 Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.md)
- [CAP-002 Metadata + Code-backed Authority 인터페이스](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [CAP-003 Capability Authoring SDK·Scaffold](../capability/CAP-003-capability-authoring-sdk-scaffold.md)
