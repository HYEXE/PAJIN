> 언어: [English](CAP-003-capability-authoring-sdk-scaffold.en.md) | [한국어](CAP-003-capability-authoring-sdk-scaffold.ko.md)

# CAP-003: Capability Authoring SDK·Scaffold

- 상태: 로컬 구현 완료
- 날짜: 2026-07-26
- 선행 조건: ARCH-001, CAP-001, CAP-002, ADR-0051, ADR-0052

## 목적

Capability 저작 속도를 높이되 생성기가 새로운 실행 권위나 자유형 공격 DSL이 되지 않게 한다.
CAP-003은 CAP-001 metadata와 CAP-002의 일곱 code-backed role을 exact digest로 연결하는
결정론적 scaffold를 생성한다.

생성 직후 모든 authority class는 추상 상태다. 각 역할의 method를 코드로 구현하기 전에는
인스턴스화·등록·실행할 수 없다.

## Task 계약

- **Task ID:** CAP-003
- **Threat Model:** path traversal·overwrite, symlink/junction 교체, template code injection,
  metadata/schema drift, external schema substitution, executable incomplete stub, secret-bearing
  template context, tampered generated file
- **변경 Trust Boundary:** 검토된 authoring spec과 CAP-002 adapter 구현 코드 사이
- **Schema/API Version:** `pajin.dev/capability-scaffold/v1alpha1`,
  `pajin.dev/capability-authority-template/v1alpha1`,
  `pajin.dev/capability-benchmark-mapping/v1alpha1`,
  `pajin.dev/capability-scaffold-manifest/v1alpha1`
- **Audit Artifact:** content-derived `CapabilityScaffold`, per-file SHA-256,
  write-last `scaffold-manifest.json`
- **Benchmark 영향:** runtime wiring을 바꾸지 않는다. 생성된 benchmark mapping만 후속
  CAP-006 coverage 측정 입력으로 제공한다.

## Authoring 입력

`CapabilityScaffoldSpec`은 bounded strict JSON만 받는다. YAML, import 문자열, module scan,
shell command는 입력 계약에 없다.

- 안전한 Python package name과 PascalCase class prefix
- 공통 authority version
- exact `CapabilityDefinition`
- standalone strict JSON parameter schema
- exact `CapabilityBenchmarkMapping`

parameter schema는 JSON Schema draft 2020-12 object여야 하고
`additionalProperties: false`를 강제한다. required field는 declared property의 sorted unique
subset이어야 한다. `$ref`는 bounded local `$defs` reference만 허용한다. schema의 canonical
digest는 CAP-001 `parameterSchemaDigest`와 같아야 한다. root composition/pattern expansion과
dynamic/external reference scope 변경은 거부한다.

benchmark mapping은 exact Capability reference, sorted benchmark ID와 expected observable을
content-derived digest에 결박한다.

## Authoring SDK

다음 추상 base template를 제공한다.

1. `MaterializerTemplate`
2. `ActionCompilerTemplate`
3. `ExecutorAdapterTemplate`
4. `ResultNormalizerTemplate`
5. `SuccessOracleTemplate`
6. `ReplayStrategyTemplate`
7. `CleanupHandlerTemplate`

공통 base는 role·authority ID/version·exact Capability reference와 canonical configuration을
제공한다. 실제 concrete class는 CAP-002 요구에 따라 `stable_execution_context()`를 자신의
class body에 명시적으로 선언해야 한다. 생성기는 이 위임 method를 각 class에 넣지만 역할 method는
추상 상태로 남긴다.

## Scaffold Generator

`generate_capability_scaffold()`는 같은 spec에 항상 같은 파일과 digest를 생성한다.

- package `__init__.py`, `py.typed`
- 일곱 추상 authority class가 있는 `authorities.py`
- exact `metadata.json`
- `capability-definition.schema.json`
- digest-bound `parameter-schema.json`
- exact `benchmark-mapping.json`
- authoring·review·activation 순서를 설명하는 `README.md`
- incomplete class가 abstract인지 확인하는 negative test template
- 전체 파일 path/media type/SHA-256을 결박하는 root manifest

사용자 문자열은 Python identifier로 제한하거나 JSON string literal로 안전하게 encode한다.
생성된 Python에 자유형 code나 command를 삽입하지 않는다.

## 안전한 쓰기와 CLI

```powershell
pajin capability-scaffold capability-scaffold-spec.json --output .\generated-capability
```

writer는 기존 destination을 절대 덮어쓰지 않는다. existing directory·file·link는 실패한다.
새 root directory를 한 번만 만들고 기존 no-follow atomic writer로 각 파일을 기록한다.
`scaffold-manifest.json`은 마지막에 기록하므로 manifest가 없는 directory는 incomplete이며
소비하면 안 된다.

## 검증

- 같은 spec의 deterministic file set·scaffold digest
- 일곱 generated class의 abstract·non-instantiable 상태
- metadata와 parameter-schema digest binding
- strict schema, external `$ref`, unsorted required field 거부
- generated file content/digest tamper 거부
- existing destination overwrite 거부와 기존 manifest 보존
- concrete template의 stable-context digest와 secret-like context 거부
- CLI 성공, repeated write 실패, traceback·untrusted detail 비노출

## 호환성·migration·rollback

- 기존 Capability·Tool·Registry·Gateway·Replay runtime API와 persistent schema를 변경하지 않는다.
- 새 CLI와 public SDK import만 additive로 추가한다.
- 생성 결과는 runtime에 자동 등록되지 않는다. CAP-004 review/activation과 명시적 bootstrap이
  필요하다.
- rollback은 scaffold CLI/SDK를 사용하지 않는 것이다. 기존 CAP-001/002 계약과 실행 경로는
  그대로 유지된다.
- partial write는 manifest가 없어 완성 산출물로 오인되지 않는다. writer는 위험한 자동 삭제를
  수행하지 않는다.

## 후속 경계

- CAP-004: maturity signing, review, activation, deprecation, rotation
- CAP-005: 기존 KISA·Bug Bounty·CTF Tool과 Replay component adapter
- CAP-006: Registry coverage, authoring lead time, Oracle·Replay metric
- GRAPH-006 ActionPermit와 Tool Gateway의 실제 opt-in runtime wiring
- Linux CI와 clean-clone scaffold consumer 검증
