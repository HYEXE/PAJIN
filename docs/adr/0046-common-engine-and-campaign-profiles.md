# ADR-0046: 공통 엔진과 Campaign Profile

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

PAJIN의 `ai-redteam`, `bug-bounty`, `ctf` 경로는 안전 경계를 공유하지만 실행, discovery,
reporting을 각 Mode가 부분적으로 소유한다. 이 구조는 HTTP에서 얻은 Observation이 AI tool
authorization Hypothesis를 활성화하는 것과 같은 cross-surface 체인을 공통 상태로 표현하기
어렵게 한다. 동시에 기존 Mode 경로에는 검증된 정책, evidence, replay 계약과 많은 회귀
테스트가 있으므로 일괄 이동이나 삭제는 위험하다.

## 결정

1. PAJIN의 내부 목표 구조는 하나의 정책 통제형 Common Attack Engine이다.
2. pentest, bug bounty, AI red team, CTF의 운영 차이는 `CampaignProfile`로 표현한다.
   Profile은 ROE 기본값, 보고 의미, benchmark expectation과 호환 adapter를 선언하지만
   Campaign authorization을 확장할 수 없다.
3. AI는 `ai.*`로 식별되는 first-class Capability domain으로 유지한다. AI가 제품 전체
   framing이나 별도 authority root가 되지는 않는다.
4. 기존 `CampaignMode` 값, manifest, CLI command, API route와 Artifact reader는 migration
   기간에 지원한다. 각 legacy input은 version-pinned Profile로 deterministic하게 컴파일한다.
5. Profile adapter 결과는 source Mode, profile ID/version, compiler ID/version, input digest와
   output digest를 감사 이벤트에 보존한다.
6. 기존 Mode path와 Common Engine path는 같은 fixture, Scope, Capability, ToolRequest와
   expected outcome으로 parity를 입증하기 전에는 기본 경로를 전환하지 않는다.
7. 전환은 기능 단위 strangler 방식으로 수행한다. `modes/`의 대규모 rename 또는 directory
   move는 consumer 전환과 parity가 완료된 뒤 별도 결정으로 수행한다.
8. CTF의 고정 lab, flag validator와 non-submission 경계는 유지한다. Profile 표현은 이 경계를
   약화하지 않는다.

## 호환성, migration, rollback

- 새 Profile 필드는 초기에는 내부 projection이며 기존 wire schema의 필수 필드가 아니다.
- unknown Profile/version, Mode와 Profile 불일치, compiler digest 불일치는 fail closed 한다.
- adapter는 feature flag/명시적 opt-in으로 활성화한다.
- parity나 negative test가 실패하면 adapter를 비활성화하고 기존 Mode path를 사용한다.
- 기존 Artifact와 sealed Run은 작성 당시 Mode/schema 의미로 계속 읽고 검증한다.

## 결과

공통 공격 흐름과 cross-surface Graph를 추가할 수 있지만 초기에는 adapter와 이중 경로
유지 비용이 생긴다. Mode별 코드 삭제보다 parity 증명이 우선이며, 이 ADR 자체는 실행
동작을 변경하지 않는다.

## 관련 문서

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0047: MissionEnvelope와 ActionPermit 대수](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0048: Minimum Graph와 Admission 일관성](0048-minimum-graph-and-admission-consistency.md)
