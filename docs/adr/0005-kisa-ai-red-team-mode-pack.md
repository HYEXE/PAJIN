# ADR-0005: KISA AI Red Team Mode Pack과 증적 기반 체크리스트

- Status: Accepted
- Date: 2026-07-12

## Context

KISA 「AI 보안 레드티밍 가이드」는 위협 분류, 레드티밍 절차, 평가 기준, 시나리오 구성,
로그·증적, 체크리스트, 계획·완료·실행 기록 산출물을 제시한다. PAJIN은 이를 단순 보고서
템플릿이 아니라 실행 가능한 Mode Pack으로 연결해야 한다.

다만 가이드의 모든 항목을 기술 실행 결과만으로 확인할 수는 없다. 법률·윤리 검토, 인력의
전문성·교육, 심리적 지원, 이해관계자 협의, 비즈니스 영향, 개선 과제의 실제 운영 반영을
자동으로 통과시키면 근거 없는 준수 주장이 된다. 위협 코드가 카탈로그에 존재한다는 사실과
해당 위협을 실제로 테스트했다는 사실도 구분해야 한다.

## Decision

### PAJIN 소유의 타입 카탈로그

1. 19개 KISA 위협을 코드, 이름, 위협군, 시스템 계층, 출처 페이지와 함께 타입 카탈로그로
   관리한다.
2. 시나리오는 대상 유형, 위협 코드, 공격 표면, 페르소나, 사전 조건, 실행 절차, 판정 기준,
   영향 차원, 증적 요구사항, 등록 Tool을 포함한다.
3. Campaign의 요청 위협 중 대상 유형에 맞는 시나리오만 Planner가 선택한다. 시나리오가
   없는 요청 위협은 `untested`와 사유로 남긴다.
4. 첫 실행 시나리오는 `mock-agent` 대상의 간접 프롬프트 인젝션·비인가 도구 호출이며
   A01·A02를 다룬다.

### 실행과 독립 검증

1. 시나리오 반복 수만큼 별도 Specialist Task를 만들고 기존 Tool Gateway, 정책,
   Capability 감쇠, Docker Worker, 예산, Kill Switch 경계를 그대로 사용한다.
2. Specialist는 Finding을 확정할 수 없다. 별도 Validator가 같은 Run의 증적만 사용해
   판정하고 PAJIN의 결정론적 게이트가 증적 출처와 Scope를 다시 확인한다.
3. 반복 실행에서 나온 동일 Finding은 제목·위협·대상을 기준으로 합치되 모든 재현 증적을
   보존하고 보수적인 신뢰도를 적용한다.

### 평가와 체크리스트

1. 공격 성공률, 차단·거부율, 재현율, 민감정보 노출 수, 평균 지연, 위협 커버리지를
   구조화된 지표로 계산한다.
2. 체크리스트는 `yes`, `no`, `not-applicable`, `needs-review` 네 상태를 사용한다.
3. `yes`는 동일 Run의 구조화 증적으로 확인 가능한 경우에만 사용한다.
4. 법률·윤리·인력·교육·HITL·비즈니스 영향 등 조직 판단은 자동화하지 않고
   `needs-review`로 남긴다.
5. 수행하지 않은 완화·개선·재검증·회귀 활동은 `no`로 표시한다.
6. Docker 환경 항목은 실제 Worker 증적에서 Docker backend가 관찰될 때만 `yes`다.

### 산출물

표준 PAJIN Run 산출물에 평가 결과, 52개 체크리스트, 테스트 계획, 완료 보고, 실행 기록,
Markdown 보고서를 추가한다. 모든 KISA 산출물은 출처 페이지 또는 근거 Artifact를 포함하며
보고서에는 준수 인증이 아니라는 제한을 명시한다.

## Consequences

### Positive

- 가이드 요구사항이 Campaign 선택부터 실행·검증·보고까지 추적된다.
- 수록된 위협과 실제 테스트 커버리지가 분리되어 누락이 숨겨지지 않는다.
- 반복 실행과 독립 검증으로 단일 실행 결과보다 재현성이 높다.
- 조직적 판단을 자동 통과시키지 않아 과도한 준수 주장을 방지한다.
- Mode Pack이 기존 보안 경계를 우회하지 않고 동일한 Tool Gateway와 Worker를 재사용한다.

### Trade-offs and residual risks

- 첫 수직 시나리오는 19개 위협 중 A01·A02만 실행한다.
- 체크리스트 자동 판정은 제공된 Campaign 데이터와 Run 증적의 완전성에 의존한다.
- 기술 심각도와 조직의 최종 조치 우선순위 사이에는 사람 판단이 필요하다.
- 실제 모델 비결정성을 다루려면 더 많은 반복, 변형 입력, 독립 모델과 정상 질의 평가가
  필요하다.
- 완화 권고, 담당·기한, 재검증과 회귀 테스트의 폐루프는 후속 목표다.

## Verification

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker simulated --repetitions 2
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker docker --repetitions 2
.venv\Scripts\pytest -q
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

인수 조건은 19개 위협과 52개 체크리스트의 스키마 검증, A01·A02 두 번 실행과 A04의 명시적
미실행 사유, 독립 검증 후 한 개 Finding과 두 개 Worker 증적, KISA JSON·Markdown 산출물,
그리고 전체 정적·동적 테스트 통과다.
