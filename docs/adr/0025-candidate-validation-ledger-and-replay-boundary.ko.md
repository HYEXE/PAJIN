> Languages: [English](0025-candidate-validation-ledger-and-replay-boundary.en.md) | [한국어](0025-candidate-validation-ledger-and-replay-boundary.ko.md)

# ADR 0025: Candidate 검증 원장과 재실행 경계

- 상태: 원장 및 객관적 게이트 설계에 대해 승인됨. 확인 의미론은 ADR 0027에서 개정됨
- 날짜: 2026-07-14
- 구현: 1단계 구현 완료. 신뢰할 수 있는 KISA Candidate 입장은 ADR 0026에서 추가됨. 이 ADR
  승인 당시 계획 상태였던 Restricted Reproducer와 공통 확인 Gate는 현재 ADR 0027에 명시된
  KISA/Local 범위에 구현됨
- 개정 대상: [ADR 0004](0004-dynamic-multi-agent-execution.ko.md)
- 개정 문서: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)

## 맥락

ADR 0004는 Finding을 확인된 것으로 보고하기 전에 별도의 Validator 역할과 결정론적 최종
게이트를 요구한다. 1단계 이전에는 Local 및 Multi-Agent 러너가 Validator 출력을 하나의
불리언 값인 `Finding.validated`로 축약했다. 승인된 Finding만 `findings.json`과 정식 보고서에
포함되었다. 따라서 Validator의 의견 불일치, 의미 표지 누락, 재실행 실패, 객관적 증거 위반이
모두 최종 산출물에서 동일하게 누락되는 결과로 축약될 수 있었다.

이 동작은 확인 판단에는 보수적이지만 사후 검토에는 파괴적이다. 또한 Local 실행과
Multi-Agent 실행이 대상 및 증거 출처를 강제할 기회를 서로 다르게 만들고, Validator 품질을
측정하기도 어렵게 한다. PAJIN은 `findings.json`의 기존 소비자를 안정적으로 유지하면서
Validator가 실제로 반환한 내용을 보존해야 한다.

완전한 설계에는 독립적인 제한 재현이 필요하다. 그러나 모델이 서술형 재실행 제안을 곧바로
실행 권한으로 바꾸어서는 안 된다. 재실행에는 새로운 Tool 호출, 대상에 미치는 영향, 증거,
예산, 프롬프트 인젝션 노출이 추가된다. 따라서 현재 Provider Validator의 모델 호출을
확장하는 대신 별도의 단계적 신뢰 경계가 필요하다.

## 결정

### 정식 검증 스냅숏과 호환성 뷰

1단계에서는 최종 Run 봉인 전에 다음 정식 Run 스냅숏을 기록한다.

- `candidate-findings.json`은 검증 경계에 입장한 모든 Candidate Finding을 안정적인 생성
  순서로 보존한다.
- `validation-decisions.json`은 입장한 각 Candidate마다 정확히 하나의 Validation Decision을
  대응되는 안정적 순서로 포함한다.
- `validation-index.json`은 ID만 담는 파생 처분 뷰이며 Candidate 본문을 중복 저장하지 않는다.

각 Candidate에는 안정적인 ID와 제한된 출처 정보가 있다. 해당 Candidate의 단일 Decision은
해당되는 경우 이를 생성한 Validator의 신원과 방법, 동일 Run의 증거 참조, 길이가 제한된 이유
요약, 기계 판독 가능한 이유 코드를 기록한다. 비공개 모델 사고 과정은 저장하지 않는다.
1단계 스키마는 Decision이 없거나 둘 이상인 Candidate를 거부한다.

`findings.json`은 확인된 항목만 제공하는 호환성 뷰로 유지된다. 기존 `Finding` 형태와
`validated: true` 조건은 현재 CLI, Reporter, KISA, Bug Bounty, CTF, Control Plane 소비자에게
계속 제공된다. Run을 최종화할 때 PAJIN은 각 Candidate의 단일 `confirmed` Decision에서 이
뷰를 직접 파생한다. ADR 0027은 이제 이러한 모든 Decision이 성공한 독립 ReplayOutcome을
참조하도록 요구한다. 해당 마이그레이션이 구현되기 전까지 현재 프로젝션에는 레거시 의미론적
확인이 포함될 수 있으므로 제품 수준의 Confirmed로 해석해서는 안 된다. 정식 Candidate 및
Decision 스냅숏, 파생 뷰, 감사 이벤트는 최종 Run 무결성 봉인으로 함께 보호된다.

1단계는 물리적 추가 전용 검증 로그, Candidate당 여러 Decision, 또는 대체 Decision 체인을
구현하지 않는다. 이를 위해서는 전이 권한, 순서, 검토자 신원, 그리고 봉인된 1단계 스냅숏을
다시 쓰지 않고 이후 Decision이 무결성 체인을 확장하는 방식을 정의하는 향후 스키마와 수명
주기 단계가 필요하다.

### 검증 처분

검증 처분은 정확히 네 가지다.

| 처분 | 의미 |
| --- | --- |
| `confirmed` | Candidate에 결합된 독립 ReplayOutcome과 Mode Oracle이 주장을 뒷받침하고, 객관적 게이트를 통과하며, Mode에서 요구하는 경우 의미론적 근거가 존재함 |
| `needs-review` | 주장은 여전히 타당할 수 있으나 독립 재현이 없거나, 부적격이거나, 승인을 기다리거나, 의미론적으로 모호함 |
| `inconclusive` | 실행 또는 증거가 불완전하여 재실행이나 관찰로 결론에 도달할 수 없음 |
| `rejected-objective` | 결정론적이고 Mode를 인식하는 규칙이 명시된 주장에 대해 Candidate가 무효임을 입증함 |

`candidate`는 원장 레코드 상태이지 처분이 아니다. `duplicate` 역시 검증 처분이 아니다. 동일
Run 내의 정확한 관계와 Bug Bounty의 알려진 Finding 또는 근본 원인 분류는 별도의 중복 제거
계층으로 유지된다. 중복 제거는 제출을 억제하거나 대표 항목을 선택할 수 있지만, 원본
Candidate를 삭제하거나 검증 이력을 다시 작성해서는 안 된다.

객관적 거부는 선언되지 않았거나 범위 밖인 대상, 없거나 다른 Run에서 온 증거, 유효하지 않은
증거 무결성, 실제로 수행되지 않은 Tool 실행 주장, 또는 정확한 주장과 직접 모순되는 형식화된
Mode Oracle과 같은 사실로 제한된다. 정확한 KISA 표지가 없으면 정확한 표지에 대한 주장과
모순될 수 있지만, 그것만으로 부분적 또는 의미론적 공개라는 별도 주장을 거부하지는 않는다.
재실행 시간 초과, 잘림, 속도 제한, 비결정적 누락은 객관적 거부가 아니라 `inconclusive`다.

### 1단계: 레거시 Candidate 보존과 단일 결정론적 게이트

첫 번째 구현 단계는 기존 `ValidatorRuntime`이 반환한 `Finding` 객체만 보존한다. 호환성
어댑터는 확인 필터링을 수행하기 전에 반환된 각 Finding을 Candidate로 입장시킨다. 현재 구현된
호환성 경로에서는 레거시 `validated: true` Candidate가 결정론적 게이트를 통과한 뒤
`confirmed`가 될 수 있다. ADR 0027은 이 확인 의미를 대체한다. 성공한 독립 ReplayOutcome이
없으면 Candidate는 `independent-reproduction-missing` 이유와 함께 `needs-review`로 남아야 한다.
객관적 게이트를 통과한 레거시 `validated: false` Candidate는 이 불리언만으로는 원인이 의견
불일치인지 불완전한 실행인지 알 수 없으므로 명시적인 레거시 모호성 이유와 함께
`needs-review`로 남는다.

이 단계는 Validator가 한 번도 반환하지 않은 Candidate를 복원하지 **않는다**. 현재
Specialist 계약은 `CandidateFinding`이 아니라 `ToolResult`를 생성한다. 표지 기반 또는
결정론적 Validator도 여전히 빈 목록을 반환하여 보존할 Candidate를 남기지 않을 수 있다.
이 누락을 해결하려면 형식화된 Candidate 생성 경계가 필요하며, 이는 명시적으로 1단계 범위
밖이다. ADR 0026은 이제 정확한 KISA `ai.chat-probe` 카탈로그 관찰에 대해서만 해당 경계를
구현한다. 다른 Tool 계열은 레거시 경로에 남는다.

Local 및 Multi-Agent 러너는 동일한 PAJIN 소유 결정론적 분류 게이트를 사용한다. 게이트는
Campaign, Run 경로 및 신원, Tool Result와 증거 인벤토리, 입장한 Candidate를 입력으로 받는다.
선언된 대상과 허용/거부 Scope를 검증한다. 인용된 모든 증거 경로에 대해 해석된 경로가 Run의
`evidence/` 디렉터리 안에 남는지, 존재하는 일반 파일인지, Candidate에 연결된 Tool Gateway
증거 레코드로 파싱되는지도 확인한다. Gateway 레코드의 요청 ID, Tool ID, 대상, 저장된 Tool
Result는 메모리 내 Tool Result 및 Candidate 출처와 일치해야 한다. 같은 Run에 단순히 존재하는
경로만으로는 충분하지 않다. Plan 요청 ID는 고유하며, Tool Result 요청 신원이 중복되면 출처
검사가 실패하므로 하나의 증거 경로가 여러 실행을 모호하게 뒷받침할 수 없다.

게이트는 최종 Run 봉인 전에 실행된다. 1단계에는 Specialist 증거나 검증 입력을 위한 중간
암호학적 봉인이 없다. 따라서 검증 전 암호학적 불변성이 아니라 분류 시점의 파일 시스템 포함
여부, 존재 여부, Gateway 요청/대상 연결을 입증한다. `candidate-findings.json`,
`validation-decisions.json`, 확인된 호환성 뷰, 참조된 증거는 최종 Run 무결성 봉인에 결합된다.
게이트는 결정론적이며 Provider 또는 Tool 권한이 없다. 의미론적 Validator는 주장을 뒷받침할
수 있지만 객관적 게이트 실패를 무시할 수는 없다.

### 2단계: 모델 실행 권한 없는 필수 제한 재현

제한 재현은 필수적인 두 번째 단계이며 다음과 같은 고정된 권한 체인을 따른다.

1. Provider 전용 의미론적 Validator는 제한된 Validation Packet 하나를 받는다. 유일한 실행
   기능은 등록된 Provider 호출이다. 모든 증거 문자열을 신뢰할 수 없는 데이터로 취급한다.
2. Validator는 형식화된 비실행형 `ReplayIntent`를 방출할 수 있다. 실행 가능한 명령, 프로세스
   경로, 임의 URL, 원시 `ToolRequest`, Capability Grant는 방출할 수 없다.
3. 신뢰할 수 있는 컴파일러는 등록된 Mode 시나리오와 Tool 템플릿을 기준으로 의도를 해석하고,
   정확한 Candidate 대상에 결합하며, 인수와 메서드를 검증하고, 위험 및 호출 예산을 상한 내로
   제한한다. 인식할 수 없거나 모호한 의도는 닫힌 상태로 실패한다.
4. PAJIN은 신뢰할 수 있는 재실행 실행자에게 별도의 재실행 Grant를 발급한다. 이 Grant는
   Specialist Grant나 Provider Grant가 아니며 컴파일된 Tool, 정확한 대상, 제한된 호출 수,
   만료 시각, 위험 상한만 포함한다.
5. 재실행은 일반 Tool Gateway 및 Worker 경계를 통해 실행되어 별도의 요청 및 증거 계보를
   생성한다. 형식화되고 Mode가 소유하는 Oracle이 재실행 관찰을 평가한 뒤 공통 결정론적
   게이트가 최종 처분을 기록한다.

초기 자동 재실행은 Tool 및 Mode 계약에서 컴파일된 작업에 대해 재실행 안전성과 멱등성을
명시적으로 선택한 T0-T2 Tool로 제한된다. T3/T4, 비멱등 작업, 해당 메타데이터가 없는 Tool은
자동으로 재실행하지 않는다. 이러한 작업에 승인 중개형 또는 보상형 재실행을 추가하려면 향후
ADR이 필요하다.

### Mode 경계

- KISA AI Red Team은 의미론적 해석을 형식화된 트랜스크립트, 표지, Tool 추적, 기준선,
  공격-응답 Oracle과 결합할 수 있다. 표지 결과는 보편적 판정이 아니라 명시적 관찰로 유지된다.
- 고정 Bug Bounty SQL 인젝션 실습은 결정론적 제어 집합 Oracle을 유지한다. 검증 처분은 별도의
  보고 및 중복 분류 상태보다 먼저 평가된다.
- CTF는 결정론 전용으로 유지된다. 플래그 및 산출물 다이제스트 비교가 권위 있는 Oracle이다.
  LLM 의미론적 Validator나 LLM이 계획하는 자동 재실행을 도입하지 않는다. 기존 CTF 풀이
  상태는 검증 처분이 아니라 Mode 출력으로 유지된다.

### 증거 보존과 개인정보 보호

Candidate 보존이 원시 증거의 무기한 보존을 허가하지는 않는다. Candidate 및 Decision 원장은
원시 트랜스크립트, 응답, 플래그, 비밀, 개인정보를 복사하지 않고 Run 상대 식별자와 다이제스트로
증거를 참조해야 한다. 이유 요약은 길이가 제한되고 비식별 처리되며, 모델 사고 과정은 결코
Run 산출물이 되지 않는다.

원시 증거에는 Campaign 및 Mode의 보존, 접근 제어, 암호화, 비식별 처리, 폐기 정책이 계속
적용된다. Provider로 보내는 Validation Packet에는 해당 Candidate에 필요한 최소한의 허용 목록
내 비식별 발췌문만 포함된다. 시스템 프롬프트, 자격 증명, 관련 없는 Candidate, 제한 없는 Run
트랜스크립트는 기본적으로 제외된다. 비식별 처리 후에도 증거 내용은 공격자가 제어하는 것으로
간주한다.

추가 방식 무결성과 데이터 최소화는 별개의 문제다. 향후 보존 처리에서 다이제스트와 폐기
레코드만 남기고 원시 증거를 사용할 수 없게 할 수 있다. 이 경우 리더는 과거 내용을 더 이상
재검증할 수 없다고 보고해야 한다. 다이제스트의 봉인은 삭제된 평문을 여전히 사용할 수 있다는
증거가 아니다.

## 결과

- 검토 및 결론 불가 사례를 감사할 수 있게 되는 동안 Candidate 및 Decision 소비자는 1단계
  원장을 계속 사용할 수 있다. Confirmed-Finding 소비자가 `findings.json`을 제품 수준 확인으로
  취급하려면 ADR 0027 마이그레이션과 산출물 버전 관리가 필요하다.
- Validator 의견 불일치에는 더 이상 삭제 권한이 부여되지 않으며, 객관적 거부 이유는 기계가
  판독할 수 있다.
- Local 및 Multi-Agent 검증은 하나의 결정론적 게이트를 사용하므로 서로 달라지지 않는다.
- 첫 단계는 의도적으로 불완전하다. 레거시 Validator 출력은 보존하지만 Finding으로 표현되지
  않은 분석은 복원할 수 없다. ADR 0026은 Semantic Validator에 직접 재실행 권한을 부여하지
  않으면서 카탈로그화된 KISA AI 채팅 관찰에 대해 이 제한을 좁힌다.
- Candidate별 스냅숏 레코드와 원시 증거 참조는 산출물 양을 늘리고 명시적 보존 처리를 요구한다.
  여러 Decision의 이력은 향후 스키마로 남는다.
- LLM 재실행에는 직접 실행 권한이 없다. 컴파일러, 재실행 Grant, Tool Gateway, 형식화된
  Oracle은 신뢰할 수 있는 PAJIN 경계로 유지된다.
- Mode별 진실성 계약, 특히 CTF 다이제스트 검증과 Bug Bounty 중복 분류는 그대로 유지된다.

## 검증 요구사항

1단계 원장 구현은 테스트를 통해 다음을 입증해야 완료된 것으로 본다.

- Local 및 Multi-Agent 러너가 반환된 `validated: false` Candidate를 보존하고
  `findings.json`에 추가하지 않은 채 분류한다.
- 스키마가 Candidate 하나에 Decision이 없거나 여러 개인 경우를 거부한다.
- 벗어났거나 없는 증거 경로와 일치하지 않는 Gateway 요청 ID 또는 대상 출처가
  `rejected-objective`가 된다.
- 다른 Run의 증거와 범위 밖 대상이 감사 이유를 포함한 `rejected-objective`가 된다.
- confirmed, needs-review, inconclusive, rejected-objective 레코드가 보고서 생성 후에도 유지되고,
  중간 검증 봉인을 주장하지 않으면서 최종 Run 무결성 봉인으로 보호된다.
- 레거시 `findings.json` 소비자에게는 여전히 확인된 Finding만 제공된다.
- Bug Bounty 중복 상태 및 CTF 풀이 상태가 검증 처분과 별도로 유지된다.

이 테스트들은 구현된 레거시 호환성 동작을 설명할 뿐 제품 확인 경계를 충족하지는 않는다.
ADR 0027 마이그레이션에는 의미론적 근거와 객관적 게이트만으로 확인된 프로젝션을 만들 수
없다는 점, 성공한 최신 ReplayOutcome으로는 만들 수 있다는 점, 실행 가능한 모델 출력,
컴파일러 모호성, Grant 범위 밖 Tool 또는 대상 요청, 비멱등 재실행, T3/T4 재실행, 증거 프롬프트
인젝션, 재실행 증거 대체가 닫힌 상태로 실패한다는 점을 입증하는 테스트도 필요하다.

## 참고 자료

- [ADR 0004: 동적 멀티 에이전트 실행과 권한 축소 위임](0004-dynamic-multi-agent-execution.ko.md)
- [ADR 0009: 추론 역할을 위한 정책 제한 Provider Runtime](0009-provider-backed-agent-runtime.ko.md)
- [ADR 0014: 보수적인 Bug Bounty Finding 중복 제거](0014-conservative-bug-bounty-deduplication.ko.md)
- [ADR 0016: 변조 방지 Run 무결성 체인](0016-tamper-evident-run-integrity.ko.md)
- [ADR 0017: 로컬 전용 CTF Web Mode 수직 슬라이스](0017-local-ctf-web-mode.ko.md)
- [ADR 0018: CTF Crypto Mode용 제한된 인라인 산출물](0018-bounded-ctf-crypto-artifacts.ko.md)
- [ADR 0019: 제한된 CTF Suite 오케스트레이션](0019-bounded-ctf-suite-orchestration.ko.md)
- [ADR 0026: 신뢰할 수 있는 KISA Candidate 입장](0026-trusted-kisa-candidate-admission.ko.md)
- [ADR 0027: 확인 경계로서의 독립적인 제한적 재현](0027-independent-reproduction-confirmation-boundary.ko.md)
