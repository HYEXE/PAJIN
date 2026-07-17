> Languages: [English](0026-trusted-kisa-candidate-admission.en.md) | [한국어](0026-trusted-kisa-candidate-admission.ko.md)

# ADR 0026: 의미론적 검증 전 신뢰할 수 있는 KISA Candidate 입장

- 상태: Candidate 입장에 대해 승인됨. 확인 의미론은 ADR 0027에서 개정됨
- 날짜: 2026-07-14
- 구현: KISA AI 채팅 Candidate 입장 구현 완료. 이 ADR 승인 당시 계획 상태였던 Restricted
  Reproducer와 공통 확인 Gate는 현재 ADR 0027에 명시된 KISA/Local 범위에 구현됨
- 개정 대상: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.ko.md)
- 개정 문서: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)

## 맥락

ADR 0025 1단계는 Validator가 반환한 모든 `Finding`을 보존하지만, 의미론적 Validator는
유효하게 빈 목록을 반환할 수 있다. 이 경우 강력한 Specialist 관찰도
`candidate-findings.json`에 들어가기 전에 사라질 수 있다. Semantic Validator에 직접 공격
Tool이나 재실행 권한을 부여해도 이 입장 문제는 해결되지 않으며 최소 권한 경계만 넓어진다.

PAJIN에는 이미 여러 KISA AI 채팅 시나리오를 위한 더 좁은 진실의 원천이 있다. 신뢰할 수 있는
카탈로그가 정확한 Plan 메타데이터, 형식화된 요청, 턴, 검사, 예상 표지를 정의한다. Tool
Gateway는 해당 요청과 결과를 동일 Run 증거에 결합한다. 이 사실들은 관찰의 의미론적 유효성을
판단하지 않고도 이를 Candidate로 입장시킬 수 있다.

일반적인 `ToolResult.data`는 여전히 신뢰할 수 없으며 보편적인 취약점 의미도 없다. 특히 임의의
`vulnerable: true` 필드, Worker가 미리 계산한 검사 결과, MCP 콘텐츠 플래그만으로는 보안
Finding의 충분한 증거가 되지 않는다.

## 결정

PAJIN은 Specialist 실행과 Validator 호출 사이에 선택적인 신뢰 경계인
`CandidateProducerRuntime`을 추가한다. 이는 동기식이고 결정론적이며 Tool이 없는 컴포넌트다.
러너는 형식화된 Campaign, 검증된 Plan, 완료된 Tool Result만 이 컴포넌트에 제공한다. 컴포넌트는
원자적으로 `CandidateProduction`을 반환한다. 여기에는 주장이 항상 `validated: false`인 불변
`CandidateFinding` 레코드와 Producer가 확인 입장 권한을 갖는 요청 ID 및
`(target, threat class)` 주장 공간이 포함된다.

첫 번째 Producer는 KISA `ai.chat-probe` 카탈로그 시나리오 M03, M06, A04로 제한된다. 다음
조건을 모두 충족할 때만 Candidate를 입장시킨다.

1. Campaign이 AI Red Team Mode다.
2. 고유한 Plan 요청 하나와 Tool Result 하나가 요청 신원을 공유한다.
3. Plan 단계가 카탈로그 시나리오의 Tool, 메서드, 위협 클래스, 공격 표면, 페르소나와 정확히
   일치한다.
4. 요청이 `AIChatProbeInput`으로 파싱되며 시나리오, 위협, 턴, 검사가 카탈로그 템플릿과 정확히
   일치한다.
5. Result가 성공했고 Tool, 대상, 시나리오, 위협, 세션 신원이 요청 및 Plan과 일치한다.
6. Result가 실제 네트워크 실행을 보고하고 동일 Run 증거를 참조하며, Candidate 소스 요청
   집합이 증거에 연결된 해당 실행과 정확히 일치한다.
7. PAJIN이 원시 응답 트랜스크립트를 대상으로 모든 카탈로그 검사를 다시 계산하고 모든 검사가
   통과한다.

Producer는 `data.vulnerable`, Worker의 `checks[*].matched` 값 또는 모델 요약을 신뢰하지 않는다.
동일한 카탈로그 시나리오, 위협, 대상에 대한 반복 관찰은 순서가 있고 고유한 요청 및 증거 참조를
가진 하나의 Candidate가 된다. Producer 출처는 의미론적 Validator에 귀속하지 않고 신뢰할 수
있는 코어 출처로 기록한다.

Validator가 반환한 뒤 공통 검증 게이트는 코어 소유의 대상, 위협 클래스, 겹치는 동일 Run 증거를
사용해 출력을 입장한 Candidate에 일대일로 조정한다. 제목이나 서술을 다시 써도 새로운 신원이
생기지 않는다. Producer의 요청 또는 주장 권한 안에서 나온 Validator 전용 결과는 Producer가
일치하는 Candidate를 입장시키지 않았다면 확인될 수 없다. 이 결과는
`candidate-producer-not-admitted`가 지정된 별도의 검토 Candidate로 보존된다. 겹치거나 모호한
Validator 출력도 삭제하지 않고 동일하게 보존한다. Campaign이 위협 집합을 선언한 경우 선언되지
않은 위협 클래스는 객관적 게이트에서 거부된다. 빈 위협 집합은 게이트와 Producer 권한 계산에서
모두 일관되게 제한 없음으로 취급한다.

ADR 0027은 그 결과로 나오는 처분 규칙을 다음과 같이 개정한다.

| Producer 관찰 | Semantic Validator 결과 | 객관적 게이트 | 독립 재현 | 처분 |
| --- | --- | --- | --- | --- |
| 입장됨 | 일치하는 근거 | 통과 | 성공한 형식화된 ReplayOutcome | `confirmed` |
| 입장됨 | 일치하는 근거 | 통과 | 실행되지 않았거나 구현되지 않음 | `independent-reproduction-missing`이 지정된 `needs-review` |
| 입장됨 | 누락 | 통과 | 무관 | `validator-omitted`가 지정된 `needs-review` |
| 입장됨 | 일치하는 이견 | 통과 | 무관 | `needs-review` |
| 입장 안 됨 | Producer 권한 안의 Validator 전용 주장 | 통과 | 무관 | `candidate-producer-not-admitted`가 지정된 `needs-review` |
| 입장됨 | Validator 또는 재실행이 취소되거나 사용 불가 | 통과 | 결정적 결과 없음 | `inconclusive` |
| 입장됨 | 무관 | 실패 | 실행 안 됨 | `rejected-objective` |

정식 Candidate 주장은 확인 후에도 `validated: false`로 유지된다. ADR 0027 마이그레이션 이후
`findings.json`의 확인 전용 호환성 프로젝션은 Decision이 성공한 ReplayOutcome을 참조할 때만
코어 주장을 복사하고 `validated: true`로 설정할 수 있다. Semantic Validator는 주장을
뒷받침하거나 반박할 수 있지만, 단독으로 확인하거나 입장한 주장을 다시 쓰거나 빈 목록을
반환하여 지울 수는 없다.

M1 마이그레이션은 이제 일치하는 의미론적 근거와 객관적 게이트가 `confirmed` 프로젝션을
생성하지 못하도록 차단한다. Restricted Reproducer 지원이 구현될 때까지 해당 Candidate는
`independent-reproduction-missing`이 지정된 `needs-review`로 보존된다.

신뢰할 수 있는 Producer가 없는 Tool 계열의 Validator 전용 Finding은 ADR 0025 레거시
어댑터를 계속 통과한다. 이렇게 현재 호환성을 보존하면서 불완전한 적용 범위를 명시한다. 새
Producer는 Validator 호출 전에 Candidate 및 권한 수만 포함하는 ID 전용 입장 감사 이벤트를
방출한다. 취소, 시간 초과, 예외로 검증이 불가능해지면 Local 및 Multi-Agent 최종화가 필요한
경우 사용 가능한 완료 결과에 순수 Producer를 다시 실행하고, 해당 Candidate를
`validator-cancelled` 또는 `validator-unavailable`이 지정된 `inconclusive`로 기록한다. 최종
Candidate 및 Decision 스냅숏은 계속 Run의 최종 무결성 봉인으로 보호된다.

## 명시적 제외 사항

- Producer에는 Tool, Provider, 재실행, Capability Grant 또는 프로세스 실행 권한이 없다.
- 일반적인 `data.vulnerable` 조건자를 도입하지 않는다.
- MCP 결과와 normal-function 회귀 프로브는 이 Producer를 통해 Candidate를 생성할 수 없다.
- 합성 `mock.agent-probe` 경로는 엄격하게 형식화된 관찰 계약을 갖출 때까지 레거시 Validator
  경계에 남는다.
- Bug Bounty는 기존의 형식화된 결정론적 제어 집합 Oracle을 유지한다.
- CTF는 플래그 및 산출물 다이제스트 검증을 Finding 처분과 분리해 유지한다.
- 직접 LLM 실행은 계속 제외된다. 독립 재현에는 ADR 0027에서 정의한 컴파일러, 재실행 전용
  Grant, Restricted Reproducer, Mode Oracle을 사용해야 한다.

## 결과

- Specialist 증거가 존재한 뒤 의미론적 Validator가 빈 목록을 반환하거나, 취소되거나, 사용할
  수 없게 되었다는 이유만으로 KISA AI 채팅 관찰이 더 이상 사라지지 않는다.
- Producer 입장만으로는 확인된 Finding을 기록하지 않으며, ADR 0027 마이그레이션 이후에는
  Semantic Validator 근거만으로도 기록할 수 없다.
- Provider Validator는 제목을 바꾸어 표현할 수 있지만 PAJIN은 안정적인 코어 소유 주장과 증거
  신원을 유지한다.
- Candidate 복구는 의도적으로 부분적이다. 지원되지 않는 Tool 계열은 Mode 소유의 형식화된
  Producer를 얻을 때까지 여전히 Validator에 의해 누락될 수 있다.
- Candidate 레코드는 검증 전 메모리에서 생성되거나 실패/취소된 최종화 중 사용 가능한 결과에서
  복원되어 최종 스냅숏과 함께 봉인된다. Validator 이전의 물리적 불변성을 증명하려면 향후 중간
  증거/입장 봉인이 여전히 필요하다.

## 검증

Candidate 입장 테스트는 다음을 입증해야 한다.

- 실제 카탈로그 트랜스크립트는 Validator가 `[]`를 반환해도 Candidate를 생성하며,
  `findings.json`은 빈 상태로 유지된다.
- 일치하는 Semantic Validator 근거와 객관적 증거 검사는 Candidate를 보존하지만 최신
  ReplayOutcome 없이는 ADR 0027 확인 경계를 충족하지 않는다.
- 카탈로그 표지가 없는 위조 Worker 판정 필드는 Candidate를 생성하지 않는다.
- 변조된 턴 또는 검사, 신원 불일치, 비네트워크 결과, 누락된 증거, 중복 요청 신원은 입장 또는
  객관적 검증에 실패한다.
- 불일치하는 Validator 주장은 Candidate 증거를 재사용해 확인된 레거시 Candidate를 생성할 수
  없지만, 불일치 출력 자체는 검토 가능하게 유지된다.
- Validator 전용 확인은 다른 증거 참조, 수정된 카탈로그 Plan, 빈 Campaign 위협 목록 또는
  선언되지 않은 위협 레이블을 통해 빈 Producer 결과를 우회할 수 없다.
- 취소 및 Validator 실패 시 사용 가능한 Candidate가 봉인된 `inconclusive` Decision으로
  유지된다.
- 기존 Local, Multi-Agent, KISA 재시험, Bug Bounty, CTF, 보고, 무결성 계약이 호환성을
  유지한다.

Restricted Reproducer 마이그레이션은 성공한 Candidate 결합 ReplayOutcome과 객관적 게이트만
확인 프로젝션을 생성한다는 점도 입증해야 한다. 테스트는 이제 ReplayOutcome 없는 의미론적
근거가 `findings.json` 밖에 남아야 하며, 과거 봉인된 Run은 다시 쓰지 않고 레거시 해석을
유지하도록 요구한다.

## 참고 자료

- [ADR 0004: 동적 멀티 에이전트 실행과 권한 축소 위임](0004-dynamic-multi-agent-execution.ko.md)
- [ADR 0016: 변조 방지 Run 무결성 체인](0016-tamper-evident-run-integrity.ko.md)
- [ADR 0025: Candidate 검증 원장과 재실행 경계](0025-candidate-validation-ledger-and-replay-boundary.ko.md)
- [ADR 0027: 확인 경계로서의 독립적인 제한적 재현](0027-independent-reproduction-confirmation-boundary.ko.md)
