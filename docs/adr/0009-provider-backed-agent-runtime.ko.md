> Languages: [English](0009-provider-backed-agent-runtime.en.md) | [한국어](0009-provider-backed-agent-runtime.ko.md)

# ADR-0009: 추론 역할을 위한 정책 결속형 Provider Runtime

- 상태: 승인됨
- 날짜: 2026-07-12
- 확인 의미론 개정: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)

> Provider Validator 출력은 의미 기반 증거 심사다. ADR 0027은 별도로 성공한 Candidate-bound
> ReplayOutcome 없이 제품 수준의 `confirmed`를 생성하는 것을 금지한다.

## 배경

PAJIN의 동적 팀은 원래 결정론적 Planner와 Validator 구현을 사용하고 Reporter는 정규 상태를
직접 렌더링했다. ADR-0008의 Provider Gateway는 안전한 모델 전송을 제공했지만 멀티 Agent
워크플로를 모델 주도로 만들지는 않았다. 모델 SDK를 역할에 직접 연결하면 Tool Gateway 정책,
Capability 회계, Docker 격리, egress 증적, Secret Lease, campaign 취소와 PAJIN의 비용 통제를
우회하게 된다.

OpenAI Chat Completions Structured Outputs는 `strict = true`와 함께
`response_format.type = json_schema`를 사용한다. Strict output은 제공된 스키마를 따르지만, 모델의
거부 응답은 별도로 반환되므로 요청한 객체로 parse하면 안 된다. Chat Completions는 prompt,
completion, 전체 token 사용량도 반환한다. PAJIN은 공급자 중립 domain 계층을 유지하면서 문서화된
이러한 wire 계약을 따른다. 공식
[Structured Outputs 가이드](https://developers.openai.com/api/docs/guides/structured-outputs)와
[Chat API 참조](https://developers.openai.com/api/reference/resources/chat)를 참고한다.

## 결정

### 모델 호출은 계속 Tool 호출로 유지한다

Planner, Validator, Reporter는 SDK나 HTTP client를 직접 호출하지 않는다. 각 역할 경계에서
Supervisor는 다음을 수행한다.

1. 역할 Agent를 만들고 등록된 Provider Tool, 정확한 Provider endpoint, T1 위험, 최대 두 번의
   호출만 포함하는 Capability를 위임한다.
2. Run 범위의 `PolicyBoundProviderPort`를 해당 역할에 binding한다.
3. 공격 표적 Scope와 분리된 Provider 전용 control-plane Scope를 구성한다.
4. 각 모델 요청을 Tool Gateway, Docker Worker, egress proxy와 일회용 Secret Lease를 통해
   dispatch한다.
5. Worker가 실제로 dispatch된 경우에만 역할 Capability, 상위 Capability, Tool 예산과 모델
   예산을 소비한다.

Supervisor root grant에는 선언된 공격 표적과 신뢰하는 등록 Provider endpoint가 모두 들어
있지만, 하위 grant는 둘을 함께 포함하지 않는다. Specialist는 공격 Tool 하나와 선언된 표적
하나를 받는다. 추론 역할은 Provider Tool 하나와 Provider endpoint 하나를 받는다.

### 역할 격리와 strict draft

각 모델 호출에는 정확히 두 개의 메시지가 들어간다.

- 고정된 Planner, Validator 또는 Reporter 역할 계약을 담은 신뢰하는 `developer` 메시지
- 정규 campaign 또는 Run 데이터를 JSON으로 담은 신뢰하지 않는 `user` 메시지

모델은 PAJIN의 전체 내부 상태가 아니라 역할별 strict draft를 반환한다.

- Planner는 `arguments_json`이 포함된 제한된 step을 반환한다. PAJIN은 JSON을 parse하고 새로운
  `ToolRequest` 객체를 구성한다.
- Validator는 기존의 동일 Run 증적, 선언된 표적, `validated` 검사를 모두 통과하는 Candidate
  Finding을 반환한다.
- Reporter는 제한된 narrative 보충 자료를 반환한다. 정규 보고서와 Finding은 결정론적으로
  유지하며 narrative는 `model-narrative.json`에 별도로 영구 저장한다.

Supervisor는 Agent fan-out 전에 Planner 출력을 다시 검증한다. 선언되지 않은 표적, 미등록 Tool,
Provider control-plane Tool과 지원하지 않는 메서드는 fail closed로 처리한다.

### 재시도, fallback과 거부 동작

Provider 전송 실패, 명시적 거부, 유효하지 않은 JSON 또는 스키마에 맞지 않는 역할 출력은 고정된
수정 지시와 함께 한 번 재시도할 수 있다. 제한된 시도가 끝나면 Planner와 Validator는 설정된
결정론적 runtime을 사용하고 Reporter는 결정론적 narrative를 사용한다. 모든 fallback은 감사
이벤트다.

`BudgetExceeded`, 만료되거나 소진된 Capability lineage, Kill Switch 활성화와 campaign 기간
만료는 모델 실패가 아니다. 이러한 상태는 fallback을 우회하고 campaign을 중단한다.

### 사용량과 비용 예산

Campaign 예산에는 `maxModelCalls`와 `maxModelTokens`가 추가된다. dispatch된 모든 모델 호출은
`maxToolCalls`에도 합산된다. 모델 기반 역할에는 완전한 Provider 사용량 정보가 필요하며,
token 합계가 일관되지 않거나 누락되면 모델 호출 실패다. Prompt token과 completion token은
별도로 기록한다. 비용은 신뢰하는 `ProviderRegistration`이 명시적으로 제공한 요율로만 계산하며,
PAJIN은 현재 공급자 가격을 추론하지 않는다. 실제 비용은 기존 `maxCostUsd` 제한에 반영된다.

## 결과

### 장점

- 통제되지 않는 두 번째 네트워크 경로를 만들지 않고 동적 팀을 모델 주도로 전환한다.
- 역할 프롬프트, 스키마, Capability, 증적과 사용량을 독립적으로 감사할 수 있다.
- Campaign 또는 Tool 데이터의 prompt injection이 신뢰하는 역할 지시를 직접 대체할 수 없다.
- 모델이 만든 Finding과 narrative는 정규 동일 Run 검증을 우회할 수 없다.
- 재시도는 계속 제한되며 예산, Capability 또는 취소 통제를 피할 수 없다.

### 절충점과 잔여 위험

- Provider가 잘못된 사용량을 보고할 수 있다. 운영 통합에서는 PAJIN telemetry를 공급자 billing
  및 rate-limit 데이터와 대조해야 한다.
- OpenAI 호환 공급자마다 정확한 Structured Output 스키마 지원이 다르므로 각 Provider 등록에
  적합성 테스트가 필요하다.
- Developer/user 메시지 분리는 지시 혼동을 줄이지만 prompt injection을 없애지는 못한다.
  따라서 Planner 의미론, 인용한 증적, 표적/Tool 경계는 계속 결정론적으로 검사해야 한다.
- Fallback 출력은 모델 출력과 다를 수 있다. 혼합 모드 Run을 식별할 수 있도록 보고서와
  이벤트에 fallback을 명시적으로 기록한다.
- 현재 모델 호출은 Chat Completions를 사용한다. 역할 계약을 바꾸지 않고 별도의 Provider 전송
  방식으로 Responses API Adapter를 도입해야 한다.

## 검증

Unit 및 integration test는 strict 응답 스키마, 유효하지 않은 스키마의 재시도, 제한된 Provider
실패 fallback, 우회할 수 없는 예산 소진, 역할 프롬프트 분리, Provider 전용 역할 Capability,
동일 Run Finding 증적, 사용량/비용 회계, Lease 폐기와 자격증명 Artifact 검사를 다룬다.

Docker lab은 다음 순서를 실행한다.

```text
Provider Planner
  -> ai.chat-probe Specialist through attack Scope
  -> Provider Validator with same-run evidence
  -> canonical finding acceptance
  -> Provider Reporter subordinate narrative
```

네 호출 모두 동일한 Tool Gateway와 Docker egress 메커니즘을 사용하며, Provider 호출 세 개는
각각 별도의 일회용 Secret Lease와 역할별 Capability를 받는다.

```powershell
.venv\Scripts\ruff check .
.venv\Scripts\mypy src
.venv\Scripts\pytest -q
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1'
.venv\Scripts\pajin provider-agent-run examples\provider-agent-lab.yaml `
  --worker docker --allow-private-provider
docker compose -f containers/compose.ai-lab.yaml down
```
