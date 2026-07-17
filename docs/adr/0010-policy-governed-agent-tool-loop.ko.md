> Languages: [English](0010-policy-governed-agent-tool-loop.en.md) | [한국어](0010-policy-governed-agent-tool-loop.ko.md)

# ADR-0010: 정책 통제형 반복 Agent Tool Loop

- 상태: 승인됨
- 날짜: 2026-07-12

## 배경

ADR-0009는 PAJIN 추론 역할을 통제된 Provider에 연결했지만, 역할 출력은 하나의 strict 객체였다.
자율 보안 작업에는 반복적인 데이터 수집도 필요하다. 모델이 Tool을 요청하고 결과를 받은 다음
완료하거나 다른 Tool을 요청하는 방식이다. Provider 함수 호출을 실행 권한으로 취급하면 모델
출력이 Tool Registry, Scope, Capability attenuation, 위험 정책, 승인, 예산과 Worker 격리를
우회할 수 있다.

공식 OpenAI 함수 호출 흐름은 명시적으로 애플리케이션을 매개로 한다. 사용 가능한 Tool 정의를
보내고, Tool 호출을 받고, 애플리케이션 코드를 실행하고, 일치하는 call ID와 함께 결과를 반환한
뒤 최종 응답이나 추가 호출을 받는다. 각 호출을 routing하고 실행할 책임은 계속 애플리케이션에
있다. Chat Completions에서는 병렬 호출을 비활성화할 수 있으며 strict 함수에는 선언된 모든
property와 `additionalProperties: false`가 필요하다. 공식
[함수 호출 가이드](https://developers.openai.com/api/docs/guides/function-calling)를 참고한다.

## 결정

### 함수 호출은 Capability가 아니라 intent다

Provider 함수 이름은 신뢰하는 `ToolLoopBinding` record를 통해 정확히 하나의 PAJIN Tool, 표적,
HTTP 메서드, 설명과 strict 인자 스키마에 매핑된다. 모델은 Tool ID, 표적 URL, 메서드, 위험 등급,
Agent ID, 컨테이너 이미지, 명령, 자격증명 또는 egress 정책을 제공하거나 재정의할 수 없다.

각 Provider 호출에서 PAJIN은 등록된 strict 함수 스키마를 `parallel_tool_calls = false`와 함께
보낸다. 함수 호출이 없거나 하나만 포함된 응답만 허용한다. Supervisor는 다음을 요구한다.

- 등록된 함수 binding과 PAJIN Tool
- Worker가 이미 정규화한 유효한 JSON 객체 인자
- control-plane Provider Tool이 아닌 Tool
- 이전 loop에서 나타나지 않은 호출 fingerprint
- 남아 있는 turn, Agent, Tool, Model, token, 비용, 기간과 Capability 예산

Fingerprint는 함수 이름, PAJIN Tool ID, 고정 표적, 메서드와 정규 인자를 포함한다. 같은 동작의
반복은 무한히 재시도하지 않고 차단한다.

### Specialist 정책 경계 재진입

Tool Loop Supervisor는 등록된 Provider와 binding된 Tool 권한을 포함한 root Capability를
소유한다. 모델을 대면하는 Agent는 Provider Tool과 endpoint만 받는다. 허용된 각 intent는 매핑된
PAJIN Tool, 고정 표적, 관찰된 위험 등급과 한 번의 호출만 포함한 새로운 Specialist Agent와 하위
Capability를 생성한다.

Specialist 요청은 일반 Tool Gateway, Campaign 인가, Scope, 메서드, 금지 사항, 위험, egress,
Docker Worker, 증적과 Secret Lease 경계를 통과한다. 정책 거부는 Tool 결과로 표현하며,
Provider는 직접 실행 권한을 받지 않는다.

실행 후 PAJIN은 원본 assistant Tool 호출과 정확한 `tool_call_id`를 사용하는 제한된 `tool`
메시지를 추가한다. 너무 큰 Tool 데이터는 상태, 오류, 증적 참조와 잘림 marker를 담은 유효한
JSON 요약으로 대체한다.

### 종료 통제

Loop는 다음 상태 중 하나로 종료한다.

- `completed`: Provider가 다른 Tool 호출 없이 최종 콘텐츠를 반환한다.
- `awaiting-approval`: T3/T4 intent를 Worker dispatch 전에 checkpoint에 기록한다.
- `denied`: Provider가 거부하거나 제공된 승인이 대기 중인 intent와 일치하지 않는다.
- `budget-exhausted`: turn, Agent, Tool, Model, token, 비용 또는 기간 예산이 진행을 중단한다.
- `failed`: 형식 오류, 병렬 호출, 알 수 없는 상태, 중복 또는 그 밖의 유효하지 않은 상태다.

Provider와 Tool 호출은 모두 공유 `maxToolCalls` 예산을 소비한다. Provider 호출은 모델 호출,
token과 비용 예산도 추가로 소비한다. 모델 실패는 Tool Loop 상태나 예산을 절대 초기화하지 않는다.

### 승인 경계

T0-T2 Tool은 Campaign 위험 정책을 따른다. T3와 T4에는 정확한 호출 fingerprint, Tool ID, 표적,
승인자 신원, 승인 시각과 만료에 binding된 `ToolLoopApproval`이 필요하다. 승인이 없으면 Run은
`awaiting-approval`에서 멈추며 Specialist나 Worker를 만들지 않는다. 승인 record가 제공됐지만
대기 중인 intent를 허용하는 항목이 없으면 continuation은 `denied`다.

포함된 `mock.approval-probe`는 안전하고 결정론적인 작업을 수행하지만, 이 통제를 검증하기
위해서만 T3를 부여했다. 이 Tool은 로컬 CLI 승인자 문자열을 운영 인증과 동등하게 만들지 않는다.
운영 배포에는 인증된 승인 서비스와 서명됐거나 그 밖의 방법으로 무결성이 보호된 승인 record가
필요하다.

### Checkpoint와 continuation

의미 있는 상태 전환마다 변경할 수 없고 버전이 지정된 새 checkpoint를 기록한다. 여기에는
메시지, 확인한 호출 fingerprint, 대기 중인 intent, Tool 결과, 승인 ID, 최종 콘텐츠/오류와 누적
예산 snapshot이 포함된다. Secret 값과 Secret reference는 제외한다.

`awaiting-approval` checkpoint만 재개할 수 있다. 재개하면 `resumed_from_run_id`로 연결된 새로운
continuation Run을 생성하고, Agent/Tool/Model/token/비용/경과 시간 사용량을 복원하고, 새로운
Capability를 재구성하고, 승인된 경우 대기 중인 정확한 intent를 실행한 뒤 대화를 계속한다.
Continuation은 예산을 초기화하거나 다른 호출로 대체할 수 없다. Continuation 생성은 원본
checkpoint를 원자적으로 claim한다. claim된 checkpoint는 다시 재개할 수 없으므로 승인과 부수
효과의 replay를 방지한다.

## 결과

### 장점

- 멀티턴 자율 작업은 일반 Tool 실행과 동일한 결정론적 보안 경계를 재사용한다.
- 모델 출력은 인프라 수준의 실행 세부 정보를 선택하거나 Scope를 몰래 넓힐 수 없다.
- 중복 호출과 병렬 fan-out은 부수 효과를 늘릴 수 없다.
- T3/T4 작업은 dispatch 전에 일시 중지되며 감사 가능한 상태에서 재개할 수 있다.
- Checkpoint는 자격증명을 영구 저장하지 않으면서 crash 복구와 외부 승인 워크플로를 지원한다.

### 절충점과 잔여 위험

- 현재 checkpoint 무결성과 일회성 claim은 로컬 filesystem 무결성에 의존한다. 운영
  continuation에는 인증된 저장소, 서명 또는 MAC, 모든 replica가 공유하는 트랜잭션 replay
  ledger가 필요하다.
- 초기 loop는 의도적으로 turn마다 하나의 함수 호출만 허용한다. 병렬 실행에는 별도의 dependency,
  conflict와 aggregate-approval 설계가 필요하다.
- Tool 출력은 계속 신뢰하지 않는 모델 입력이며 prompt injection을 포함할 수 있다. Developer 역할
  계약과 결정론적 Supervisor 경계는 모든 turn에서 필수다.
- Provider가 보고한 token 사용량은 부정확할 수 있으므로 billing telemetry와 대조해야 한다.
- 승인 만료는 continuation 시점에 검사한다. 장시간 실행되는 외부 승인 워크플로에는 시각 동기화와
  명시적 폐기 지원이 필요하다.

## 검증

테스트는 성공적인 Tool 호출/결과/최종 응답 흐름, strict 스키마, 병렬 호출 비활성화, 일치하는
call ID, 정확한 Specialist Capability, 중복 차단, turn 예산 소진, T3 승인 대기, 잘못된 표적
승인 거부, 누적 예산 복원, continuation Run 연결, Lease 폐기와 Run 간 자격증명 검사를 다룬다.

Docker 검증은 두 시나리오를 사용한다.

```powershell
.venv\Scripts\pajin tool-loop-run examples\tool-loop-lab.yaml `
  --worker docker --allow-private-provider
.venv\Scripts\pajin tool-loop-approval-check examples\tool-loop-approval-lab.yaml `
  --worker docker --allow-private-provider --approved-by local-security-owner
```

첫 번째 시나리오는 두 turn 안에 Provider → Specialist → Provider를 완료한다. 두 번째는 승인 전
Worker dispatch가 0건임을 증명한 다음 연결된 Run을 재개하고 T3 lab Tool을 정확히 한 번 실행한다.
