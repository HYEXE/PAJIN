> Languages: [English](0008-provider-gateway-and-secret-leases.en.md) | [한국어](0008-provider-gateway-and-secret-leases.ko.md)

# ADR-0008: OpenAI 호환 Provider Gateway와 Secret Lease

- 상태: 승인됨
- 날짜: 2026-07-12

## 배경

PAJIN Agent에는 모델 접근 권한이 필요하지만, 공급자 endpoint, 모델 선택, 자격증명 또는 임의
함수 실행에 관한 권한까지 부여해서는 안 된다. 공급자 키를 Agent 상태, 계획, Tool 인자,
Docker 환경 변수 또는 증적을 통해 전달하면 프롬프트와 감사 Artifact가 자격증명 유출 경로가
된다. 공급자별 SDK 객체도 공급자 의미론을 오케스트레이션과 검증 계층에 노출한다.

OpenAI Chat Completions는 `POST /chat/completions`에서 메시지 목록을 받고 assistant message를
포함한 choices를 반환한다. 스트리밍은 데이터 전용 server-sent event를 사용하며 `[DONE]`으로
끝난다. 함수 호출 인자는 모델이 제공한 JSON 문자열이므로 사용하기 전에 애플리케이션이
검증해야 한다. 이러한 전송 규격 수준의 동작은 공식
[Chat API 참조](https://developers.openai.com/api/reference/resources/chat),
[스트리밍 가이드](https://developers.openai.com/api/docs/guides/streaming-responses),
[함수 호출 가이드](https://developers.openai.com/api/docs/guides/function-calling)에 설명되어 있다.

## 결정

### 신뢰하는 등록 정보와 신뢰하지 않는 요청

`ProviderRegistration`은 신뢰하는 설정이다. 이 설정은 공급자 ID, 정확한 HTTP endpoint,
모델, secret reference, 스트리밍 허용 여부, Lease TTL, 허용 함수 이름을 고정한다. Agent 입력은
정규 메시지, stream flag, 제한된 completion 설정, 등록된 함수 스키마만 포함한다. 알 수 없는
필드, endpoint/model 재정의, 미등록 함수, POST 외 메서드, 표적 불일치는 Worker dispatch 전에
실패한다.

초기 Adapter는 의도적으로 최소 OpenAI 호환 Chat Completions 표면만 대상으로 한다.
Responses API와 공급자별 확장을 지원하려면 별도의 Adapter와 ADR이 필요하다.

### Secret Lease 수명 주기

Supervisor 측 `SecretBroker`는 평문 값을 메모리에 저장하고 PAJIN의 나머지 부분에는 메타데이터만
노출한다. 승인된 각 Worker 실행에서 Tool Gateway는 다음을 수행한다.

1. 1~300초 TTL과 한 번의 materialization 권한을 가진 audience-bound Lease를 발급한다.
2. Lease ID, binding, reference fingerprint, 만료 시각만 기록한다.
3. 정확한 Agent/실행 audience를 대상으로 값을 materialize한다.
4. 값을 별도의 `SecretMaterial` 객체로 Docker backend에 전달한다.
5. 프로세스 실행 직전에 버전이 지정된 stdin envelope을 구성한다.
6. Worker 실행이 끝나면 `finally`에서 Lease를 폐기한다.

평문은 `WorkerJob`, Docker 명령 인자, 환경 변수, Capability 상태, 계획, 이벤트, 보고서 또는
증적에 추가되지 않는다. Worker stdout, stderr, proxy log, 정규화된 Tool 결과와 중첩된 결과
값은 영구 저장 전에 마스킹한다. Campaign을 취소할 때도 활성 Lease를 모두 폐기한다.

### 공급자 응답 정규화

격리된 Worker는 Bearer 자격증명을 추가하고 campaign egress proxy를 통해 고정 요청을 보낸다.
비스트리밍 응답과 SSE delta는 하나의 `ProviderChatResult`가 된다. 스트리밍된 텍스트, 거부
텍스트, 사용량, 종료 이유와 tool call은 byte와 chunk 제한 안에서 누적한다. Tool call은 index
순서로 정렬한다. 인자 fragment는 원본 JSON으로 보존하고, 명시적인 유효성 flag와 함께 별도로
dictionary로 parse한다. Adapter는 tool-call intent만 반환하며 이를 실행하지 않는다.

## 결과

### 장점

- Agent는 자격증명을 다른 endpoint로 보낼 수 없고 미등록 모델을 선택할 수도 없다.
- 공급자별 wire format은 Worker 경계에서 끝난다.
- 모델 접근과 다른 PAJIN Tool에는 동일한 정책, Scope, Capability, 예산, egress, 증적, Kill
  Switch 경로가 적용된다.
- 일회용 단기 자격증명은 값을 감사 데이터에 넣지 않으면서 발급과 폐기 수명 주기를 감사할 수
  있다.
- 악의적이거나 고장 난 공급자 응답이 자격증명을 그대로 돌려줘도 Agent나 Artifact가 확인하기
  전에 마스킹된다.

### 절충점과 잔여 위험

- Python 문자열은 신뢰성 있게 zeroize할 수 없다. 현재 broker는 로컬 runtime에 적합하지만,
  운영 배포에는 platform vault, 격리된 Supervisor, 제한된 진단, 프로세스 수준 강화가 필요하다.
- 정확한 값 일치에 의존하는 마스킹은 변환·인코딩·해싱되거나 일부만 노출된 secret을 찾지
  못한다. 따라서 공급자 자격증명은 범위를 좁게 유지하고 빠르게 교체할 수 있어야 한다.
- 공급자마다 Chat Completions 호환성이 다르다. 지원하지 않는 확장은 그대로 전달하지 않고
  거부하며, 새로운 dialect마다 적합성 테스트가 필요하다.
- proxy는 네트워크 경계에서 범위 밖 redirect를 차단하지만, 공급자 신뢰, 보존, 지역별 처리와
  계약상 데이터 통제는 여전히 배포 책임이다.
- 공급자 함수 호출은 정규화만 한다. 향후 실행 loop는 함수를 실행하기 전에 독립적인 PAJIN
  Tool 조회, 스키마 검증, 정책 평가, Capability 확인과 결과 메시지 결합을 수행해야 한다.

## 검증

결정론적 테스트 모음은 Lease 사용, audience 불일치, 만료, 폐기, 중첩된 값의 마스킹, 고정된
공급자 등록, stdin 전용 주입, Artifact 유출 검사와 스트리밍 tool-call 조립을 다룬다. Docker
검증 campaign은 Specialist Agent 네 개를 추가하고 다음 사항을 검증한다.

- 인증된 비스트리밍 응답 정규화
- egress proxy를 통한 SSE 텍스트와 사용량 정규화
- index 기반 함수 호출 조각 조립과 JSON 검증
- 공급자 측 자격증명 반향을 모의 실행한 뒤 마스킹하는지 여부
- 네 개의 Lease가 발급되고 완전히 소비된 뒤 네 개 모두 폐기되는지 여부
- 어떤 Run Artifact에도 원본 자격증명이 없는지 여부

```powershell
.venv\Scripts\ruff check .
.venv\Scripts\mypy src
.venv\Scripts\pytest -q
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1'
.venv\Scripts\pajin provider-check examples\provider-openai-compatible-lab.yaml --worker docker
```
