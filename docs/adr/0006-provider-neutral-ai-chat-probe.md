# ADR-0006: 공급자 중립 AI Chat Probe와 격리형 검증 표적

- Status: Accepted
- Date: 2026-07-12
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)

> 이 문서의 Validator는 원 transcript를 재검산하는 증거 심사 경계다. ADR 0027 이후 제품
> 수준의 Confirmed에는 별도 Restricted Reproducer의 새 요청·증적과 Oracle 성공이 필요하다.

## Context

KISA Mode Pack의 첫 시나리오는 네트워크를 사용하지 않는 `mock-agent`로 A01·A02 경계를
검증했다. 시스템 프롬프트 유출(M03), 탈옥(M06), 메모리 오염(A04)은 실제 멀티턴 AI 응답과
세션 상태를 관찰해야 한다. 특정 모델 공급자의 SDK나 인증 형식을 Mode Pack에 직접 넣으면
시나리오·정책·증적이 공급자에 종속되고, 에이전트가 임의 HTTP 헤더나 실행 명령을 구성할
위험도 커진다.

개발과 회귀 테스트에는 실제 공격 신호를 결정론적으로 재현하면서도 외부 서비스나 실제
사용자 데이터에 접촉하지 않는 격리형 표적도 필요하다.

## Decision

### 공급자 중립 계약

1. PAJIN은 `sessionId`, `messages`, `metadata`를 받으며 구조화된 assistant message, safety,
   tool call, memory write 메타데이터를 반환하는 고정 Chat API 계약을 정의한다.
2. 등록 Tool `ai.chat-probe`만 이 계약을 호출한다. 에이전트는 임의 명령, 임의 헤더, URL
   자격증명, 네트워크 정책을 제공할 수 없다.
3. Probe 입력은 시나리오 ID, 단일 KISA 위협, 세션 ID, 최대 20개 턴, 최대 20개 판정 조건의
   엄격한 타입으로 검증된다.
4. Tool Adapter는 항상 network-none Worker Job을 준비한다. Tool Gateway만 Campaign
   Scope와 교전 규칙에서 egress proxy 정책을 주입한다.
5. Worker는 응답 크기와 시간을 제한하고 원문 요청·응답, 판정 결과, 실제 표적 응답 지연을
   구조화된 증적으로 반환한다.

### 독립 판정

1. Worker는 카탈로그 판정 조건을 적용해 관찰 결과를 만들지만, 이를 최종 Finding으로
   확정할 수 없다.
2. Validator는 계획의 원본 Probe 조건과 ToolResult의 실제 transcript를 다시 비교한다.
3. `vulnerable=true`라도 응답에 시나리오 마커가 없거나 시나리오·위협·세션이 불일치하면
   Finding을 생성하지 않는다.
4. 같은 시나리오의 반복 Finding은 기존 KISA deduplication 단계에서 합치고 모든 독립
   Worker 증적을 보존한다.

### 격리형 AI 표적

1. `pajin-ai-target:dev`는 M03·M06·A04 신호를 결정론적으로 재현하는 의도적 취약
   개발 표적이다.
2. 표적은 별도 컨테이너에서 non-root, read-only filesystem, all capabilities dropped,
   no-new-privileges, CPU·메모리·PID 제한으로 실행한다.
3. 포트는 host loopback에만 게시한다. Worker는 직접 연결하지 않고 Campaign이 허용한
   `host.docker.internal` 경로를 egress proxy로만 사용한다.
4. 각 반복은 고유 세션을 사용해 메모리 상태가 다른 Task로 누출되지 않게 한다.
5. `hardened` profile은 세 신호를 모두 차단해 향후 재검증과 방어 회귀 기준으로 사용한다.

## Consequences

### Positive

- KISA 시나리오가 특정 LLM SDK와 분리된다.
- 실제 HTTP·멀티턴·세션 상태와 egress 정책을 하나의 Docker 캠페인에서 검증한다.
- Tool이 결과 플래그를 조작해도 transcript 없는 Finding은 확정되지 않는다.
- 취약·강화 프로필이 동일 계약을 사용해 수정 전후 회귀 테스트 기반이 된다.
- 지표의 응답 지연은 Docker와 proxy 시작 시간이 아니라 실제 표적 응답 시간을 사용한다.

### Trade-offs and residual risks

- 실제 공급자 API에는 인증, 스트리밍, rate limit, 고유 tool-call 스키마를 변환하는 별도
  Adapter가 필요하다.
- 문자열 마커 판정은 결정론적 회귀에는 적합하지만 의미 기반 탈옥과 부분 유출을 모두 찾지
  못한다. 분류기·LLM Judge·변형 데이터셋을 추가해야 한다.
- 개발 표적은 실제 모델이 아니며 외부 서비스의 비결정성, 토큰 비용, 장문 컨텍스트를
  대표하지 않는다.
- transcript에는 민감 응답이 포함될 수 있으므로 운영 Artifact 암호화·마스킹·보존 정책이
  필요하다.

## Verification

```powershell
docker build --tag pajin-worker:dev containers/worker
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml down
.venv\Scripts\pytest -q
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

당시 구현 인수 조건은 M03·M06·A04 여섯 Specialist Task, 100% 요청 위협 커버리지, legacy
validation Finding 세 건, Finding별 두 Docker 증적, 모든 호출의 egress proxy allow 기록, 표적 응답 지연
측정, 조작된 vulnerability flag 거부, 종료 후 임시 컨테이너·네트워크 정리다.
이 세 Finding은 ADR 0027의 Restricted Replay 전까지 제품 수준의 Confirmed가 아니다.
