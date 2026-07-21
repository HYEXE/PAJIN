# ADR-0002: Tool Gateway와 Docker Worker 격리

- 상태: Accepted
- 날짜: 2026-07-12

## Context

PAJIN 에이전트는 향후 MCP, 보안 CLI, 브라우저, 코드 실행기를 사용할 수 있다. 에이전트나
개별 Tool Adapter가 프로세스와 컨테이너를 직접 실행하도록 허용하면 Scope, Capability,
예산, 증적 수집을 우회할 수 있다. 또한 모델이 생성한 도구 이름·인자·이미지는 신뢰할 수 없는
입력이다.

## Decision

1. 모든 Tool Invocation은 단일 `ToolGateway`를 통과한다.
2. Tool Adapter는 직접 실행하지 않고 `WorkerJob`을 준비하고 `WorkerResult`를 해석한다.
3. Tool Gateway는 실행 전에 Authorization, Scope, Capability, Risk, Method, Budget 정책을
   검사한다.
4. 등록되지 않은 도구와 allowlist에 없는 이미지는 Worker dispatch 전에 거부한다.
5. Docker Worker는 다음 고정 통제를 적용한다.
   - `--network none`
   - `--read-only`
   - `--cap-drop ALL`
   - `--security-opt no-new-privileges`
   - 비루트 UID/GID `65532`
   - CPU, 메모리, PID 및 실행시간 제한
   - 크기가 제한된 `/workspace`, `/tmp` tmpfs
   - stdout 및 stderr 수집 크기 제한
   - `--pull never`와 이미지 allowlist
6. Timeout 발생 시 Docker 클라이언트 프로세스와 컨테이너를 강제 종료한다.
7. 정책 판정, 안전하게 축약한 WorkerJob 메타데이터, WorkerResult, ToolResult를 하나의 증적
   파일에 연결한다.
8. Simulated Worker는 개발·단위 테스트 전용이며 보안 격리로 간주하지 않는다.
9. 일반 `pajin run`과 `pajin multi-run` 명령은 Docker Worker를 기본값으로 사용한다. Simulated
   Worker는 `--worker simulated`를 명시해야만 선택된다.
10. 모든 Local/Multi-Agent Run은 실제 backend instance에서 Worker identity를 파생하여
    `execution-context.json`에 봉인하고, 핵심 field를 `run.json`과 `campaign.started` event에
    반복 기록하며 report에도 표시한다. simulated Run은 항상
    `SIMULATED / NOT REAL TARGET EVIDENCE`로 표시하고 CLI completion line만 권위로 삼지 않는다.
11. Tool Adapter는 성공한 Worker stdout을 완전한 strict JSON object로만 해석한다. stdout이나
    stderr가 잘렸거나, 중복 object key·비유한 수·과도한 depth/node 수가 있으면 fail closed로
    처리한다. 따라서 원본 증적과 정규화된 ToolResult 사이에 last-wins 의미 차이가 생기지 않는다.

## Verification

`pajin worker-check`는 컨테이너 내부 관찰을 통해 다음 항목을 검증한다.

- 비루트 사용자
- 네트워크 차단
- 읽기 전용 루트 파일시스템
- 제한된 workspace 쓰기 가능성
- Linux capability 제거
- `no-new-privileges`
- cgroup 메모리, PID, CPU 제한 관찰
- timeout 강제 종료
- 일반 Run 명령의 Docker 기본값과 명시적 simulated opt-in
- 봉인된 execution context, Run summary, start event, report의 일치하는 backend identity
- simulated CLI와 report의 명확한 개발 전용 경고
- 중복 key, 잘린 transcript, 과도한 JSON tree를 거부하는 공통 Adapter decoder

## Consequences

### Positive

- 에이전트와 Tool Adapter가 정책 검사를 우회할 수 없다.
- Docker 명령은 인자 배열로 구성되어 셸 문자열 주입 위험을 줄인다.
- 외부 도구 실패와 정책 거부가 동일한 감사·증적 흐름에 남는다.
- 향후 Docker 외 원격 Worker도 동일한 `WorkerBackend` 계약을 구현할 수 있다.

### Negative

- 현재 Docker 모드는 네트워크를 완전히 차단하므로 실제 대상 테스트를 수행할 수 없다.
- 대상 단위 egress 제어를 위해 별도의 네트워크 프록시 또는 네트워크 정책 계층이 필요하다.
- 개발 이미지는 `pajin-worker:dev` 태그를 사용하며 배포 단계에서는 digest 고정과 서명 검증이
  추가로 필요하다.
- Docker daemon 자체는 높은 권한을 가지므로 전용 Worker 호스트 또는 강화 런타임이
  필요하다.

## Next

다음 단계에서는 대상 allowlist를 강제하는 egress proxy와 MCP Adapter를 구현한다. MCP
서버는 에이전트에 직접 노출하지 않고 Tool Gateway 뒤에서만 호출한다.
