> Languages: [English](0003-egress-proxy-and-mcp-boundary.en.md) | [한국어](0003-egress-proxy-and-mcp-boundary.ko.md)

# ADR-0003: Egress Proxy와 등록된 MCP 실행 경계

- 상태: Accepted
- 날짜: 2026-07-12

## 배경

PAJIN 도구에는 승인된 대상에 대한 통제된 접근이 필요하지만, 침해된 에이전트, 프롬프트,
Tool Adapter 또는 MCP 서버가 일반 네트워크나 프로세스 실행 권한을 얻어서는 안 된다.
Docker의 `--network none`은 안전한 기본값이지만 실제 대상 검증을 지원할 수 없다. Worker에
일반 bridge network를 제공하면 캠페인 범위가 네트워크 통제가 아니라 애플리케이션 관례에
불과해진다.

MCP는 두 번째 경계 문제를 추가한다. 에이전트가 서버 명령, 실행 파일 경로 또는 임의의
stdio 인자를 제공할 수 있다면 겉보기에 유효한 MCP 호출이 무제한 프로세스 실행으로
바뀐다.

## 결정

### 네트워크 송신

1. Tool Adapter는 항상 네트워크가 비활성화된 `WorkerJob`을 준비한다. Tool Gateway는
   네트워크 모드나 egress 정책을 자체 부여하려는 모든 Adapter를 거부한다.
2. `network_access=true`인 등록된 `ToolSpec`에 대해 Tool Gateway는 승인된 캠페인의 허용
   범위, 거부 범위, 허용 메서드 및 사설 네트워크 규칙으로 `EgressPolicy`를 생성한다.
3. 모든 네트워크 실행에는 새 Docker `--internal` 네트워크가 할당된다. Worker는 해당
   네트워크에만 참여하고 HTTP(S) 프록시 환경 변수를 받는다.
4. 비루트, 읽기 전용, capability가 없는 전용 프록시 컨테이너가 내부 네트워크와 구성된
   외부 Docker 네트워크 모두에 참여한다. 실행이 끝나면 내부 네트워크와 함께 제거된다.
5. 프록시는 요청 URL을 파싱하고, 허용보다 거부 규칙을 먼저 적용하고, DNS를 확인하며,
   금지된 주소가 하나라도 있으면 전체 결과를 거부한 뒤 검증된 리터럴 주소에 연결한다.
6. 사설, loopback, link-local, multicast, unspecified 및 reserved 주소는 기본적으로 거부된다.
   사설 대상에는 명시적인 캠페인 교전 규칙이 필요하다.
7. 프록시의 허용, 거부 및 타입이 정해진 오류 이벤트는 Worker 증적에 첨부된다. 쿼리 값과
   raw exception text는 보관하지 않는다.
8. 평문 HTTP 요청에는 메서드, authority, 경로, 쿼리 정책 및 대상 IP 전체 검사가 적용된다.
   HTTPS는 종단 간 암호화를 유지하므로 프록시는 CONNECT authority만 집행할 수 있다.
   호스트 전체에 적용되는 `/*` 또는 `/**` allow rule만 허용하고, 해당 authority를 대상으로
   하는 deny rule이 하나라도 있으면 전체 authority를 거부한다. 정확한 HTTPS method와 path는
   proxy inspection이 아니라 Gateway에 결박된 고정 Worker action에서 온다. CONNECT event는
   `receiptEligible=false`이며 `methodEnforcement=trusted-worker-only`와
   `pathEnforcement=authority-only`를 명시하므로 request/response receipt가 아니다. PAJIN은
   TLS를 가로채지 않는다.

### MCP 실행

1. 호스트 측 MCP 도구는 정규 `ToolSpec` 항목으로 등록되고 일반 Policy Engine과 Tool
   Gateway를 계속 통과한다.
2. 등록된 Adapter는 Worker action `mcp-call`에 `serverId`, `toolName`, `arguments`만 보낼 수
   있다. 실행 파일 경로나 서버 인자는 보낼 수 없다.
3. Worker는 ID를 명령 및 허용 목록에 포함된 도구 이름에 매핑하는 별도의 고정 서버
   카탈로그를 소유한다. 알 수 없는 서버와 도구는 fail closed 방식으로 거부한다.
4. Worker bridge는 공식 MCP Python SDK v1을 사용하고 stdio 세션을 초기화한 뒤
   `list_tools`를 확인하며, 서버가 해당 도구를 알릴 때만 등록된 도구를 호출한다.
5. MCP SDK 의존성은 Python 3.12를 기준으로 해석되고, SDK 버전은 v2 미만으로 고정되며
   platform marker와 전이 의존성을 포함해 hash-lock된다. Docker build는 설정된 package
   index 또는 cache에서 binary wheel을 내려받고 선택된 모든 distribution hash의 일치를
   요구하며 TLS 검증을 비활성화하지 않는다. lock 기준으로 재현 가능하지만 offline build는
   아니다.
6. Worker는 bridge의 stdout과 stderr를 동시에 끝까지 비우되 각 스트림에서 고정 크기
   prefix만 보관한다. 어느 한쪽이라도 상한을 넘으면 fail closed로 처리하고, timeout이나
   취소가 발생하면 action을 반환하기 전에 bridge 프로세스 그룹을 종료한다.
7. 호스트 Adapter는 엄격한 bridge envelope만 수용한다. `isError`는 실제 boolean이어야
   하고 content는 타입과 크기가 제한된다. 중복 JSON key와 예약된 식별자 필드는 거부하며,
   target·server·tool 식별자는 요청과 봉인된 등록 정보에서만 생성한다.

## 결과

### 장점

- destination authority, DNS 결과, 평문 HTTP 범위는 Tool Gateway와 네트워크 경계 모두에서
  강제된다. 정확한 HTTPS request는 신뢰된 고정 Worker action에 계속 결박된다.
- Worker의 직접 소켓은 내부 Docker 네트워크를 통해 프록시를 우회할 수 없다.
- 금지된 주소를 향하는 DNS rebinding은 연결 전에 거부된다.
- 에이전트가 MCP 등록을 임의 프로세스 실행으로 바꿀 수 없다.
- 모든 실제 네트워크 판정과 MCP 결과를 캠페인 증적에서 재현할 수 있다.

### 절충점과 잔여 위험

- 프록시에는 HTTPS method와 path 세부 정보가 보이지 않는다. 따라서 host-wide 승인이
  필요하고 path별 HTTPS deny rule은 전체 authority에 대해 fail closed하며, CONNECT event는
  암호화된 어떤 request가 전송됐는지 attest할 수 없다. 신뢰된 고정 Worker action의 침해는
  이 proxy의 method/path 집행 경계 밖이다.
- Proxy policy JSON, response buffering, JSON receipt parsing은 크기가 제한된다. 고정 64 MiB
  proxy container가 허용하는 response 상한은 8 MiB이며, 더 큰 설정은 eventual OOM kill에
  의존하지 않고 validation에서 거부된다.
- 로컬 Docker daemon과 외부 Docker 네트워크는 계속 신뢰 인프라로 남는다. 운영 배포에는
  강화된 원격 Worker plane, 이미지 digest와 서명, 호스트 방화벽 통제가 필요하다.
- 호스트와 Worker의 MCP 카탈로그는 서로 달라질 수 있다. 런타임 `list_tools` 검증은 누락된
  도구를 찾아내지만, 향후 서명된 registry가 검토된 단일 출처에서 두 카탈로그를 모두
  생성해야 한다.
- 개발 프록시는 제한된 HTTP/1.1과 CONNECT를 지원한다. 범용 forward proxy가 아니며 UDP와
  임의 TCP 같은 프로토콜은 의도적으로 제외한다.

## 검증

다음 검사는 이 결정의 인수 증적을 구성한다.

```powershell
.venv\Scripts\pajin egress-check
.venv\Scripts\pajin run examples\egress-proxy.yaml --worker docker
.venv\Scripts\pajin run examples\mcp-tool.yaml --worker docker
.venv\Scripts\pajin mcp-check
.venv\Scripts\pytest -q
```

Docker 검증에서는 허용 목록의 요청이 성공하고, 거부된 authority가 차단되며, 직접 소켓
우회가 막히고, CONNECT evidence가 request receipt로 명시적으로 부적격 상태를 유지하며,
등록된 MCP 도구가 검증된 Finding 하나를 생성하고, 잔여 PAJIN 컨테이너나 실행별 네트워크가
없어야 한다.
