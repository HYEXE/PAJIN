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
7. 프록시의 허용, 거부 및 오류 이벤트는 Worker 증적에 첨부된다. 쿼리 값은 마스킹된다.
8. HTTP 요청에는 메서드, authority, 경로, 쿼리 정책 및 대상 IP 전체 검사가 적용된다.
   HTTPS는 종단 간 암호화를 유지한다. CONNECT는 호스트 전체에 적용되는 `/*` 또는 `/**`
   규칙으로만 허용되며, 해당 authority에 대한 거부 규칙이 하나라도 있으면 터널 전체를
   거부한다. PAJIN은 TLS를 가로채지 않는다.

### MCP 실행

1. 호스트 측 MCP 도구는 정규 `ToolSpec` 항목으로 등록되고 일반 Policy Engine과 Tool
   Gateway를 계속 통과한다.
2. 등록된 Adapter는 Worker action `mcp-call`에 `serverId`, `toolName`, `arguments`만 보낼 수
   있다. 실행 파일 경로나 서버 인자는 보낼 수 없다.
3. Worker는 ID를 명령 및 허용 목록에 포함된 도구 이름에 매핑하는 별도의 고정 서버
   카탈로그를 소유한다. 알 수 없는 서버와 도구는 fail closed 방식으로 거부한다.
4. Worker bridge는 공식 MCP Python SDK v1을 사용하고 stdio 세션을 초기화한 뒤
   `list_tools`를 확인하며, 서버가 해당 도구를 알릴 때만 등록된 도구를 호출한다.
5. MCP SDK 의존성은 Python 3.12 Linux 환경을 기준으로 해석되고, SDK 버전은 v2 미만으로
   고정되며 전이 의존성과 함께 해시로 잠긴다. 준비 스크립트는 호스트 신뢰 저장소를 사용해
   로컬 번들을 구성한다. Docker 빌드는 패키지 인덱스에 접근하지 않으며 TLS 검증을
   비활성화하지 않는다.

## 결과

### 장점

- 캠페인 범위가 Tool Gateway와 네트워크 경계 모두에서 강제된다.
- Worker의 직접 소켓은 내부 Docker 네트워크를 통해 프록시를 우회할 수 없다.
- 금지된 주소를 향하는 DNS rebinding은 연결 전에 거부된다.
- 에이전트가 MCP 등록을 임의 프로세스 실행으로 바꿀 수 없다.
- 모든 실제 네트워크 판정과 MCP 결과를 캠페인 증적에서 재현할 수 있다.

### 절충점과 잔여 위험

- 프록시에는 HTTPS 메서드와 경로 세부 정보가 보이지 않는다. 따라서 호스트 전체 승인이
  필요하며, 경로별 HTTPS 거부 규칙은 전체 authority에 대해 fail closed 방식으로 작동한다.
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
우회가 막히고, 등록된 MCP 도구가 검증된 Finding 하나를 생성하며, 잔여 PAJIN 컨테이너나
실행별 네트워크가 없어야 한다.
