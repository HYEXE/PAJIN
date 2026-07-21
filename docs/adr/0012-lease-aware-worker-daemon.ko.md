> Languages: [English](0012-lease-aware-worker-daemon.en.md) | [한국어](0012-lease-aware-worker-daemon.ko.md)

# ADR 0012: 임대 인식형 Control Plane Worker 데몬

- 상태: 승인됨
- 날짜: 2026-07-12
- 개정: [ADR 0024](0024-cooperative-execution-cancellation.ko.md)

## 배경

ADR 0011에서 Run, Job, 체크포인트, 승인 및 이벤트 상태를 영속화했지만, 실행하려면 여전히
호출자가 각 Job을 수동으로 획득하고 완료해야 했다. 프로덕션 Worker는 일시적인 Control
Plane 장애를 견디고, 캠페인이 활성 상태인 동안 임대를 유지하며, 자신의 ID가 거부되면
중지해야 한다. 또한 제출된 페이로드가 프로세스 명령이나 Python 호출 가능 객체를 선택하게
하지 않으면서 기존 PAJIN 실행 결과를 영속 상태로 변환해야 한다.

## 결정

PAJIN에 비동기 Worker 데몬과 타입이 지정된 Control Plane 클라이언트를 추가한다. 연결 풀링을
위해 하나의 HTTPX `AsyncClient`를 유지한다. 연결, 읽기, 쓰기 및 풀 타임아웃을 명시한다. 획득
요청은 최대 20초로 제한된 서버 측 롱 폴링을 사용한다. 전송 오류와 5xx 오류에는 백오프를
적용하고, 401/403은 치명적 오류로 처리한다. 409는 Worker의 종료 상태 또는 소유권 펜스를
의미한다. 구조화된 코드는 취소된 Run과 임대 거부를 구분하며, 이전 형식이거나 타입이 없는
409는 `lease-lost`로 간주하여 안전하게 실패한다.
인증 클라이언트는 origin-only HTTPS base URL만 허용한다. 평문 HTTP는
`PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB`이 literal `true`인 경우에만 예외이며, 그 경우에도
loopback 또는 번들 `control-plane` Compose service 이름으로 제한한다.

데몬은 한 번에 하나의 Job을 처리한다. 디스패치 전에 하트비트 태스크를 시작하고 완료, 실패
또는 체크포인트 최종화까지 이를 유지한다. 일시적인 최종화 실패는 동일한 임대 토큰으로
재시도하며 Control Plane의 완료 작업은 멱등성을 유지한다. 실행기 태스크가 활성 상태일 때
하트비트 소유권을 잃거나 하트비트를 사용할 수 없게 되면, 타입이 지정되고 최초 쓰기가
우선하는 실행 취소 컨텍스트에 신호를 보낸다. 이 컨텍스트는 강제로 비동기 태스크를 취소하기
전에 실행기에 제한된 협력적 정리 유예 시간을 제공하며, 오래된 결과는 제출하지 않는다.
실행기가 반환된 후 하트비트 또는 최종화 충돌이 발생하면 결과 제출을 즉시 취소한다. 엔진을
다시 열거나 러너 정리가 수행되었다고 주장하지 않는다.

각 claim과 renewal은 서버의 heartbeat/expiry 구간을 이벤트 루프의 monotonic clock에 매핑한다.
매핑 기준은 응답 수신이 아니라 요청 시작 시점이므로 네트워크 및 서버 지연은 임대 구간을
늘리지 않고 소비한다. heartbeat 호출 자체도 이 deadline을 넘을 수 없다. 만료까지 멈춰 있으면
daemon은 I/O를 취소하고 cooperative grace를 생략한 채 executor를 강제 취소하며, 다른 Worker가
Job을 재획득하기 전에 동시에 도착한 완료 응답도 거부한다.

Control Plane schema v10은 별도의 절대 `lease_deadline_at`을 영속화한다. claim 시 server 시간을
기준으로 최대 24시간 뒤로 설정하고 Replay는 compiled specification 또는 Grant expiry까지 더
짧게 줄일 수 있지만, heartbeat와 늦게 재개된 schema-v9 writer는 이를 연장할 수 없다. database는
leased row마다 해당 horizon 안의 canonical expiry, heartbeat, owner, token, attempt와 deadline
authority를 요구한다. Job submission digest는 immutable dispatch tuple을 결박하고 migration,
startup과 claim에서 다시 계산된다. managed trigger는 Run/Job state machine도 강제하고, 늦은 구
writer insert와 row replace/delete를 거부하며 terminal history를 immutable하게 만든다. 승인된
모든 renewal의 lease 전이는 계속 영속화하되 `job.heartbeat` audit event는 60초당 최대 하나만
기록한다. lease expiry/reclaim은 rolling expiry와 절대 deadline을 모두 검사한다.

SIGTERM/SIGINT를 받으면 제한 없이 드레이닝이 끝나기를 기다리는 대신 새로운 획득을 중단하고
활성 실행에 `daemon-shutdown` 신호를 보낸다. 동일한 협력적 유예와 강제 폴백을 적용한다.
프로세스나 컨테이너가 갑자기 종료된 경우에는 여전히 정리 호출이 수행되지 않는다. PostgreSQL
임대가 만료되면 새로운 토큰과 증가한 시도 횟수로 Job을 다시 큐에 넣는다. ADR 0024에서 취소
원인, 로컬 러너 영수증 및 그 증거 경계를 정의한다.

`ExecutorRegistry`가 실행 권한을 가진다. 제출된 Job 종류는 시작 시 구성되는 신뢰할 수 있는
레지스트리의 키일 뿐이다. Job 계약에는 명령, 모듈, 클래스, 스크립트 경로, URL 또는 실행 파일
필드가 없다. 알 수 없는 종류와 엄격한 페이로드 검증 실패는 영구 실패이며, 검증 값은 Control
Plane 오류 텍스트에 복사하지 않는다.

두 어댑터가 첫 번째 수직 단면을 구성한다.

| 종류 | 신뢰할 수 있는 어댑터 | 기존 PAJIN 경계 |
|---|---|---|
| `campaign` | `CampaignJobExecutor` | `LocalCampaignRunner`, Policy Engine, Tool Gateway |
| `tool-loop` | `ToolLoopJobExecutor` | `PolicyToolLoopRunner`, Provider Gateway, Secret Lease, Capability Ledger |

캠페인 프로필은 결정론적인 `mock-agent` 및 `mock-sleep` 대상만 허용한다. Tool Loop 프로필은
네트워크를 사용하지 않는 결정론적 Provider 픽스처와 T3 `mock.approval-probe`를 사용한다. 이는
프로덕션 모델 백엔드가 아니라 안전한 통합 픽스처다. 그래도 실제 Tool Loop, Provider Tool,
Secret Lease, Capability, 정책 재진입 및 체크포인트 코드를 실행한다.

두 내장 profile은 canonical Worker execution context를 봉인된 Run에 결박하고, 검증된 값을 완료
Job의 optional `executionProfile`, `executionContext` result field로 복사한다. 기본 profile은
명시적으로 `simulated-development-only`이고, Docker-backed Adapter는
`worker-observed-execution`, 그 밖의 custom backend는 `custom-backend-unclassified`로 남는다.

Tool Loop 실행이 `awaiting-approval`에 도달하면 어댑터가 타입이 완전히 지정된 체크포인트와
정확한 보류 인텐트를 업로드한다. Control Plane은 서명된 페이로드에 원본 Job 종류와 재시도
한도를 추가한다. 재개 시 승인을 한 번만 소비하고 원본 종류를 보존하며, 신뢰할 수 있는 승인
스냅샷을 후속 Job에 포함한다. 어댑터는 `ToolLoopApproval`을 재구성하고 기존 러너의 재개 경로를
호출한다.

## 전달 의미 체계

큐는 정확히 한 번의 Tool 부작용이 아니라 최소 한 번 실행을 보장한다. 완료와 체크포인트
최종화는 멱등적이지만, 외부 Tool이 효과를 발생시킨 뒤 결과를 커밋하기 전에 Worker가 종료될
수 있다. 프로덕션 Tool 어댑터는 대상 시스템이 지원하는 경우 멱등성 키를 사용해야 한다.
지원하지 않으면 재실행 위험을 정책에 노출하고 승인을 요구해야 한다. 체크포인트의 일회성
획득은 두 개의 후속 Job이 생기는 것을 막지만, 임의의 외부 시스템을 PostgreSQL과 트랜잭션으로
묶을 수는 없다.

## 운영 및 보안

- Worker 베어러 자격 증명은 상태, Job, 이벤트, 체크포인트 또는 아티팩트 데이터에 절대 쓰지 않는다.
- Worker 베어러 자격 증명은 검증된 HTTPS origin으로만 전송한다. 명시적인 평문 flag는 격리된
  번들 Compose/loopback lab 전용이며 원격 환경에서는 비활성 상태를 유지해야 한다.
- 상태 파일에는 Worker ID, 상태, 활성 Job ID, 개수, 타임스탬프, 제한된 오류 및 비밀 정보가
  없는 마지막 타입 지정 취소 스냅샷만 포함한다.
- 두 Worker daemon은 하나의 directory-descriptor 기반 writer로 상태를 교체한다. 이 writer는
  `O_EXCL`/`O_NOFOLLOW`로 private random temporary leaf를 만들고 fsync한 뒤 symlink를 따라가지
  않고 destination을 원자적으로 교체하며 parent directory도 fsync한다.
- Host 기본값은 shared `/tmp`의 예측 가능한 leaf가 아니라 `~/.pajin/status` 아래에 둔다. custom
  parent는 daemon effective UID 소유이고 group/other 쓰기가 불가능해야 한다. Compose가 명시하는
  `/tmp`는 container-private UID 소유 mode-0750 tmpfs다. Health reader는 no-follow regular UTF-8
  file만 최대 64 KiB까지 읽는다.
- status 보장과 Tool Loop continuation-checkpoint 격리에는 POSIX dirfd, `O_NOFOLLOW`, effective UID,
  sticky-directory 의미 체계가 필요하다. native Windows daemon은 어느 write도 시작하기 전에 명확한
  오류로 fail closed하며 Linux container 또는 WSL을 사용해야 한다. PowerShell에서 실행하는 Docker
  Compose는 계속 지원한다.
- `PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS`의 기본값은 2초이고,
  `PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS`의 기본값은 5초다. 두 값 모두 0.05부터 30까지 허용한다.
- 데몬은 아직 보류 중인 태스크를 포기하기 전에 유예 구간 하나와 강제 구간 두 개를 사용할 수
  있다. 프로세스 감독자는 `grace + (2 * force)`에 스케줄링 여유를 더한 시간보다 긴 시간을
  허용해야 한다.
- 이러한 한도에는 실행 중인 asyncio 이벤트 루프가 필요하며 동기식 블로킹 코드를 선점하지
  않는다. 백엔드 정리도 같은 구간 안에 들어와야 한다. `DockerWorkerBackend`에는 별도의 20초
  내부 정리 한도가 있으므로, 이를 포함하는 어댑터에는 20초보다 긴 강제 구간과 결정론적
  Compose 프로필보다 큰 감독자 허용 시간이 필요하다.
- Compose Worker는 루트가 아니고 읽기 전용이며 capability가 없다. 상태와 랩 아티팩트용 쓰기
  가능한 tmpfs만 가진다.
- Compose는 충돌 테스트를 빠르게 하기 위해서만 6초 임대를 사용한다. 프로덕션에서는 지연 시간과
  복구 목표에 맞춰 임대 및 하트비트 간격을 정해야 한다.
- 설정된 rolling lease 길이와 관계없이 절대 server lease horizon은 24시간이다. 장기 작업은 하나의
  권위를 무기한 갱신하지 말고 새 fence를 가진 Job으로 이어져야 한다.
- 프로덕션 실행 어댑터는 기존의 격리된 Worker 및 이그레스 경계를 유지해야 한다. 결정론적
  인프로세스 어댑터는 로컬 검증 프로필이다.
- Compose의 아티팩트 tmpfs는 일시적이다. 프로덕션에는 보존, 암호화, 접근 제어 및 Run-객체 간
  무결성 메타데이터를 갖춘 영속 증거 저장소가 필요하다.

## 검증

Docker 시나리오는 제출만으로 시작되는 자동 실행, T3 승인 대기, 인증된 승인, 후속 실행 재개 및
완료를 검증한다. 두 번째 시나리오는 5초짜리 캠페인 도중 Worker를 강제로 종료하고 임대가
지나기를 기다린 다음 Worker를 재시작한다. 이후 두 번째 시도가 `job.lease-expired-requeued`
이벤트와 함께 완료되는지 검증한다. 단위 테스트는 타입이 지정된 하트비트 및 종료 취소, 협력적
유예와 강제 폴백, 일시적 완료 재시도, 오래된 임대 거부, 롱 폴링 한도, 유효하지 않은 페이로드
거부, 두 실제 실행 어댑터 및 봉인된 로컬 취소 영수증을 검증한다.

## 참고 자료

- [HTTPX 비동기 클라이언트](https://www.python-httpx.org/async/)
- [HTTPX 타임아웃 구성](https://www.python-httpx.org/advanced/timeouts/)
- [Python asyncio 태스크 조정](https://docs.python.org/3/library/asyncio-task.html)
- [ADR 0024: 협력적 실행 취소](0024-cooperative-execution-cancellation.ko.md)
