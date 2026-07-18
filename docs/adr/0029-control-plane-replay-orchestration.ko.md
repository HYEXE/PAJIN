> Languages: [English](0029-control-plane-replay-orchestration.en.md) | [한국어](0029-control-plane-replay-orchestration.ko.md)

# ADR 0029: Control Plane Replay 오케스트레이션과 burn-on-claim 전달

- 상태: 승인됨
- 날짜: 2026-07-17
- 범위: M6-07B Control Plane 수직 조각
- 확장 대상: [ADR 0011](0011-durable-control-plane.ko.md), [ADR 0012](0012-lease-aware-worker-daemon.ko.md)
- 의존 문서: [ADR 0024](0024-cooperative-execution-cancellation.ko.md), [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md), [ADR 0028](0028-durable-local-replay-ticket-ledger.ko.md)
- 별도 로컬 범위: M6-07A 로컬 Replay 오케스트레이션

## 상태 참고

이 ADR은 2026-07-17에 승인되어 M6-07B의 분산 신뢰 경계와 전달 의미를 확정했다. 첫 권위 상태
조각에는 이제 버전이 지정된 Replay 집합체 스키마, 엄격한 시작 검증을 포함한 저장소 관리형
v1→v2 마이그레이션, 내부 전용 엄격한 Job payload, 원자적 batch 생성, burn-on-claim,
heartbeat, lease 만료 및 취소 상태 전이가 포함된다. 이것이 M6-07B 전체 완료를 뜻하지는 않는다.
Artifact 저장소와 서버 소유 소스 입장은 제한된 M6-07B-2A 기반으로 구현됐다. 이 기반은 소유자
통제 staging과 managed filesystem repository, immutable `cp_artifacts` metadata, schema v3,
exact opaque `(artifact_id, repository_version)` resolution 및 content/seal 재검증을 포함한다.
입장은 producer Control Plane Run ID와 sealed Run ID를 따로 보존한다. forward migration은
v1→v2→v3이며, legacy Replay data가 있는 v2→v3는 가짜 Artifact binding을 만들지 않고 fail
closed한다. 이 내부 서비스 경로는 public Replay/admission API를 열지 않는다. exact KISA
item/contract/compilation 파생, 새 identity 재시도 발행, ticket 발행 전 영속형 budget/rate permit,
Replay executor 연결, 타입이 지정된 서버 측 artifact 확정과 결과 digest 검증 및 Gate는 남아
있다. 실제 PostgreSQL schema-v3 인수 검증은 깨끗한 임시 database에서 migration/locking,
`cp_artifacts` append-only 강제와 exact composite Artifact foreign key를 검증해 완료했다. 나머지
실행 경계가 완료되기 전에는 Control Plane이 완전한 영속형 Replay 오케스트레이션을 제공한다고
주장할 수 없다.

## 맥락

M6-07A와 M6-07B는 같은 KISA Replay 계약을 사용하더라도 authority가 다르다. M6-07A는 한
프로세스가 로컬 sealed Run, 동일한 live budget/rate-limit state와 ADR 0028의 SQLite ticket
원장을 직접 소유하는 명시적 Local 경로다. 반면 M6-07B에서는 Operator, Control Plane API,
PostgreSQL, Worker daemon과 artifact storage 사이에 process 및 실패 경계가 있다. 로컬 경로의
경로명, mutable runtime 객체 또는 SQLite 파일을 원격 Worker 신뢰로 확장해서는 안 된다.

이 결정을 작성할 당시 구현에는 다음과 같은 구체적인 공백이 있었다.

- [`JobKind`와 `CompleteJobRequest`](../../src/pajin/control_plane/models.py)는 public
  `campaign`/`tool-loop` 종류와 임의의 `dict` 결과만 정의했다. Replay 전용 typed finalization,
  ticket fence와 result digest가 없었다.
- [`ControlPlaneRepository.initialize`](../../src/pajin/control_plane/database.py)는
  `create_all`을 사용하고 Run, Job, checkpoint, approval, event table만 만들었다. Replay schema와
  배포 가능한 forward migration 경로가 없었다.
- [`ControlPlaneService.claim_job`, `complete_job`, `_expire_leases`](../../src/pajin/control_plane/service.py)는
  일반 Job을 lease하고, 결과 JSON을 그대로 저장해 Run 전체를 완료하며, lease가 만료되면 같은
  Job row를 다시 queued로 돌렸다. burn-on-claim Replay ticket에는 이 재큐잉 의미가 맞지 않았다.
- [`WorkerDaemon._finalize`](../../src/pajin/control_plane/worker.py)는 전송 실패 시 같은 completion
  호출을 재시도했지만, 서버는 Replay artifact를 다시 열어 exact result digest를 검증하지
  않았다.
- [`CampaignJobExecutor`와 `ToolLoopJobExecutor`](../../src/pajin/control_plane/executors.py)는
  trusted registry를 사용했지만 결과의 `runPath`가 Worker 호스트의 절대 경로였다. API
  프로세스가 그 경로의 object identity, 불변성 또는 seal을 보장할 수 없었다.
- [`GatewayRestrictedReproducerRuntime._finish`](../../src/pajin/replay/runtime.py)는 한 프로세스 안에서
  artifact를 두 번 seal하고 ticket을 finalize한 다음 verified result를 다시 연다. 이 순서를
  Worker가 PostgreSQL authority까지 소유하는 형태로 옮기면 Worker의 자기 검증을 신뢰하게 된다.
- [`KISAReplayCoordinator`](../../src/pajin/modes/ai_redteam/replay.py)는 sealed source와 정확한
  KISA 계약을 다시 읽는 기존 기준점이고,
  [`SQLiteReplayExecutionAuthority`](../../src/pajin/replay/sqlite_tickets.py)는 로컬 재시작
  검증의 기준점이다. 둘 다 분산 queue와 artifact handoff를 대신하지 않는다.

승인 후 첫 구현 조각은 이 결정의 경계를 약화하지 않고 기준선의 일부를 해소했다. public Job
kind는 `campaign`과 `tool-loop`로 유지하고, 별도로 typed된 internal Replay payload를
batch/item/ticket/event authority state와 burn-on-claim fencing에 결박해 영속화한다. Repository
startup은 이제 versioned v1→v2 migration을 수행하거나 호환되지 않는 schema state를 거부한다.
M6-07B-2A는 이어서 private managed repository와 immutable Artifact metadata를 추가했다. trusted
admission service는 완료된 producer Job의 strict staging identity만 받아 database lock 밖에서
sealed source를 import·검증한 뒤 producer state를 다시 확인하고 canonical metadata와 internal
storage key를 기록한다. Replay batch consumer는 exact opaque Artifact locator만 사용하며 service는
batch 생성 전에 이를 resolve하고 다시 검증한다. 일반 Job completion/failure 경로는 Replay Job에
계속 사용할 수 없다. KISA 파생, retry 발행, durable permit, executor, typed finalization, Gate와
같은 실행 경계는 의도적으로 완료된 기반 밖에 남아 있다. 실제 PostgreSQL v3 migration/locking,
`cp_artifacts` append-only와 exact composite-FK acceptance는 검증된 기반에 포함된다.

따라서 M6-07B는 단순히 public `JobKind.REPLAY`를 추가하거나 Worker가 제출한 Candidate,
Capability Grant, contract, `runPath`와 verdict를 저장하는 방식으로 구현할 수 없다. 일반 Job의
at-least-once lease 복구와 single-use Replay ticket의 burn-on-claim 규칙도 명시적으로 결합해야
한다.

## 결정

M6-07B는 아래 경계를 채택한다.

### 로컬 M6-07A와 Control Plane M6-07B 분리

- M6-07A는 단일 호스트의 Local runner와 SQLite ticket 원장을 유지한다. Local filesystem
  path와 process-local 객체는 그 경계 안에서만 유효하다.
- M6-07B의 authority는 Control Plane 서비스와 PostgreSQL이다. SQLite 원장을 복제하거나
  Worker가 가진 Local authority를 PostgreSQL의 대리자로 취급하지 않는다.
- 두 경로는 ADR 0027의 typed Candidate, exact Mode contract, compilation, Outcome, Oracle 및
  common Gate 의미를 공유한다. storage identity, ticket lifecycle, lease와 finalization은 각
  경계가 별도로 구현한다.
- 첫 Control Plane Mode는 기존에 명시적으로 등록된 KISA M03, M06, A04 exact contract로
  제한한다. Candidate의 구조가 비슷하다는 일반 predicate로 새 scenario나 Tool을 자동 실행에
  포함하지 않는다.

### 서버 소유 소스 입장과 불변 `ArtifactRef`

Control Plane은 raw path 대신 versioned `ArtifactRef`만 교환한다. 최소 계약은 opaque
`artifact_id`, repository version, media/schema kind, byte length, content digest, producer Control
Plane Run ID, sealed Run ID, integrity root digest와 creation identity를 포함한다. storage key는
repository 내부 값이며 Operator나 Worker가 임의 path, URL, symlink 또는 object key를 선택할 수 없다.

첫 단일 호스트 구현은 owner-controlled filesystem repository를 사용할 수 있다. trusted Control
Plane service가 staging directory에서 artifact를 가져와 canonical path와 size bound를 검사하고,
content digest를 계산한 뒤 immutable object로 등록한다. 등록 후에는 같은 `ArtifactRef`의 bytes를
바꿀 수 없고, 새 bytes는 새 immutable identity와 reference를 만든다. 현재 filesystem repository는
각 identity에 repository version 1을 발급한다. source와 replay output 모두 같은 import 규칙을
통과한다. Worker의 절대 `runPath`는 Control Plane 계약에 들어가지 않는다.

Replay batch를 만들 때 서버는 다음 순서로 source를 admission한다.

1. 서버가 `ArtifactRef`를 repository에서 resolve하고 전체 Run integrity chain과 모든 sealed
   artifact를 직접 검증한다.
2. 서버가 sealed Campaign, Plan, Capability ledger, budget/rate-limit snapshot, Candidate와
   validation projection을 typed loader로 다시 읽는다.
3. 서버가 exact KISA registry를 이용해 eligible Candidate와 Mode contract를 파생하고 Replay
   Compiler를 실행한다.
4. 서버가 원 source root, canonical Candidate/contract/compilation digest와 새 Replay Capability를
   PostgreSQL에 저장한다.

Worker가 보낸 Candidate, contract, comparison rule, Capability Grant, target, Tool arguments,
source root 또는 eligibility flag는 authority input이 아니다. Worker claim envelope는 서버가
이미 파생하고 저장한 exact compilation과 짧은 수명의 non-delegable Capability만 전달한다.

### PostgreSQL Replay 집합체와 순방향 마이그레이션

새 schema는 최소한 다음 aggregate를 가진다.

| Aggregate | 역할 | 핵심 불변식 |
| --- | --- | --- |
| `cp_replay_batches` | source snapshot과 전체 Gate lifecycle | 하나의 immutable source `ArtifactRef`/root, Mode, purpose, policy version 및 CAS version에 결박 |
| `cp_replay_items` | eligible Candidate별 진행 상태 | Candidate/contract/compilation digest와 요구 반복 수가 batch 안에서 유일 |
| `cp_replay_tickets` | 한 번의 실행 attempt authority | item attempt, Job, Replay Run ID, Grant, source root, claim principal/fence 및 exact finalization에 결박 |
| `cp_replay_events` | Replay authority 감사 이력 | 상태 전이 transaction 안에서 append되고 update/delete 금지 |

Artifact metadata, durable budget reservation과 rate-limit bucket/permit에는 별도 table을 둘 수
있다. 모든 authority-bearing foreign key와 uniqueness/check constraint는 database에서 강제한다.
Replay event와 필요 시 대응하는 `cp_events` summary는 같은 transaction에 기록한다.

상태 기계는 최소한 다음 의미를 구분한다.

```text
batch:  planned -> running -> gating -> completed
                    |           |
                    +----------> failed / cancelled

item:   pending -> queued -> running -> verified -> gated
                               |
                               +-> retry-pending / failed / cancelled

ticket: issued -> claimed -> finalized
           |          |
           +----------+-> abandoned
```

`abandoned`는 실행이 실패했다는 Oracle 판정이 아니다. 해당 ticket의 권한과 결과를 Gate에 사용할
수 없다는 terminal authority 상태다. Item은 정책과 남은 예산이 허용할 때 새로운 attempt로
돌아갈 수 있지만 abandoned ticket은 어떤 상태에서도 되살리지 않는다.

ADR 0011이 예고한 대로 이 schema는 production startup의 `create_all`에 의존하지 않는다.
versioned, forward-only migration으로 table, enum/check constraint, index, trigger와 기존 Job 연계를
추가하고 migration version을 기록한다. 서버는 기대 version보다 오래되거나 알 수 없는 schema를
자동 추측하지 않고 시작을 거부한다. SQLite는 repository unit test adapter일 수 있지만
PostgreSQL row lock, constraint와 migration 검증을 대신하지 않는다.

### 내부 전용 Replay Job과 burn-on-claim lease

Replay Job은 Operator 제출 API에 노출하지 않는 internal kind다. Public `SubmitRunRequest`가
`replay`를 선택할 수 없고, Control Plane의 trusted batch service만 검증된 `cp_replay_item`과
ticket에서 Job을 생성한다. Worker startup registry에도 exact Replay executor가 명시적으로
설치되어야 한다. Job payload는 opaque batch/item/ticket/artifact reference와 서버 생성
compilation identity만 포함하며 executable path, 임의 URL, callable 또는 Worker 선택 Grant를
포함하지 않는다.

일반 Control Plane queue는 at-least-once 전달을 유지하지만 Replay에서는 다음과 같이 ticket과
결합한다.

- queued Replay Job을 lease하는 transaction이 정확히 하나의 `issued` ticket을 `claimed`로
  바꾸고, authenticated Worker principal, lease identity, attempt number와 fencing value를 함께
  저장한다. claim 순간부터 ticket은 burn된다.
- 각 internal Replay Job은 한 ticket attempt만 나타내며 같은 Job row의 실행 재큐잉을 허용하지
  않는다. Replay retry 횟수는 Item이 소유하고 Job의 일반 `max_attempts` 재사용과 분리한다.
- heartbeat 또는 명시적 retryable failure 뒤 lease가 끝나면 기존 Job은 terminal 처리되고
  claimed ticket은 `abandoned`가 된다. `_expire_leases`가 그 Job/ticket을 다시 queued/issued로
  돌려서는 안 된다.
- 재시도가 허용되면 서버가 source root, cancellation, policy, budget과 rate state를 다시
  검사한 후 새 attempt number, 새 ticket ID, 새 Replay Run ID와 새 Job ID를 만든다.
- claim 응답이 유실되어 Worker가 실행하지 못한 경우에도 claimed ticket을 되살리지 않는다.
  가용성 손실보다 같은 실행 권한의 중복 사용 방지를 우선한다.

즉 Item 수준에서는 여러 delivery attempt가 가능하지만 ticket과 Job attempt 수준에서는
single-use다. 이 예외는 ADR 0012의 일반 Job lease recovery를 폐기하지 않고 internal Replay
kind에만 더 강한 규칙을 적용한다.

### 인증된 Worker 주체와 fencing

현재 요청 body의 `worker_id` 문자열만으로 Replay authority를 부여하지 않는다. 인증 middleware가
확정한 Worker principal subject를 등록된 Worker identity에 결박하고, claim/heartbeat/permit/
finalize의 actor는 그 principal에서만 파생한다.

모든 Replay mutation은 다음 값의 exact match를 요구한다.

- Worker principal subject와 허용된 Replay executor profile;
- Job ID와 lease-token digest;
- batch, item, ticket ID와 attempt number;
- ticket의 monotonically increasing fencing value;
- source root와 compilation digest.
- active Run/batch/item/ticket state와 cancellation fence.

새 attempt가 만들어지거나 ticket이 abandoned/cancelled/finalized되면 이전 fence는 즉시 무효다.
stale Worker는 heartbeat, Tool-call permit, artifact import 완료 또는 finalization을 수행할 수 없다.
Worker credential 탈취나 Worker host compromise 자체는 별도 운영 위협이지만, 그런 Worker도
서버가 발급하지 않은 contract/Capability와 stale attempt를 PAJIN 결과로 확정할 수 없어야 한다.

### 내구성 있는 예산 예약과 요청 속도 권한

Replay batch admission은 전체 eligible item과 반복 수의 worst-case Tool call을 계산하고, 첫 Job을
만들기 전에 Campaign budget을 PostgreSQL에서 원자적으로 reserve한다. reservation은 batch/item/
ticket에 결박하고 다른 Local/Control Plane 실행과 같은 Campaign 한도를 초과할 수 없다. Worker가
보고한 `usedCalls`나 로컬 snapshot은 정산 근거가 아니다.

각 실제 Tool call 전에 Worker의 trusted Replay runtime은 internal permit endpoint를 호출한다.
서버는 active principal/lease/ticket fence를 다시 확인하고, canonical target/Tool/call ordinal에
대해 한 번만 쓸 수 있는 permit을 발급하면서 reserved budget을 consume하고 durable rate-limit
bucket 또는 append-only entry를 갱신한다. permit은 다른 ticket, target, Tool 또는 ordinal에
재사용할 수 없다. 여러 Worker가 동시에 요청해도 database lock과 unique constraint가 budget과
rate limit을 초과 발급하지 않아야 한다.

이미 발급된 permit은 실행 여부가 불명확하더라도 자동 환불하지 않고 소비된 것으로 본다.
abandon/cancel 뒤에는 새 permit을 발급하지 않으며, 명확히 미발급인 reservation만 감사 event와
함께 해제할 수 있다. 새 attempt는 남은 durable budget과 rate window를 다시 통과해야 한다.

### Worker 실행/봉인과 권한 최종화 단계 분리

분산 경로는 현재 process-local `_finish`를 두 단계로 나눈다.

1. **Worker execute/seal:** Worker는 서버가 발급한 compilation과 permit만 사용해 ordinary Tool
   Gateway/Worker boundary로 실행한다. 별도의 Replay Run에 canonical artifact set, Outcome과
   execution receipt를 쓰고 두 seal을 완성한 뒤 managed repository로 import한다. 이 receipt는
   Worker가 어떤 bytes를 만들고 seal했는지 나타낼 뿐 ticket finalization 권한은 아니다.
2. **Control Plane authority finalize:** 서버는 immutable Replay `ArtifactRef`를 다시 열어 content
   digest, 두 seal, artifact set, fresh request/evidence lineage, Mode Oracle result, source root,
   Candidate, compilation, ticket과 Replay Run identity를 직접 검증한다. 검증된 값으로만 typed
   finalization을 만들고 PostgreSQL transaction에서 ticket, Job, item과 event를 확정한다.

Replay completion은 일반 `CompleteJobRequest.result: dict`를 사용하지 않는다. 전용 typed command는
최소한 exact Job/ticket/fence, immutable `ArtifactRef`, compilation/source/replay Run identity,
artifact-set digest, 두 seal root, Outcome digest와 canonical `result_digest`를 결박한다. 서버가
artifact bytes에서 authority-bearing 값을 다시 계산하며 Worker가 보낸 verdict 또는 digest를
그대로 신뢰하지 않는다.

finalization transaction이 성공했지만 HTTP 응답이 유실된 경우, 같은 authenticated principal이
동일한 canonical `result_digest`와 ArtifactRef로 재시도하면 저장된 성공을 idempotent하게
반환한다. 하나라도 다른 retry는 conflict다. transaction이 commit되기 전에 lease/fence가
끝났다면 해당 attempt는 abandoned되고 늦은 finalization은 거부된다. Gate는 이후 새 read-only
repository/session으로 finalized ticket과 sealed artifact를 다시 검증하므로 API process의 mutable
검증 객체를 신뢰하지 않는다.

### 소스 루트 CAS 확인 Gate

Worker는 confirmation Gate를 실행하거나 `confirmed`를 제출하지 않는다. 모든 required item이
exact finalized receipt를 가진 뒤 Control Plane authority가 Gate를 수행한다.

1. 서버는 batch의 immutable source `ArtifactRef`, admitted source root, CAS version과 정렬된
   item/finalization digest 집합을 snapshot한다.
2. database transaction 밖에서 source 및 replay artifact를 새 handle로 다시 열고 ADR 0027의
   common Gate와 exact KISA Oracle/coverage 규칙을 적용한다.
3. Gate output은 imported source object를 덮어쓰지 않고, source reference/root를 parent로 가진
   새 immutable versioned validation projection artifact로 만든다.
4. 짧은 transaction에서 `batch_id`, state=`gating`, CAS version, source ArtifactRef/root와 item
   digest 집합이 snapshot과 모두 같을 때만 batch/item을 gated/completed로 바꾸고 projection
   reference를 기록한다.

source가 다른 object/version/root로 치환되었거나 item set, ticket finalization, cancellation 또는
policy state가 달라졌다면 compare-and-set은 실패하고 confirmation projection을 publish하지 않는다.
Gate retry는 새 snapshot에서 전체 verification을 다시 수행한다. 이미 completed인 exact
`result_digest`의 Gate retry만 idempotent하며, 기존 sealed source를 재해석하거나 수정하지 않는다.

### 취소, 폐기와 잠금 순서

ADR 0024의 typed cooperative cancellation을 그대로 사용한다. Run 또는 Replay batch cancellation은
새 Job claim과 Tool-call permit을 즉시 fence하고, queued Job과 issued/claimed ticket을 terminal
처리한다. 실행 중 Worker는 heartbeat conflict로 cancellation을 관찰해 bounded cleanup과 sealed
local receipt를 시도할 수 있다. 그 receipt는 여전히 process-local cleanup evidence일 뿐 Control
Plane physical quiescence나 external effect rollback 증명이 아니다.

claimed ticket의 lease expiry, stale fence, Worker crash, forced cancellation, conflicting
finalization과 retryable execution failure는 ticket을 `abandoned`로 만든다. Abandoned artifact와
ticket은 Gate coverage에 포함하지 않는다. 취소 시 이미 finalized된 역사와 event는 보존하지만
새 Gate publication은 중단한다. ADR 0027의 `inconclusive`, `needs-review`, `confirmed` 같은 validation
disposition과 operational `abandoned`를 혼합하지 않는다.

PostgreSQL mutation은 ADR 0023/0024의 dependent-to-Run 순서를 확장해 다음 순서를 지킨다.

```text
cp_jobs (stable Job ID order)
  -> cp_replay_tickets (stable attempt/ticket order)
  -> cp_replay_items (stable item order)
  -> cp_replay_batches
  -> budget reservations / rate-limit buckets (canonical key order)
  -> cp_runs
```

한 경로에 앞 단계 row가 없으면 그 단계를 건너뛰되 역순으로 잠그지 않는다. cancellation은 active
Job을 안정된 순서로 잠근 후 Replay dependent를 잠그고 Run을 마지막에 잠근다. issuance, claim,
lease expiry, permit, finalization과 Gate publication도 같은 순서를 사용한다. Artifact hashing,
seal 검증과 Oracle 실행은 database lock을 잡지 않은 상태에서 수행하고 immutable reference와
CAS로 결과를 commit한다.

## 첫 수직 조각과 비목표

첫 구현은 PostgreSQL, Control Plane API, managed filesystem artifact repository와 한 호스트의
하나 이상 Worker process를 사용하는 KISA positive confirmation 수직 조각이다. 같은 호스트에서도
동시 Worker claim, API/Worker restart와 response loss를 검증한다. `ArtifactRef` abstraction은 처음부터
사용해 raw path 의존성을 만들지 않는다.

다음은 이 ADR의 첫 수직 조각 범위가 아니다.

- multi-host artifact transfer, shared network filesystem, S3 호환 object store, cross-region 복제와
  object-store credential delegation;
- SQLite를 PostgreSQL queue 또는 distributed ticket authority로 사용하는 것;
- public Operator-authored Replay Job, arbitrary Mode/Tool 자동 등록, T3/T4 또는 비멱등 replay;
- portable 제3자 attestation, 공개키 receipt signature, transparency log와 key lifecycle;
- Worker host compromise가 만든 외부 side effect의 rollback 또는 destination-level exactly-once;
- Control Plane이 물리적 fleet quiescence를 증명하는 cancellation acknowledgement protocol.

multi-host/object-store 지원은 immutable `ArtifactRef` resolver, upload authorization, retention,
encryption, tenant isolation과 cross-service authentication을 별도 ADR로 설계한 뒤 추가한다.

## 결과

- Worker는 실행 주체이지만 Candidate 선정, replay 권한 발급, finalization과 confirmation의
  authority가 아니다.
- 일반 queue의 at-least-once 복구를 유지하면서도 single-use ticket과 Job attempt를 재사용하지
  않아 replay 권한 중복 실행을 줄인다. 대신 claim 응답 유실과 crash는 새 ticket 비용과 추가
  latency를 만든다.
- immutable artifact import와 server-side seal 검증으로 Worker-local absolute path와 mutable
  runtime 객체가 결과 authority에서 제거된다.
- PostgreSQL migration, artifact retention, orphan artifact 정리, reservation reconciliation과
  rate-limit 운영이 새로운 책임이 된다.
- budget/permit을 보수적으로 소비하므로 ambiguous crash 뒤 가용 예산이 줄 수 있다. 이 손실은
  자동 환불로 중복 실행 위험을 키우는 것보다 우선한다.
- Local M6-07A는 가벼운 단일 호스트 경로로 남고, M6-07B 구현 여부를 가장하지 않는다.

## 승인 및 검증

이 ADR의 구현은 자동화된 테스트가 최소한 다음을 증명할 때 완료된다.

- forward migration이 빈 PostgreSQL과 직전 지원 version을 새 Replay schema로 올리고, unknown,
  partial 또는 constraint/trigger가 손상된 schema에서 서버가 fail closed한다;
- public submission이 internal Replay kind, raw path/URL, Candidate, contract, Capability와 Worker
  verdict 주입을 거부하고, server-side sealed source admission만 exact KISA Job을 만든다;
- source와 replay `ArtifactRef`의 content, Run ID, seal root, artifact set 또는 repository version
  치환과 symlink/path traversal이 server-side verification에서 거부된다;
- 두 Worker가 같은 queued Replay Job/ticket을 동시에 claim해 정확히 하나만 성공하고 principal,
  lease token, ticket과 fence가 같은 transaction에 결박된다;
- claim된 Worker가 crash하거나 lease가 만료되면 이전 ticket과 Job은 재큐잉되지 않고 abandoned가
  되며, retry는 새 attempt/ticket/Replay Run/Job ID를 사용한다;
- stale Worker가 heartbeat, permit, artifact import 완료와 finalization을 시도해도 거부되고 새
  attempt의 budget, rate state 또는 결과를 바꾸지 못한다;
- 여러 Worker의 동시 permit 요청이 reserved Tool-call budget과 durable rate window를 초과하지
  않고, duplicate ordinal은 한 번만 소비되며 abandoned/cancelled ticket은 새 permit을 받지 못한다;
- finalization commit 뒤 응답 유실을 모사한 exact retry는 같은 result를 반환하고, 다른
  ArtifactRef, root, Outcome 또는 `result_digest` retry는 거부된다;
- finalization 이전 응답/connection loss와 lease expiry가 겹치면 이전 attempt는 Gate에 들어가지
  않고 새 ticket만 실행될 수 있다;
- Gate verification 중 source reference/root, item set 또는 ticket finalization을 바꾸는 race가
  source-root CAS를 실패시키며 confirmed projection을 publish하지 않는다;
- Run/batch cancellation과 Worker shutdown은 ADR 0024 cancellation을 전달하고 claimed ticket을
  abandoned로 남기며 sealed cleanup receipt만으로 finalization 또는 confirmation하지 않는다;
- API, Worker와 Gate process를 각각 재시작해도 PostgreSQL ticket/event, immutable artifact,
  reservation/rate state와 exact finalized receipt를 다시 열어 같은 결과를 검증한다;
- PostgreSQL concurrency test가 claim 대 claim, lease expiry 대 late finalize, cancellation 대
  permit/finalize, Gate 대 source drift를 race해 deadlock 없이 위 lock ordering과 fencing을
  만족한다.
- 단일 호스트 KISA end-to-end가 sealed source admission부터 internal Candidate -> Replay -> Gate,
  versioned Confirmed projection까지 성공하되 semantic-only, coverage 누락, unsupported scenario와
  tampered artifact는 confirmation하지 않는다.

## 이전 결정과의 관계

- [ADR 0011](0011-durable-control-plane.ko.md)의 PostgreSQL orchestration/authorization 경계를
  확장하고, 당시 future work였던 managed forward migration을 Replay schema부터 요구한다. 기존
  Run/Job/checkpoint/approval/event 의미는 Replay 전용 aggregate와 typed completion 없이는 충분하지
  않다.
- [ADR 0012](0012-lease-aware-worker-daemon.ko.md)의 authenticated lease, trusted executor registry,
  heartbeat와 at-least-once 전달을 재사용한다. 단, Replay claim 뒤에는 같은 Job을 재큐잉하지 않고
  새 ticket/Job attempt를 만드는 더 강한 예외를 둔다.
- [ADR 0024](0024-cooperative-execution-cancellation.ko.md)의 first-write-wins cancellation과 local
  cleanup receipt 한계를 유지한다. 이 ADR의 `abandoned`는 durable execution-authority fence이지
  physical quiescence attestation이 아니다.
- [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)의 Candidate/Compiler/
  Restricted Reproducer/Mode Oracle/common Gate와 `confirmed` 불변식을 바꾸지 않는다. Control
  Plane은 그 입력을 sealed source에서 파생하고 finalized receipt를 다시 검증하는 orchestration
  authority를 추가할 뿐이다.
- [ADR 0028](0028-durable-local-replay-ticket-ledger.ko.md)의 canonical compilation binding,
  burn-on-claim, exact idempotent finalization과 read-only restart verification 원칙을 PostgreSQL
  failure model에 맞게 확장한다. SQLite 파일이나 Local writer를 분산 authority로 승격하지 않는다.

## 참고 자료

- [Control Plane 형식화 계약](../../src/pajin/control_plane/models.py)
- [Control Plane 데이터베이스 스키마](../../src/pajin/control_plane/database.py)
- [Control Plane 트랜잭션 서비스](../../src/pajin/control_plane/service.py)
- [리스 인식 Worker 데몬](../../src/pajin/control_plane/worker.py)
- [신뢰할 수 있는 실행자 레지스트리](../../src/pajin/control_plane/executors.py)
- [Run 무결성 저장소와 검증기](../../src/pajin/runtime/store.py)
- [Restricted Replay 런타임과 검증된 로더](../../src/pajin/replay/runtime.py)
- [SQLite 내구성 Replay ticket 권한](../../src/pajin/replay/sqlite_tickets.py)
- [KISA 봉인 소스 Replay 코디네이터](../../src/pajin/modes/ai_redteam/replay.py)
