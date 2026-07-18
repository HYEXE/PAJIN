# ADR 0029: Control Plane Replay orchestration과 burn-on-claim 전달

- Status: Accepted
- Date: 2026-07-17
- Implementation update: 2026-07-18 (M6-07B-2F exact KISA execution-context authority)
- Scope: M6-07B Control Plane 수직 조각
- Extends: [ADR 0011](0011-durable-control-plane.md), [ADR 0012](0012-lease-aware-worker-daemon.md)
- Depends on: [ADR 0024](0024-cooperative-execution-cancellation.md), [ADR 0027](0027-independent-reproduction-confirmation-boundary.md), [ADR 0028](0028-durable-local-replay-ticket-ledger.md)
- Separate local scope: M6-07A Local Replay orchestration

## Status note

이 ADR은 2026-07-17에 Accepted되어 M6-07B의 분산 신뢰 경계와 전달 의미를 확정했다. 첫
authority-state 조각에는 이제 versioned Replay aggregate schema, strict startup validation을
포함한 repository-managed v1→v2 migration, internal-only strict Job payload, 원자적 batch 생성,
burn-on-claim, heartbeat, lease 만료 및 취소 상태 전이가 포함된다. 이것이 M6-07B 전체 완료를
뜻하지는 않는다. Artifact repository와 server-owned source admission은 제한된 M6-07B-2A
기반으로 구현됐다. 이 기반은 소유자 통제 staging과 managed filesystem repository, immutable
`cp_artifacts` metadata, schema v3, exact opaque `(artifact_id, repository_version)` resolution 및
content/seal 재검증을 포함한다. admission은 producer Control Plane Run ID와 sealed Run ID를 따로
보존한다. forward migration은 v1→v2→v3이며, legacy Replay data가 있는 v2→v3는 가짜 Artifact
binding을 만들지 않고 fail closed한다. M6-07B-2B는 2026-07-18에 구현됐다. batch command는 exact
Artifact locator와 idempotency key만 받는다. Control Plane은 managed sealed AI Red Team source를
다시 읽어 eligible exact M03·M06·A04 confirmation Candidate와 contract를 파생하고 trusted Replay
Compiler를 실행한 뒤 canonical `ReplayCompilation`과 `ReplayCapabilityGrant`를 batch `planned`, 각
item `pending` 상태의 append-only, non-dispatchable PostgreSQL derivation record이자 proof로
저장한다. caller가 작성한 Candidate, contract, policy, digest, target, arguments는 authority input이
아니다. schema v4는 canonical, non-dispatchable compilation derivation record를 추가해 forward 경로를
v1→v2→v3→v4로 확장한다. `compilation_id`가 row identity이고 `item_id`는 고유하지 않다.
Candidate/contract field는 plan identity FK를 구성하며 각 row가 Replay Run identity, compilation
digest와 Grant digest를 소유하므로 item 하나에 attempt/version row를 append할 수 있다. planned Grant는
최대 5분만 유효하고 pending 중 만료될 수 있으므로 이후 실행 권한으로 절대 재사용하면 안 된다.
M6-07B-2C durable issuance도 2026-07-18에 구현됐다. schema v5는
`cp_replay_budget_accounts`, `cp_replay_budget_reservations`, `cp_replay_rate_accounts`,
`cp_replay_rate_reservations`와 `cp_replay_tickets`의 exact compilation 및 reservation FK를 추가한다.
budget account는 sealed source Run/root, Campaign, budget digest, baseline/max count,
reserved/consumed/released counter와 CAS를 결박한다. rate account는 sealed ledger ID와 digest,
observed unit, managed Artifact admission 시각을 `observed_at`으로, nullable per-minute limit, 고정
60초 window와 CAS를 보수적으로 결박하고 각 첫 시도
rate reservation은 그 window 뒤 만료된다. 내부 멱등
`ControlPlaneService.issue_replay_batch(batch_id, actor=...)`는 authority lock 전에 managed source를
다시 resolve·재검증한다. batch 첫 시도 전체의 Tool-call/request-unit을 예약하고 pending item마다 fresh
Replay Run identity와 Grant로 다시 compile한 뒤 canonical compilation, active budget/rate
reservation, one-shot 내부 Job과 `issued` ticket을 한 transaction에서 만든다. strict payload와 ticket은
exact `compilation_id`, `budget_reservation_id`, `rate_reservation_id`, attempt, Replay Run,
compilation digest와 Grant digest에 결박된다. batch는 `running`, item은 `queued`가 된다. 응답
유실(response-loss) 재시도는 현재 active exact authority graph가 발급 직후 ticket/Job
`issued`/`queued`이거나 claim 뒤 `claimed`/`running`일 때만 같은 issuance를 재구성하며, terminal이거나
그 밖에 변경된 graph는 fail closed한다. 같은 transaction은 `run.submitted`, item별
`replay.compilation.derived`·`replay.ticket.issued`, 마지막 `replay.batch.issued` event를 기록한다.
최초 planned row는 non-dispatchable로 남고 승격하거나 재사용하지 않는다. M6-07B-2D 내부 서비스 전용
호출별 permit 원장/발급도 2026-07-18에 구현됐다. schema v6는 forward 경로를
v1→v2→v3→v4→v5→v6으로 확장하고 append-only `cp_replay_tool_permits`를 추가한다. strict
`ReplayToolPermitRequest`는 executor profile, lease token, ticket ID, fencing value와 1-based call ordinal만
받는다. 멱등 `ControlPlaneService.issue_replay_tool_permit(job_id, request, actor=...)`는 인증 principal과
등록 profile, exact Job/ticket lease token·fence, active Run/batch/item/ticket, canonical compilation/Grant,
exact reservation counter와 rolling request-rate admission을 다시 검증한다. cap이 있으면 현재 sealed
baseline, 발급 후 아직 유효한 reservation의 미소비 unit, 각 60초 window에서 active인 permit unit과 새 trusted
request 비용을 합산한다. cap이 없으면 rate 거부만 생략하고 exact reservation counter는 계속 소비한다.
canonical permit은 exact ticket/compilation/reservation
graph, source/original request, Tool/version/target/method, ordinal, Tool-call unit 하나와 trusted request
unit에 결박된다. TTL은 최대 30초이고 Job/ticket lease 및 compiled spec/Grant deadline에 제한되며 rate
reservation expiry에는 제한되지 않는다. 고유 `(ticket, ordinal)`과 저장된 permit digest/request ID로
exact response-loss duplicate는 counter를 다시 소비하거나 event를 두 번 append하지 않고 같은 row를 반환한다. 최초 발급은
reserved budget/rate unit을 consumed로 원자적으로 옮기고 audit event를 append한다. 실행이 불확실해도
발급분은 consumed로 남고 cancel/abandon은 확실히 미발급된 잔여분만 release한다.
stale/wrong/cancelled/expired/finalized/ordinal-gap/over-limit 요청은 fail closed한다. M6-07B-2E는 strict
JSON `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` subject→profile-array allowlist와 전용 WORKER-role HTTP
endpoint/async client를 추가했다. allowlist는 설정이 없으면 빈 목록으로 fail closed하며,
`{"worker-service":["kisa-exact-v1"]}`는 해당 subject에 profile 하나만 허용한다. claim,
heartbeat, Tool-permit 발급은 internal Worker transport로만 노출되고, claim/heartbeat envelope은
서버가 exact digest·identity binding을 다시 검증한 canonical `ReplayCompilation`을 포함한다.
permit은 발급 시 이미 소비된 non-bearer proof이며 별도 redeem mutation은 없다.
M6-07B-2F는 schema v7 append-only `cp_replay_execution_contexts`를 추가한다. 첫 시도 발급은 fresh
compilation마다 canonical context 하나를 저장한다. 이 context는 exact typed Campaign, exact KISA
Scenario, canonical `AIChatProbeTool.spec`, 각 component digest와 전체 context digest, source/policy
identity, 고정 `kisa-exact-v1` executor profile, Secret Lease ID가 없는 secret 금지 정책과 opaque
output-staging slot을 포함한다. strict Job payload는 context ID/digest를 반복하고 claim/heartbeat는
exact graph 검증 뒤 context를 반환한다. profile admission은 고정 profile을 검증하며 Tool-permit
발급은 같은 compilation/context 권위를 전이적으로 다시 검증한다. staging slot은 identity일 뿐
path, store, upload 권한 또는 result claim이 아니다. v6→v7 migration은 exact issuance-time bytes를
재구성할 수 없으므로 dispatch 가능한 v6 Replay authority가 하나라도 있으면 fail closed한다.
non-dispatchable planned proof만 있는 database는 context table을 비운 채 전진할 수 있다. 실제
executor daemon은 Compose에서 계속 기본 활성화하지 않는다. public Replay admission/read API,
실제 Replay executor/pre-dispatch permit-use 집행, Worker execute/seal, output import와 typed
server-side finalization, 새 identity retry, Gate와 negative Control Plane retest는 남아 있다. 이
실행 경계가 완료되기 전에는 Control Plane이 완전한 durable Replay orchestration을 제공한다고
주장할 수 없다.

## Context

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
batch 생성 전에 이를 resolve하고 다시 검증한다. M6-07B-2B는 나머지 command input을 idempotency로
한정하고 trusted source 재로딩, exact M03·M06·A04 confirmation Candidate/contract 파생, canonical
compilation과 append-only planned/pending, non-dispatchable PostgreSQL derivation record를 추가했다.
저장된 compilation과 Grant는 파생 결과를 증명할 뿐 dispatch 권한이 아니며 issuance 때 재사용할 수 없다.
M6-07B-2C는 schema-v5 durable budget/sealed-rate reservation과 내부 멱등 첫 시도 발행 transaction을
추가했다. service는 source를 재검증하고 fresh Replay Run/Grant compilation 권위를 append한 뒤 전체
batch의 exact reservation-bound Job/ticket 집합을 원자적으로 만든다. 일반 Job completion/failure
경로는 Replay Job에 계속 사용할 수 없다. M6-07B-2D는 schema-v6 append-only 호출별 permit 원장과
내부 서비스 발급을 추가하고 exact active authority 재검증, canonical operation 결박,
ticket/ordinal 멱등성, reserved→consumed 전이와 burn-on-uncertainty를 구현했다. M6-07B-2E는
fail-closed subject/profile allowlist, WORKER-only claim·heartbeat·Tool-permit HTTP endpoint, async client와
서버 검증 canonical compilation claim envelope를 추가했다. M6-07B-2F는 schema-v7 append-only
execution context를 추가해 fresh issuance compilation마다 exact typed Campaign, KISA Scenario,
canonical ToolSpec, component/context digest, 고정 executor profile, secret 금지와 opaque
output-staging identity를 결박한다. Job payload, claim envelope, profile admission과 permit issuance는
이 authority graph를 보존하거나 전이적으로 재검증한다. v6→v7 migration은 누락된 issuance-time
bytes를 만들어 내지 않고 dispatch 가능한 legacy authority를 거부한다. public Replay
admission/read API, 실제 executor/pre-dispatch permit-use, Worker execute/seal, output import와 typed
finalization, retry, Gate와 negative Control Plane retest는 의도적으로 완료된 기반 밖에 남아 있고,
Compose에는 활성 Replay executor daemon이 없다.

따라서 M6-07B는 단순히 public `JobKind.REPLAY`를 추가하거나 Worker가 제출한 Candidate,
Capability Grant, contract, `runPath`와 verdict를 저장하는 방식으로 구현할 수 없다. 일반 Job의
at-least-once lease 복구와 single-use Replay ticket의 burn-on-claim 규칙도 명시적으로 결합해야
한다.

## Decision

M6-07B는 아래 경계를 채택한다.

### Local M6-07A와 Control Plane M6-07B 분리

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

### Server-owned source admission과 immutable `ArtifactRef`

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
4. 서버가 원 source root, canonical Candidate/contract identity와 최초 Replay compilation/Capability를
   `compilation_id` 기반 non-dispatchable derivation record이자 proof로 저장한다. 이 row가 Replay Run
   ID, compilation digest와 Grant digest를 소유한다.
5. 별도 내부 issuance 호출이 managed source를 다시 resolve·재검증하고 sealed budget/rate snapshot을
   durable account에 결박해 첫 시도 전체를 reserve한 뒤, fresh Replay Run/Grant compilation 권위를
   append하고 Job/ticket을 원자적으로 만든다.

Worker가 보낸 Candidate, contract, comparison rule, Capability Grant, target, Tool arguments,
source root 또는 eligibility flag는 authority input이 아니다. planned record의 5분 Grant는 발행 전에
만료될 수 있으며 Worker 실행 권한이 아니다. Worker claim envelope는 구현된 durable issuance
transaction에서 서버가 결박한 fresh compilation과 짧은 수명의 non-delegable Capability만 전달한다.

### PostgreSQL Replay aggregate와 forward migration

새 schema는 최소한 다음 aggregate를 가진다.

| Aggregate | 역할 | 핵심 불변식 |
| --- | --- | --- |
| `cp_replay_batches` | source snapshot과 전체 Gate lifecycle | 하나의 immutable source `ArtifactRef`/root, Mode, purpose, policy version 및 CAS version에 결박 |
| `cp_replay_items` | eligible Candidate별 진행 및 plan identity | Candidate/contract plan identity와 요구 반복 수가 batch 안에서 유일하며 item 하나가 여러 compilation row를 가질 수 있음 |
| `cp_replay_compilations` | non-dispatchable derivation/attempt record | `compilation_id`가 PK이고 non-unique `item_id`와 Candidate/contract field가 plan identity를 결박하며, 각 append-only row가 Replay Run ID, canonical bytes, compilation digest와 Grant digest를 소유 |
| `cp_replay_budget_accounts` | source Campaign Tool-call authority | source Run/root, Campaign, sealed budget digest와 baseline/max count를 결박하고 reserved/consumed/released counter를 CAS로 전이 |
| `cp_replay_budget_reservations` | item attempt 하나의 Tool-call authority | account, batch/item/attempt와 compilation에 결박되고 total call을 넘지 않는 active/partially-consumed/consumed/released lifecycle |
| `cp_replay_rate_accounts` | 보수적인 sealed request-rate authority | source Run/root, Campaign, sealed ledger ID/digest와 observed unit, managed Artifact admission 시각인 `observed_at`, nullable per-minute cap, 60초 window와 CAS를 결박 |
| `cp_replay_rate_reservations` | item attempt 하나의 request-unit authority | account, batch/item/attempt와 compilation에 결박되고 exact 60초 expiry와 같은 bounded lifecycle을 가짐 |
| `cp_replay_tickets` | 한 번의 실행 attempt authority | exact compilation과 두 reservation FK, item attempt, Job, Replay Run, source root, claim principal/fence와 finalization에 결박 |
| `cp_replay_events` | Replay authority 감사 이력 | 상태 전이 transaction 안에서 append되고 update/delete 금지 |

Artifact metadata는 `cp_artifacts`에 따로 둔다. compilation/event row만 append-only이며 account와
reservation은 제한된 accounting lifecycle 안에서만 변경된다. 모든 authority-bearing foreign key와
uniqueness/check constraint는 database에서 강제한다. Replay event와 필요 시 대응하는 `cp_events`
summary는 같은 transaction에 기록한다.

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

### Internal-only Replay Job과 burn-on-claim lease

Replay Job은 Operator 제출 API에 노출하지 않는 internal kind다. Public `SubmitRunRequest`가
`replay`를 선택할 수 없고, Control Plane의 trusted batch service만 검증된 `cp_replay_item`과
fresh compilation, active reservation, ticket에서 Job을 생성한다. Worker startup registry에도 exact
Replay executor가 명시적으로 설치되어야 한다. Job payload는 opaque batch/item/ticket/artifact
reference와 서버 생성 `compilation_id`, `execution_context_id`, `execution_context_digest`,
`budget_reservation_id`, `rate_reservation_id` 권위만 포함하며 executable path, 임의 URL, callable
또는 Worker 선택 Grant를 포함하지 않는다. context의 `output_staging_id`도 opaque identity이며
filesystem 위치, storage operation, upload, import 또는 finalization을 허가하지 않는다.

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

### Authenticated Worker principal과 fencing

현재 요청 body의 `worker_id` 문자열만으로 Replay authority를 부여하지 않는다. 인증 middleware가
확정한 Worker principal subject를 등록된 Worker identity에 결박하고, claim/heartbeat/permit/
finalize의 actor는 그 principal에서만 파생한다.

모든 Replay mutation은 다음 값의 exact match를 요구한다.

- Worker principal subject와 허용된 Replay executor profile;
- Job ID와 lease-token digest;
- batch, item, ticket ID와 attempt number;
- ticket의 monotonically increasing fencing value;
- source root와 compilation digest; and
- active Run/batch/item/ticket state와 cancellation fence.

새 attempt가 만들어지거나 ticket이 abandoned/cancelled/finalized되면 이전 fence는 즉시 무효다.
stale Worker는 heartbeat, Tool-call permit, artifact import 완료 또는 finalization을 수행할 수 없다.
Worker credential 탈취나 Worker host compromise 자체는 별도 운영 위협이지만, 그런 Worker도
서버가 발급하지 않은 contract/Capability와 stale attempt를 PAJIN 결과로 확정할 수 없어야 한다.

### Durable budget reservation과 request-rate authority

구현된 내부 issuance service는 Job을 하나라도 만들기 전에 전체 eligible item과 반복 수의 정확한 첫
시도 Tool call 및 network request unit을 계산한다. PostgreSQL lock 아래에서 source Campaign의 budget
account를 만들거나 검증하고 sealed source Run/root, Campaign, budget digest, baseline use와 max를
결박하며 baseline + reserved + consumed가 max를 넘지 않도록 batch 전체를 reserve한다. Worker가 보고한
`usedCalls`는 정산 근거가 아니다.

rate account도 sealed `ledger_id`, rate snapshot digest와 observed Campaign request unit, managed
Artifact admission 시각인 `observed_at`, nullable `max_requests_per_minute`, 고정 60초 window를 결박한다.
service는 그 admission 시각부터 60초 동안 sealed observation unit을 보수적으로 계산하고 만료되지
않은 reservation을 잠근 뒤 첫 시도 전체를 더하면 cap을 넘을 경우 fail closed한다. 각 item은 60초
active request-unit reservation을 받는다.
per-minute cap이 없어도 exact source/account/reservation 결박은 생략하지 않는다.

같은 transaction은 최초 planned derivation record를 실행 권한으로 승격하지 않는다. 각 item을 fresh
Replay Run identity와 Grant로 다시 compile해 새 `cp_replay_compilations` row, active budget/rate
reservation, one-shot Job과 `issued` ticket을 만든다. schema-v5 FK는 ticket을 exact compilation과 두
reservation에 결박하고 strict Job payload도 같은 `compilation_id`, `budget_reservation_id`,
`rate_reservation_id`를 반복한다. 현재 active exact authority graph가 발급 직후 ticket/Job
`issued`/`queued`이거나 claim 뒤 `claimed`/`running`인 response-loss 재시도에만 이미 저장된 exact
item/ticket 집합을 재구성한다. 만료·terminal·binding drift 등 변경된 graph는 fail closed한다.

M6-07B-2D는 이 호출별 경계의 서버 원장/발급 절반을 구현한다. strict request는 Worker가 작성한
target, Tool, method, argument 또는 unit을 권위 입력으로 받지 않고 executor profile, lease token,
ticket ID, fencing value와 1-based call ordinal만 받는다. 내부 멱등 서비스는 active
principal/profile/lease/ticket fence, Run/batch/item/ticket lifecycle, canonical compilation/Grant, exact
reservation counter와 rolling request-rate state를 다시 검증한다. cap이 있으면 현재 sealed baseline,
60초 expiry가 아직 유효한 reservation의 미소비 잔여량, issuance window가 active인 permit과 새 trusted
request 비용을 합산한다. 만료된 reservation 잔여량은 capacity에 포함하지 않지만 만료 자체가 발급을
금지하지 않는다. cap이 없으면 rate 비교만 생략하고 exact counter는 계속 소비한다. 다음 ordinal만
허용하며 compiled call count 또는 reservation limit을 넘으면 fail closed한다. schema-v6 append-only
row는 exact ticket/compilation/reservation graph,
source/original request, canonical target/Tool/version/method/compiled argument digest, ordinal, Tool-call unit
하나와 trusted request unit을 결박한다. TTL은
`min(now + 30초, lease deadline, compiled-spec expiry, Grant expiry)`이며 rate reservation expiry를 cap으로
사용하지 않는다. `(ticket_id, call_ordinal)` unique constraint와 persisted permit
digest/request ID는 concurrent request 및 response-loss duplicate가 같은 permit을 한 번만 발급하게 한다.

최초 발급 transaction만 budget/rate reserved unit을 consumed로 옮기고 감사 event를 append한다. 이미
발급된 permit은 실행 여부가 불명확하더라도 자동 환불하지 않고 소비된 것으로 본다. abandon/cancel
뒤에는 새 permit을 발급하지 않으며, 명확히 미발급인 reservation만 감사 event와 함께 해제할 수 있다.
새 attempt는 남은 durable budget과 rate window를 다시 통과해야 한다. M6-07B-2E는
`POST /v1/worker/replay/jobs/claim`,
`POST /v1/worker/replay/jobs/{job_id}/heartbeat`,
`POST /v1/worker/replay/jobs/{job_id}/tool-permits`를 WORKER role에만 열고 대응 async client
method를 제공한다. `PAJIN_CP_REPLAY_EXECUTOR_PROFILES`는 strict JSON subject→profile-array
allowlist이며 미설정 시 빈 목록으로 fail closed한다. claim/heartbeat의
`ReplayExecutionClaimView`는 canonical `ReplayCompilation`을 포함하고 서버가 compilation,
Candidate, contract, Grant, Campaign, Mode, Candidate Run, Replay Run의 exact binding을 다시
검증한다. permit은 발급 시 소비가 완료된 non-bearer proof이므로 별도 redeem
mutation을 추가하지 않는다. 실제 Worker executor의 Tool call 직전 permit-use 집행은 아직
구현되지 않았다.

### Exact KISA execution-context authority

M6-07B-2F는 Worker를 authority source로 만들지 않으면서 issuance-time executor input을 durable하게
만든다. schema v7 append-only `cp_replay_execution_contexts` row는 compilation, item, batch, Replay
Run, compilation digest와 Grant digest FK identity를 통해 fresh `cp_replay_compilations` row 하나에
one-to-one으로 결박된다. canonical context bytes/digest, required executor profile과 output-staging
identity는 불변이며 context digest와 staging identity도 고유하다.

서버는 fresh compilation, reservation, one-shot Job, ticket과 같은 첫 시도 issuance transaction에서
context를 생성한다. context는 서버가 파생한 typed `CampaignManifest`, exact
`KISAScenarioDefinition`, canonical `AIChatProbeTool.spec`, 각각의 canonical component digest와 전체
context digest를 포함한다. source Artifact identity/root, policy version,
batch/item/compilation/Replay Run identity, 고정 `kisa-exact-v1` profile,
`secret_policy="forbidden"`, 빈 Secret Lease ID와 생성된 opaque `output_staging_id`도 같은 canonical
bytes에 포함된다. Worker는 이 값을 제출하거나 넓힐 수 없다.

strict Replay Job payload는 `execution_context_id`와 `execution_context_digest`를 반복한다. claim과
heartbeat는 canonical bytes, digest, row metadata, compilation, payload, Campaign, Scenario,
ToolSpec, policy, source와 Replay Run binding을 서버가 검증한 뒤에만 typed context를 반환한다.
executor-profile admission은 context의 고정 profile을 요구하고 permit issuance는 공통 active
authority verifier를 호출하므로 context/payload 치환은 permit도 차단한다. permit row가 context
identity를 반복할 필요는 없다. exact ticket/compilation graph가 one-to-one context에 전이적으로
결박하기 때문이다.

opaque output-staging slot은 의도적으로 storage 경계 전에 멈춘다. 후속 execute/seal과 output-import
설계가 허가할 slot의 이름일 뿐 path, mutable storage handle, ArtifactRef, upload capability,
imported artifact 또는 finalization evidence가 아니다. secret도 후속으로 미루지 않는다. 이 exact
KISA profile은 secret을 금지하고 Secret Lease ID를 받지 않는다.

v6→v7 migration은 이전 row에 이 authority 형태의 exact issuance-time Campaign, Scenario,
ToolSpec과 staging identity가 저장되지 않았으므로 execution context를 안전하게 backfill할 수 없다.
따라서 migration은 writer를 lock하고 issued/claimed ticket, permit, 내부 Replay Job, active authority
account/reservation 또는 planned/pending proof를 넘어선 batch/item 등 dispatch 가능한 v6 Replay
state가 하나라도 있으면 fail closed한다. non-dispatchable planned proof만 migration할 수 있고 가짜
context row를 만들지 않는다. 이 규칙은 호환성을 추측하지 않고 모든 schema-v7 context의 의미를
보존한다.

### Worker execute/seal과 authority finalize의 phase 분리

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

### Source-root CAS confirmation Gate

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

### Cancellation, abandonment와 lock ordering

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

PostgreSQL mutation은 ADR 0023/0024의 dependent-to-Run 순서 뒤에 Replay accounting/permit authority를
추가해 다음 순서를 지킨다.

```text
cp_jobs (stable Job ID order)
  -> cp_replay_tickets (stable attempt/ticket order)
  -> cp_replay_items (stable item order)
  -> cp_replay_batches
  -> cp_runs
  -> cp_replay_budget_accounts (canonical account order)
  -> cp_replay_rate_accounts (canonical account/window order)
  -> cp_replay_budget_reservations (stable reservation order)
  -> cp_replay_rate_reservations (stable reservation order)
  -> cp_replay_tool_permits (ticket, call ordinal order)
```

한 경로에 앞 단계 row가 없으면 그 단계를 건너뛰되 역순으로 잠그지 않는다. cancellation은 active
Job을 안정된 순서로 잠근 후 Replay dependent와 Run을 잠그며, 필요한 accounting row가 있으면 그 뒤에
잠근다. issuance, claim,
lease expiry, permit, finalization과 Gate publication도 같은 순서를 사용한다. Artifact hashing,
seal 검증과 Oracle 실행은 database lock을 잡지 않은 상태에서 수행하고 immutable reference와
CAS로 결과를 commit한다.

## First vertical slice and non-goals

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

현재 구현된 M6-07B-2F 조각은 schema-v7 exact execution-context authority와 그
payload/claim/profile/permit binding에서 끝난다. public Replay admission/read API, 실제 Worker
executor와 pre-dispatch permit-use enforcement, Worker execute/seal, output import와 typed artifact
finalization, 새 identity retry issuance, Gate와 negative Control Plane retest는 이 ADR의 후속 exit
criteria다. opaque staging slot은 이 경계 중 어느 것도 구현하지 않으며 Compose에는 활성 Replay
executor daemon이 없다. permit은 bearer credential이 아니므로 별도 redeem mutation을 exit
criterion으로 추가하지 않는다.

multi-host/object-store 지원은 immutable `ArtifactRef` resolver, upload authorization, retention,
encryption, tenant isolation과 cross-service authentication을 별도 ADR로 설계한 뒤 추가한다.

## Consequences

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
- Local M6-07A는 가벼운 단일 호스트 경로로 남고, 아직 미완료인 M6-07B
  executor/finalization/Gate 경로가 있다고 가장하지 않는다.

## Acceptance and validation

M6-07B-2F 최신화 기준 source admission/derivation, schema-v5 reservation authority, fresh 첫 시도
compilation, 원자적 내부 issuance와 issuance 멱등성, schema-v6 호출별 permit 원장/내부 서비스 발급,
fail-closed WORKER-only HTTP transport/async client, server-validated compilation claim envelope와
schema-v7 exact execution-context authority 및 그 transitive binding은 아래 항목 중 해당 server-side
부분을 충족한다. public admission/read API, 실제 executor/pre-dispatch permit use, Worker
execute/seal, output import/typed finalization, retry, Gate와 negative retest 항목은 M6-07B 전체의 exit
criteria로 유지한다. Compose에는 활성 Replay executor daemon이 없다.

이 ADR의 구현은 자동화된 테스트가 최소한 다음을 증명할 때 완료된다.

- forward migration이 빈 PostgreSQL과 직전 지원 version을 새 Replay schema로 올리고, unknown,
  partial 또는 constraint/trigger가 손상된 schema에서 서버가 fail closed한다. 특히 v6→v7은
  dispatch 가능한 v6 authority를 거부해 추측한 context bytes를 backfill하지 않고,
  non-dispatchable planned proof는 가짜 context row 없이 전진시킨다;
- public submission이 internal Replay kind, raw path/URL, Candidate, contract, Capability와 Worker
  verdict 주입을 거부한다. server-side sealed-source derivation만 exact KISA planned/pending,
  non-dispatchable compilation proof를 만든다. 내부 issuance는 source를 재검증하고 만료된 planned
  Grant를 재사용하지 않으며 같은 item에 fresh compilation row를 append하고 budget/rate authority를
  예약한 뒤, 각 첫 시도 Job/ticket을 그 row의 `compilation_id`, Replay Run identity,
  compilation/Grant digest, `budget_reservation_id`, `rate_reservation_id`에 원자적으로 결박한다.
  response-loss 재시도는 현재 active exact authority graph가 ticket/Job `issued`/`queued` 또는
  `claimed`/`running`일 때만 같은 exact authority 집합을 재구성하고, terminal 또는 변경된 graph는
  fail closed한다;
- 첫 시도 issuance가 fresh compilation마다 schema-v7 `cp_replay_execution_contexts` row를 정확히
  하나 append하고 exact typed Campaign, KISA Scenario, `AIChatProbeTool.spec`, 각 component digest,
  전체 context digest, source/policy identity, 고정 `kisa-exact-v1` profile, Secret Lease ID가 없는
  secret 금지와 opaque unique output-staging identity를 canonical하게 결박한다. Job payload,
  claim/heartbeat, profile admission과 permit issuance는 context/digest/component/transitive authority
  치환을 거부하고 staging identity만으로는 storage, execution, import 또는 finalization을 허가할 수
  없다;
- strict permit input은 executor profile, lease token, ticket ID, fencing value와 1-based ordinal만 받고
  target/Tool/method/argument/unit 주입을 거부한다. 서버가 exact active authority와 canonical operation을
  파생하고 current baseline/post-admission live reservation remainder/active permit/new cost로 rolling-window rate
  재수용을 수행하며, persisted permit digest/request ID를 포함한 exact response-loss duplicate만 같은 row를
  counter/event 중복 없이 반환한다;
- source와 replay `ArtifactRef`의 content, Run ID, seal root, artifact set 또는 repository version
  치환과 symlink/path traversal이 server-side verification에서 거부된다;
- 두 Worker가 같은 queued Replay Job/ticket을 동시에 claim해 정확히 하나만 성공하고 principal,
  lease token, ticket과 fence가 같은 transaction에 결박된다;
- claim된 Worker가 crash하거나 lease가 만료되면 이전 ticket과 Job은 재큐잉되지 않고 abandoned가
  되며, retry는 새 attempt/ticket/Replay Run/Job ID를 사용한다;
- stale Worker가 heartbeat, permit, artifact import 완료와 finalization을 시도해도 거부되고 새
  attempt의 budget, rate state 또는 결과를 바꾸지 못한다;
- 여러 Worker의 동시 permit 요청이 reserved Tool-call budget과 durable rate window를 초과하지 않고,
  duplicate ordinal은 한 번만 소비되며 ordinal gap, over-limit, expired/finalized/abandoned/cancelled
  ticket은 새 permit을 받지 못한다;
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
  만족한다; and
- 단일 호스트 KISA end-to-end가 sealed source admission부터 internal Candidate -> Replay -> Gate,
  versioned Confirmed projection까지 성공하되 semantic-only, coverage 누락, unsupported scenario와
  tampered artifact는 confirmation하지 않는다.

## Relationship to prior decisions

- [ADR 0011](0011-durable-control-plane.md)의 PostgreSQL orchestration/authorization 경계를
  확장하고, 당시 future work였던 managed forward migration을 Replay schema부터 요구한다. 기존
  Run/Job/checkpoint/approval/event 의미는 Replay 전용 aggregate와 typed completion 없이는 충분하지
  않다.
- [ADR 0012](0012-lease-aware-worker-daemon.md)의 authenticated lease, trusted executor registry,
  heartbeat와 at-least-once 전달을 재사용한다. 단, Replay claim 뒤에는 같은 Job을 재큐잉하지 않고
  새 ticket/Job attempt를 만드는 더 강한 예외를 둔다.
- [ADR 0024](0024-cooperative-execution-cancellation.md)의 first-write-wins cancellation과 local
  cleanup receipt 한계를 유지한다. 이 ADR의 `abandoned`는 durable execution-authority fence이지
  physical quiescence attestation이 아니다.
- [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)의 Candidate/Compiler/
  Restricted Reproducer/Mode Oracle/common Gate와 `confirmed` 불변식을 바꾸지 않는다. Control
  Plane은 그 입력을 sealed source에서 파생하고 finalized receipt를 다시 검증하는 orchestration
  authority를 추가할 뿐이다.
- [ADR 0028](0028-durable-local-replay-ticket-ledger.md)의 canonical compilation binding,
  burn-on-claim, exact idempotent finalization과 read-only restart verification 원칙을 PostgreSQL
  failure model에 맞게 확장한다. SQLite 파일이나 Local writer를 분산 authority로 승격하지 않는다.

## References

- [Control Plane typed contracts](../../src/pajin/control_plane/models.py)
- [Control Plane database schema](../../src/pajin/control_plane/database.py)
- [Control Plane transactional service](../../src/pajin/control_plane/service.py)
- [Lease-aware Worker daemon](../../src/pajin/control_plane/worker.py)
- [Trusted executor registry](../../src/pajin/control_plane/executors.py)
- [Run integrity store and verifier](../../src/pajin/runtime/store.py)
- [Restricted Replay runtime and verified loader](../../src/pajin/replay/runtime.py)
- [SQLite durable Replay ticket authority](../../src/pajin/replay/sqlite_tickets.py)
- [KISA sealed-source Replay coordinator](../../src/pajin/modes/ai_redteam/replay.py)
