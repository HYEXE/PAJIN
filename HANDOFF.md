# PAJIN 개발 인수인계

- 기록일: 2026-08-09
- 브랜치: `main`
- 현재 기능 HEAD: `ac021a8a6eb314f9797a4c53ec93710731756a25`
- 현재 코드 체크포인트: Phase 7 완료 — `SUP-007A/B` T0/T1과 `SUP-008` 사전 승인 T2 no-write Control Plane profile
- 문서 동기화: 이 파일을 포함하는 후속 `docs(handoff)` 커밋에서 현재 체크포인트를 동기화
- 원격 기준: `origin/main@021a1f4ee327fd04ee5413ee3ef3618c2d08f766`
- APPROVAL-001A 구현 커밋: `8733ccc51a00ab0efc34a2f6dfa288ca930f3e1b`
- APPROVAL-001B 구현 커밋: `6c75896ad7a52796d9dd2193e96b2f42724c407f`
- APPROVAL-001C1/C2 구현 커밋: `ba7274af4f96c1207b9d5dd509b659877f2a27b5`
- APPROVAL-001C3 구현 커밋: `613425367ef7a8f2e881812559efb48e4dc9d73d`
- SUP-007A 구현 커밋: `16fe8d1f44e5524cfe0f9a68b86d9126848ef091`
- SUP-007B 구현 커밋: `2434e83dd80df1dface1f0e68fab41d0b4ecfd1b`
- SUP-008 구현 커밋: `ac021a8a6eb314f9797a4c53ec93710731756a25`
- 현재 구현 체크포인트: 기존 Approval·Permit·receipt·Gateway·managed Run·Outcome 권한을 재사용하는 approval-free/approved General Attack profile
- 다음 로드맵: Phase 8 `CHAIN-001` Auth Bypass에서 AI Admin Surface까지의 mode-neutral attack chain 계약
- 원격 push: 수행하지 않음. 이 문서 동기화 커밋 뒤 로컬 `main`은 `origin/main@021a1f4`보다 8 commits ahead

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. SUP-007A는 `16fe8d1`, SUP-007B는 `2434e83`, SUP-008은 `ac021a8`에
보존됐다. 이 문서 동기화 커밋 뒤 로컬 `main`은 `origin/main@021a1f4`보다 8 commits ahead이고 working tree는
clean이어야 한다.
별도 detached worktree
`C:\Users\hyeon\.codex\worktrees\6b64\PAJIN`에는 이전 중복 변경이 남아 있으므로 사용자의 명시적
요청 없이 정리·reset·stash·삭제하지 않는다.

## 현재 구현 상태

`APPROVAL-001A`는 기존 GRAPH-006 최종 transaction을 재사용해 deployment-authenticated 단일
operator approval, 기존 consumed `ActionPermit`, non-reusable consumption receipt를 원자적으로
소비한다.

`APPROVAL-001B`는 이 no-write 경계를 유지하면서 General Attack의
`reversible-write + cleanupRequired=true`에 한해 approval, 기존 consumed ActionPermit,
non-reusable receipt와 기존 cleanup reservation을 schema v4 transaction 하나에서 원자 소비한다.

`APPROVAL-001C1/C2`는 기존 single-action authority를 2~8개 ordered host-local async batch로
조정한다. no-write 항목은 APPROVAL-001A, reversible-write 항목은 APPROVAL-001B combined authority를
그대로 호출한다. reversible terminal은 exact cleanup reservation과 deployment-authenticated
restored-state evidence를 요구하며, partial/unknown 상태는 자동 redispatch 권위를 만들지 않는다.

`APPROVAL-001C3`는 기본 단건 경로를 유지하면서 두 opt-in surface만 추가한다. General Attack은
`dispatch_approved_batch_item_once()`가 current approval과 reversible cleanup request를 다시 만들고 gate의
기존 Graph store/verifier로 batch authority를 구성한다. Control Plane은 deployment v1alpha2가 exact batch,
journal path와 optional cancellation을 pin한 경우 `capability-graph-batch-v1` Job만 실행한다. Gateway Run
seal을 journal completion 전에 검증하고 exact retry는 Worker를 재호출하지 않는다. journal backup은 local
content-addressed manifest와 새 경로 restore만 제공하며 retention assessment는 pending·unknown을 항상
삭제 부적격으로 둔다. 실제 삭제, remote signature/encryption과 cross-host authority는 없다.

`SUP-007A`는 기존 General Attack Proposal·compiler, GRAPH Permit, Capability Gateway, managed Run audit와
PERMIT-004A outcome authority를 하나의 explicit direct-call gate로 조합한다. T0/T1 `none`·`read-only`만
허용하며 exact retry, callback 실패, 취소 또는 authority 대체가 Worker 재호출 권위를 만들지 않는다.

`SUP-007B`는 같은 조합을 기존 Control Plane Campaign executor의 `general-attack-v1` profile로 노출한다.
startup SHA-256-pinned Capability Graph deployment가 Campaign·Envelope·activation·Graph store·Run root·
Tool registry·Worker를 소유하고, executor는 strict Job source에서 Proposal과 intent를 다시 만든다. 첫 profile은
approval-free, non-networked, zero-cost T0/T1 no-write로 제한된다. T2, T3+, write, caller pricing과 기존 default
Campaign workflow는 계속 닫혀 있다.

`SUP-008`은 별도 `general-attack-approved-v1` profile에서 deployment가 이미 pin한 Approval inventory와
`ActionApprovalInputAuthority`를 `capability-graph-v1`과 동일한 인스턴스로 재사용한다. strict Job approval은
deployment inventory와 exact-match해야 하며 APPROVAL-001A가 Approval·Permit·non-reusable receipt를 원자
소비한다. 완료 결과와 PERMIT-004A assessment는 durable approval/receipt ID·digest를 결박한다. 승인 대상 T2
no-write와 Definition-required T0/T1만 허용하며 T3+, write, network, priced action은 닫혀 있다.

- `ActionApprovalEnvelope`는 `mode=single`, JSON integer `maxActions=1`로 고정하고 issuer·requester·
  approver, Campaign·Run·MissionEnvelope, source intent·activation set, signed release·Capability,
  GraphDecision·ActionProposal·request·target·risk·reservation·expected Permit·time window를 결박한다.
- content digest는 issuer 서명이 아니다. deployment-pinned `ActionApprovalInputAuthority`가 high-level
  authority와 SQLite transaction 안팎에서 complete input을 검증하며 permissive 기본 구현은 없다.
- full activation `ActionApprovalCapabilityPolicyRegistry`와 plain·approved·reversible·cleanup 전용
  non-transferable writer token을 사용한다. generic caller나 per-call policy/verifier가 specialized
  transaction을 호출할 수 없다.
- schema v4는 append-only approval·receipt ledger를 추가하고 approval·Permit·receipt를 all-or-nothing으로
  커밋한다. store post-verifier 실패는 rollback하고, high-level post-verifier 실패는 이미 소비된 tuple을
  유지해 다음 exact retry가 `newlyConsumed=false`로만 복구한다.
- exact retry는 approval expiry 뒤에도 같은 durable Permit·receipt를 반환하고 Worker를 재호출하지 않는다.
  callback 실패·unknown outcome도 authority를 복구하지 않는다.
- General Attack은 T2 no-write와 T0/T1 `approvalRequired`에 approval을 요구한다. outcome gate는 durable
  receipt를 다시 조회해 exact-match하고 assessment에 approval·receipt ID/digest를 결박한다.
- `capability-graph-v1`은 deployment approval inventory와 issuer verifier를 고정하고 Job·prepared action·
  activation의 release 5-tuple을 재검증한다. completion result는 durable approval·receipt ID/digest를
  최초 실행과 retry에 동일하게 노출한다.
- Common Engine과 legacy `deterministic-local`은 approval-aware composition이 없으므로 T2를 Permit 전에
  거부한다. Web Console 기본 실행은 bounded T0 `mock-sleep`으로 유지한다.
- T2 또는 Definition `approvalRequired` reversible-write는 deployment approval verifier와 code-owned
  cleanup mapping verifier가 모두 있을 때만 combined writer를 사용한다. 어느 insert나 transaction 내부
  post-verifier가 실패해도 네 ledger가 모두 rollback한다.
- exact retry와 verified backup/restore retry는 같은 네 레코드를 `newlyConsumed=false`로 반환하고
  Worker를 다시 호출하지 않는다. authenticated outcome은 approval side-effect·cleanup flags를 current
  signed Definition과 다시 exact-match한 뒤 기존 PERMIT-004B2 cleanup 경로에 전달한다.
- production inventory와 `capability-graph-v1`, Common Engine, legacy write는 계속 닫혀 있다. Control Plane
  batch write, T3+와 기본 runtime batch/async workflow도 fail closed한다.
- current direct/retained Graph backup은 v1alpha3/schema v4다. strict v1alpha2/schema v3와
  v1alpha1/schema v2 reader·migration은 legacy material을 검증하되 approval을 backfill하지 않는다.

핵심 위치:

- `src/pajin/graph/approval.py`
- `src/pajin/graph/approved_cleanup.py`
- `src/pajin/graph/approval_batch.py`
- `src/pajin/graph/sqlite_store.py`
- `src/pajin/graph/authority.py`
- `src/pajin/graph/cleanup.py`
- `src/pajin/graph/backup_retention.py`
- `src/pajin/supervision/action_permit.py`
- `src/pajin/supervision/action_outcome.py`
- `src/pajin/supervision/action_execution.py`
- `src/pajin/control_plane/capability_deployment.py`
- `src/pajin/control_plane/executors.py`
- `src/pajin/workflow/engine_execution_gate.py`
- `docs/orchestration/APPROVAL-001A-single-action-approval.md`
- `docs/orchestration/APPROVAL-001B-approved-reversible-cleanup-hold.md`
- `docs/orchestration/APPROVAL-001C1-bounded-async-approval-batch.md`
- `docs/orchestration/APPROVAL-001C2-reversible-async-approval-batch.md`
- `docs/orchestration/APPROVAL-001C3-opt-in-batch-runtime-and-retention.md`
- `docs/orchestration/SUP-007A-opt-in-general-attack-execution.md`
- `docs/orchestration/SUP-007B-control-plane-general-attack-profile.md`
- `docs/orchestration/SUP-008-approved-general-attack-control-plane-profile.md`
- `docs/adr/0134-consume-single-approval-with-action-permit.md`
- `docs/adr/0135-atomically-bind-approval-and-cleanup-hold.md`
- `docs/adr/0136-coordinate-bounded-async-approval-batches.md`
- `docs/adr/0137-bind-reversible-batch-items-to-cleanup-authority.md`
- `docs/adr/0138-compose-opt-in-batch-runtime-and-journal-retention.md`
- `docs/adr/0139-compose-general-attack-through-managed-gateway.md`
- `docs/adr/0140-expose-general-attack-through-control-plane.md`
- `docs/adr/0141-compose-approved-general-attack-profile.md`

## 현재 검증

### 2026-08-09 SUP-008 사전 승인 T2 profile 집중·통합 검증

- SUP-008 구현 커밋: `ac021a8`
- General Attack approval·execution·Permit 집중 회귀: 55 passed
- Capability Graph approval store·rollout·outcome 인접 회귀: 77 passed
- General Attack Proposal·Permit·execution·outcome·Control Plane·rollout 통합 회귀: 161 passed
- Control Plane 인접 회귀: 116 passed, 1 skipped
  - skip: 격리된 `PAJIN_TEST_CONTROL_PLANE_URL` 미설정
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 258 source files 통과
- 변경 Python format check: 통과
- 변경 Markdown 13개 상대 링크 검사: 통과
- `git diff --cached --check`: 통과
- 전체 pytest는 SUP-007B 체크포인트에서 15분 상한과 기존 Artifact admission 메시지 불일치를 이미
  재현했으므로 동일 원인의 전 범위 실행을 반복하지 않았다. SUP-008 관련·인접 묶음은 위와 같이 통과했다.

### 2026-08-09 SUP-007A/B 집중·통합 검증

- SUP-007A 구현 커밋: `16fe8d1`
- SUP-007B 구현 커밋: `2434e83`
- General Attack 실행·Proposal·Permit·Outcome·Capability rollout 회귀: 156 passed
- General Attack direct-call·Control Plane 집중 회귀: 20 passed
- Control Plane 인접 회귀: 116 passed, 1 skipped
  - skip: 격리된 `PAJIN_TEST_CONTROL_PLANE_URL` 미설정
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 258 source files 통과
- 변경 Python format check: 통과
- 변경 Markdown 11개 상대 링크 검사: 통과
- `git diff --cached --check`: 통과
- 전체 pytest: 15분 상한에서 약 45%까지 진행 후 timeout. 여러 실패 표시가 관찰됐고,
  `-x` 최초 실패 재현은 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지 불일치 1건이다.
  이번 SUP-007B diff에는 해당 모듈과 테스트가 포함되지 않는다.

### 2026-08-09 APPROVAL-001C3 집중·통합 검증

- C3 batch runtime·backup/restore 집중 묶음: 85 passed
- APPROVAL-001A/B/C1/C2·General Attack outcome/cleanup·Control Plane 인접 회귀: 180 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 257 source files 통과
- 변경 Python format check: 통과
- 전체 pytest: 20분 상한에서 약 64%까지 진행 후 timeout. 최초 실패 재현은
  `tests/test_control_plane_artifact_admission.py::test_artifact_admission_rejects_mismatched_sealed_run_without_authority`
  의 오류 메시지 기대값(`not admission-bound`)과 실제 상위 오류(`staged source Artifact failed managed admission`)
  불일치이며 C3 변경 파일 밖이다. `-x` 재현 결과 634 passed, 11 skipped 뒤 해당 1 failure다.

### 2026-08-06 APPROVAL-001C1/C2 집중 검증

- 새 no-write/reversible batch model·journal·dispatcher 집중 테스트: 13 passed
- 기존 APPROVAL-001A/B·Permit·General Attack과 C1/C2 결합 회귀: 161 passed
- Graph 전체 모듈 회귀: 178 passed, 2 skipped(POSIX link semantics)
- Ruff 전체: 통과
- Linux 대상 strict mypy: 257 source files 통과
- 변경 Python format check: 통과
- 공개 `pajin.graph` import: 통과

### 2026-08-06 저장소 전 범위 리팩터링·안정화 재검증

- APPROVAL-001B 중복 구조 정리 뒤 benchmark distribution fixture 만료, Capability 발급 wall-clock,
  긴 환경변수, Windows `uv`·절대 경로, MCP envelope, 패키징 source tree, POSIX mode·process-group,
  Linux container observation fixture의 실제 실패를 각각 독립 커밋으로 수정했다.
- Windows first-failure 전체 회귀는 POSIX 전용 파일을 제외한 상태에서 1,063 passed, 78 skipped까지
  진행한 뒤 stale MCP fixture를 찾았고, 수정 후 나머지는 파일 묶음으로 분할 검증했다.
- error-safety부터 Graph admission: 362 passed
- Graph backup·CampaignFact·SQLite·KISA·local replay: 195 passed, 2 skipped
- policy·provider·replay runtime 1차: 264 passed, 1 skipped
  - replay tickets 전체: 39 passed, 10 skipped
  - replay verify CLI·worker process: 11 passed, 1 skipped
- safe-files·scope·secrets·Supervisor: 206 passed, 2 skipped
- Tool Loop 전체: 37 passed, validation artifact 묶음: 51 passed
- Worker HTTP 전체: 35 passed, 1 skipped
- workflow integrity 전체: 20 passed, YAML loader: 18 passed
- 패키징은 생성 console-script 실행 smoke 1건을 제외한 16건이 통과했다. 제외한 한 건도 clean
  wheel/sdist build·install·import·metadata까지 통과한 뒤 조직 Windows 애플리케이션 제어가 임시
  console-script `.exe` 실행을 `WinError 4551`로 차단했다.
- Ruff 전체: 통과
- Linux 대상 strict mypy: 256 source files 통과
- Windows 대상 mypy: 배포 코드의 POSIX 전용 `os` API 33건만 실패
- `git diff --check`: 통과
- Windows에서 단일 전체 pytest는 POSIX directory fsync·dirfd·비이식 파일명·worker daemon 경계 때문에
  완료하지 못했다. `tests/test_control_plane_artifacts.py`, `test_control_plane_artifact_admission.py`,
  `test_control_plane_replay.py`, `test_integrity.py`, `test_worker_daemon.py`, `test_worker_health.py`의
  Linux 경로와 packaging console-wrapper smoke는 Linux CI 또는 허용된 환경에서 재검증해야 한다.

아래 항목은 APPROVAL-001B 구현 완료 시점의 더 넓은 검증 기록이다.

- APPROVAL/PERMIT/General Attack 집중 회귀: 131 passed
- approval store·legacy backup·Graph SQLite 인접 회귀: 36 passed, 2 skipped
- existing Capability rollout: 35 passed
- Control Plane Web: 14 passed, 1 skipped
  - Node.js 미제공으로 dependency-free Web Console runtime 1건 skip
- Common Engine execution gate: 8 passed
  - Windows 환경에서 마지막 두 테스트가 각각 약 60~70초 걸려 6+1+1로 분할 실행
- 관련 검증 합계: 224 passed, 3 skipped
- Ruff 전체: 통과
- Linux 대상 strict mypy: 256 source files 통과
- 변경 모듈 `python -B` import 검증: 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 Benchmark registry fixture 만료에서 중단
  - 오류: `Benchmark registry distribution is not currently valid`
  - 이번 승인 변경의 회귀와 구분한다.
- `git diff --check`: 통과
- `compileall`은 기존 `src/**/__pycache__` 권한 때문에 `.pyc` 교체에서 실패했다. 같은 모듈의
  no-bytecode import와 Ruff·mypy·pytest 통과로 구문 실패와 구분한다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_approval_models.py tests\test_graph_action_permit.py tests\test_general_attack_action_permit.py tests\test_general_attack_action_outcome.py tests\test_general_attack_action_cleanup.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_approval_store.py tests\test_graph_backup_v2_compatibility.py tests\test_graph_sqlite_store.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_existing_capability_rollout.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_control_plane_web.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_execution_gate.py
.\.venv\Scripts\python.exe -m ruff check --no-cache src tests containers
New-Item -ItemType Directory -Path ..\.codex-tmp\pajin-mypy -Force | Out-Null
.\.venv\Scripts\python.exe -m mypy --platform linux --cache-dir ..\.codex-tmp\pajin-mypy src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 안정화 점검

contract·quality·trust 관점의 병렬 읽기 전용 검토에서 초기 구현의 retry registry object-identity,
stale test double, generic policy/verifier bypass, approval receipt outcome 누락, cross-release substitution,
strict JSON boolean/number coercion, Control Plane receipt surface와 store post-verification rollback 공백을
찾았다. canonical policy digest, path-specific writer, full activation registry, strict before-validator,
release 5-tuple, durable receipt assessment/completion binding과 transaction 내부 post-verification으로
수정했다. 다른 정상 receipt 치환, 다른 policy registry 재claim과 post-verifier 실패를 음성 테스트로
고정한 뒤 최종 검토에서 P0~P2가 남지 않았다.

이번 짧은 안정화 점검에서는 HANDOFF가 실제 `8733ccc` 커밋을 반영하지 않던 문서 드리프트,
reversible approval scope의 strict JSON pairing, 기존 no-write authority와 새 write authority의 policy
분리, outcome의 approval side-effect·cleanup Definition 교차검증 누락을 수정했다. generic writer,
cleanup insert failure, transaction post-verifier drift와 backup/restore retry를 음성·원자성 테스트로
고정했다.

동작 보존 리팩터링에서는 승인·Permit·receipt·cleanup hold 결과의 row decode와 authorization 조립을
단일 헬퍼로 모으고, SQLite 원자 트랜잭션의 기존 tuple 조회와 식별자 충돌 SQL을 분리했다. high-level
authority의 canonical·exact-result 검증과 General Attack dispatcher의 envelope·activation pin도 공통
경로로 모았다. wire shape, schema version, 공개 authority, error branch와 검증 순서는 변경하지 않았다.

## 현재 상태와 다음 한 단계

APPROVAL-001C3는 `6134253`에 보존됐다. 현재 working tree의 SUP-007A는 `GeneralAttackActionExecutionGate`를
추가해 deployment-owned 실행 입력, managed Run anchor, 기존 GRAPH Permit, Capability Gateway, Worker와
PERMIT-004A outcome을 하나의 명시적 direct-call T0/T1 no-write 경로로 조합한다. 새 Permit·Grant·store·record
type은 추가하지 않으며 T2/T3+, write, cleanup-required, 자동 redispatch와 기존 default workflow는 닫혀 있다.

1. SUP-007A 집중 11 tests와 Proposal·Permit·Outcome·rollout 인접 통합 147 tests가 통과했다.
2. 전체 Linux 대상 strict mypy는 258 source files에서 통과했다.
3. 현재 변경은 미커밋이다. 사용자가 로컬 커밋을 승인하면 SUP-007A 코드·테스트·문서만 명시적으로 stage하고
   한글 Conventional Commit으로 보존한다.
4. push는 별도 명시 승인 전까지 수행하지 않는다. 다음 수직 슬라이스는 SUP-007B의 구체 제품 노출과 T2
   사전 승인 정책이다.

## 알려진 경계

- policy registry, writer token, approval verifier와 cleanup verifier는 process-local deployment TCB다.
  approval·Permit·receipt·cleanup hold 소비는 durable하지만 verifier code identity는 SQLite에 pin되지
  않는다.
- current production inventory에는 reversible-write Capability가 없다. `capability-graph-v1`, Common
  Engine과 legacy write는 cleanup authority composition이 없어 닫혀 있다.
- C3는 General Attack 별도 메서드와 Control Plane 별도 Job profile에서만 opt-in된다. 기본 batch workflow,
  cleanup-hold aggregation, Control Plane write, cross-host coordination과 T3+는 미지원이다.
- batch journal과 Graph DB는 하나의 transaction이 아니므로 경계 crash는 manual review로 닫히며 자동
  redispatch하지 않는다. local backup/restore는 이를 그대로 보존하지만 signed/encrypted remote retention,
  anti-rollback repository와 durable verifier identity는 아직 없다. journal 삭제도 구현하지 않았다.
- Graph schema v4 direct downgrade는 없다. rollback 시 v4 reader와 immutable consumption evidence를
  유지해야 한다.
- Windows `dirfd`/directory fsync/symlink/비이식 파일명과 조직 AppControl 제약은 코드 회귀와 구분한다.
- Docker daemon과 real-container 경로는 이번 체크포인트에서 확인하지 않았다.
