# PAJIN 개발 인수인계

- 기록일: 2026-08-06
- 브랜치: `main`
- 원격 기준: `origin/main@e05e672314f44790bb662b039d48127be06c1d35`
- APPROVAL-001A 구현 커밋: `8733ccc51a00ab0efc34a2f6dfa288ca930f3e1b`
- APPROVAL-001B 구현 커밋: `6c75896ad7a52796d9dd2193e96b2f42724c407f`
- 현재 구현 체크포인트: `APPROVAL-001B` 완료
- 다음 사용자 체크포인트: 안정화·리팩터링 점검
- 이후 로드맵: `APPROVAL-001C` bounded batch·async approval
- 원격 push: 미실행

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. 이 HANDOFF 동기화 커밋까지 포함한 `main`은
`origin/main`보다 3개 커밋 앞서 있어야 한다. 별도 detached worktree
`C:\Users\hyeon\.codex\worktrees\6b64\PAJIN`에는 이전 중복 변경이 남아 있으므로 사용자의 명시적
요청 없이 정리·reset·stash·삭제하지 않는다.

## 현재 구현 상태

`APPROVAL-001A`는 기존 GRAPH-006 최종 transaction을 재사용해 deployment-authenticated 단일
operator approval, 기존 consumed `ActionPermit`, non-reusable consumption receipt를 원자적으로
소비한다.

`APPROVAL-001B`는 이 no-write 경계를 유지하면서 General Attack의
`reversible-write + cleanupRequired=true`에 한해 approval, 기존 consumed ActionPermit,
non-reusable receipt와 기존 cleanup reservation을 schema v4 transaction 하나에서 원자 소비한다.

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
- production inventory와 `capability-graph-v1`, Common Engine, legacy write는 계속 닫혀 있다. T3+, batch,
  async도 미지원이며 `APPROVAL-001C` 전까지 fail closed한다.
- current direct/retained Graph backup은 v1alpha3/schema v4다. strict v1alpha2/schema v3와
  v1alpha1/schema v2 reader·migration은 legacy material을 검증하되 approval을 backfill하지 않는다.

핵심 위치:

- `src/pajin/graph/approval.py`
- `src/pajin/graph/approved_cleanup.py`
- `src/pajin/graph/sqlite_store.py`
- `src/pajin/graph/authority.py`
- `src/pajin/graph/cleanup.py`
- `src/pajin/graph/backup_retention.py`
- `src/pajin/supervision/action_permit.py`
- `src/pajin/supervision/action_outcome.py`
- `src/pajin/control_plane/capability_deployment.py`
- `src/pajin/control_plane/executors.py`
- `src/pajin/workflow/engine_execution_gate.py`
- `docs/orchestration/APPROVAL-001A-single-action-approval.md`
- `docs/orchestration/APPROVAL-001B-approved-reversible-cleanup-hold.md`
- `docs/adr/0134-consume-single-approval-with-action-permit.md`
- `docs/adr/0135-atomically-bind-approval-and-cleanup-hold.md`

## 현재 검증

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
.\.venv\Scripts\python.exe -m mypy --no-incremental --no-sqlite-cache --platform linux src
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

## 현재 상태와 다음 한 단계

APPROVAL-001A와 APPROVAL-001B 구현은 각각 `8733ccc`, `6c75896`에 로컬 커밋됐다. 이 HANDOFF
동기화 커밋 뒤 worktree가 clean이고 `origin/main`보다 3개 앞선 상태인지 확인한다.

1. 사용자가 요청할 안정화·리팩터링 체크포인트 전에는 APPROVAL-001C 기능을 시작하지 않는다.
2. 리팩터링은 동작을 바꾸지 않는 범위에서 combined authority/store의 중복 validation·retry 구조,
   General Attack dispatcher composition, 대형 SQLite transaction 메서드와 테스트 fixture 중복을 먼저
   점검한다. 실제 버그는 재현 테스트와 함께 별도 작은 커밋으로 수정한다.
3. 리팩터링 체크포인트가 끝난 뒤 `APPROVAL-001C` batch·async 상태 머신을 새 계약·ADR로 시작한다.
4. 원격 push는 별도 사용자 승인 뒤 `git -c http.sslBackend=schannel push origin main`으로 수행하고
   local/upstream/remote/clean 상태를 재검증한다.

## 알려진 경계

- policy registry, writer token, approval verifier와 cleanup verifier는 process-local deployment TCB다.
  approval·Permit·receipt·cleanup hold 소비는 durable하지만 verifier code identity는 SQLite에 pin되지
  않는다.
- current production inventory에는 reversible-write Capability가 없다. `capability-graph-v1`, Common
  Engine과 legacy write는 cleanup authority composition이 없어 닫혀 있다.
- T3+·batch·async와 partial/unknown batch claim은 미지원이다.
- Graph schema v4 direct downgrade는 없다. rollback 시 v4 reader와 immutable consumption evidence를
  유지해야 한다.
- 전체 pytest의 Benchmark registry 만료, Windows `dirfd`/symlink 제약은 코드 회귀와 구분한다.
- Docker daemon과 real-container 경로는 이번 체크포인트에서 확인하지 않았다.
