# PAJIN 개발 인수인계

- 기록일: 2026-08-06
- 브랜치: `main`
- 작업 시작 및 현재 기준 HEAD: `e05e672314f44790bb662b039d48127be06c1d35`
- 현재 구현 체크포인트: `APPROVAL-001A` Single T2 No-write Approval
- 다음 구현: `APPROVAL-001B` T2 Write Approval·Cleanup Hold Atomic Binding
- delivery 상태: 구현·검토·최종 재검증 완료, 관련 없는 formatter 변경 복구와 의도 파일 내부
  정리 완료, 로컬 커밋 준비됨

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. 관련 없는 Python formatter 변경 88개는 HEAD로 복구했고,
APPROVAL-001A 의도 변경만 남겼다. `git status`가 Windows index refresh 제약으로 복구된 파일을
계속 표시할 수 있으므로 실제 내용 변경은 `git diff --name-only`와 `git diff`로 대조한다.

## 현재 구현 상태

`APPROVAL-001A`는 기존 GRAPH-006 최종 transaction을 재사용해 deployment-authenticated 단일
operator approval, 기존 consumed `ActionPermit`, non-reusable consumption receipt를 원자적으로
소비한다.

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
- T2 write와 `approvalRequired` write는 approval+cleanup 결합 authority가 없어 거부한다. T3+, batch,
  async도 미지원이며 `APPROVAL-001B/C` 전까지 fail closed한다.
- current direct/retained Graph backup은 v1alpha3/schema v4다. strict v1alpha2/schema v3와
  v1alpha1/schema v2 reader·migration은 legacy material을 검증하되 approval을 backfill하지 않는다.

핵심 위치:

- `src/pajin/graph/approval.py`
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
- `docs/adr/0134-consume-single-approval-with-action-permit.md`

## 현재 검증

- Graph approval model/store/backup 최종 묶음: 43 passed
- Graph Permit·SQLite 인접 회귀: 59 passed, 2 skipped
- General Attack Permit·Outcome·Cleanup: 60 passed
- Control Plane rollout·Web: 49 passed, 1 skipped
- Common Engine execution gate: 8 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 255 source files 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 Benchmark registry fixture 만료에서 중단
  - 오류: `Benchmark registry distribution is not currently valid`
  - 이번 승인 변경의 회귀와 구분한다.
- Worker daemon 전체: 59 passed, 1 skipped, 25 failed
  - Windows POSIX `dirfd` 부재와 symlink 생성 `WinError 1314`에서 실패했다.
  - 승인 경로는 별도 Control Plane rollout 테스트가 통과했다.
- `git diff --check`: 통과
- 독립 contract·quality·trust 재검토: 현재 Job/input 공격자 경계에서 P0~P2 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_approval_models.py tests\test_graph_action_approval_store.py tests\test_graph_backup_v2_compatibility.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_permit.py tests\test_graph_sqlite_store.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_permit.py tests\test_general_attack_action_outcome.py tests\test_general_attack_action_cleanup.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_existing_capability_rollout.py tests\test_control_plane_web.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_execution_gate.py
.\.venv\Scripts\python.exe -m ruff check src tests containers
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 독립 검토

contract·quality·trust 관점의 병렬 읽기 전용 검토에서 초기 구현의 retry registry object-identity,
stale test double, generic policy/verifier bypass, approval receipt outcome 누락, cross-release substitution,
strict JSON boolean/number coercion, Control Plane receipt surface와 store post-verification rollback 공백을
찾았다. canonical policy digest, path-specific writer, full activation registry, strict before-validator,
release 5-tuple, durable receipt assessment/completion binding과 transaction 내부 post-verification으로
수정했다. 다른 정상 receipt 치환, 다른 policy registry 재claim과 post-verifier 실패를 음성 테스트로
고정한 뒤 최종 검토에서 P0~P2가 남지 않았다.

## 현재 차단 요인과 다음 한 단계

의도한 APPROVAL-001A 변경은 tracked 29개와 신규 6개 파일이다. 관련 없는 tracked Python 88개와
의도 파일 내부의 기계적 formatter noise는 복구했고 `git diff --check`가 통과했다.

1. 명시적 35개 파일만 stage하고 staged diff를 최종 확인한 뒤
   `feat(approval): T2 단일 작업 사전 승인 원자 소비 추가`로 로컬 커밋한다.
2. 원격 push는 별도 사용자 승인 뒤 `git -c http.sslBackend=schannel push origin main`으로 수행하고
   local/upstream/remote/clean 상태를 재검증한다.
3. 다음 구현 `APPROVAL-001B`에서 approval과 기존 reversible cleanup hold를 같은 transaction에
   결박한다.

## 알려진 경계

- policy registry, writer token과 issuer verifier는 process-local deployment TCB다. approval·Permit·receipt
  소비는 durable하지만 verifier code identity는 SQLite에 pin되지 않는다.
- T2 write·T3+·batch·async와 partial/unknown batch claim은 미지원이다.
- Graph schema v4 direct downgrade는 없다. rollback 시 v4 reader와 immutable consumption evidence를
  유지해야 한다.
- 전체 pytest의 Benchmark registry 만료, Windows `dirfd`/symlink 제약은 코드 회귀와 구분한다.
- Docker daemon과 real-container 경로는 이번 체크포인트에서 확인하지 않았다.
