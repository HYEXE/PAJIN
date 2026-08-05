# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 작업 시작 원격 체크포인트: `e91e25ae105603807301bd7bddf5b5f2beeae0ff` (`PERMIT-004B1`)
- 현재 구현 체크포인트: `PERMIT-004B2` Authenticated Reversible-write Cleanup Dispatch
- 다음 구현: `APPROVAL-001` T2 ApprovalEnvelope와 Batch·Async 승인

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같은지 확인한다.

## 현재 구현 상태

`PERMIT-004`가 완료됐다. A 경로는 기존 no-write assessment를 유지하고, B 경로는 reversible write 전에
cleanup capacity를 확보한 뒤 authenticated source에서 distinct cleanup Capability를 정확히 한 번 실행하고
실제 target state 복구를 독립 확인한다. 기존 ActionProposal·ActionPermit·PERMIT-004A assessment·Gateway·Worker
wire와 동작은 깨지 않는다.

- PERMIT-004A의 private authentication core는 managed Run·pre-claim anchor·exact Grant, stored ActionPermit,
  sealed completed dispatch, Gateway·Worker·evidence와 current CAP-002 role을 exact-rebuild하되 Oracle과 Handler를
  호출하지 않는다. 기존 public no-write `assess()`가 semantic role을 호출한 뒤 authority를 재검증한다.
- `GeneralAttackActionPermitGate`는 `reversible-write + cleanupRequired=true`와 명시적
  `GeneralAttackReversibleCleanupAuthority`가 있을 때만 write callback을 허용한다. code-owned mapping의
  distinct current cleanup release, Handler·Executor와 trusted cost/deadline을 B1 ActionPermit+hold transaction에
  결박한다. irreversible write와 hold 없는 write는 Worker 전에 닫힌다.
- `CleanupCapabilityMappingRegistry`는 별도 store 없이 adapter implementation·stable context, source
  Capability, distinct current cleanup activation/release와 method를 content-addressed mapping으로 고정한다.
- current source Cleanup Handler는 authenticated execution 뒤 source Success Oracle 판정과 무관하게 정확히
  한 번의 bounded `restore-target` plan을 반환해야 한다. plan은 expected-state SHA-256, mapping, source Handler,
  cleanup Executor와 complete prepared action에 결박된다. claim 전후 Handler를 다시 호출해 동일 typed plan을
  exact-match하므로 same-identity plan equivocation도 Worker 전에 닫힌다.
- source outcome identity는 mutable latest Run root가 아니라 source evidence를 처음 포함한 immutable seal root를
  사용한다. 따라서 같은 Run에 cleanup audit를 append/seal한 뒤에도 source를 exact re-authenticate할 수 있다.
- fresh cleanup Grant는 source Grant와 ID·digest가 다르고 exact agent·Tool·Target, one call, no delegation,
  source terminal 이후 issuance, Permit·Envelope 이내 expiry를 요구한다. original ActionPermit은 lineage일 뿐
  cleanup 권위로 재사용하지 않는다. prospective Permit window보다 긴 Grant는 Permit claim 전에 거부한다.
- Tool Gateway, audit store와 restored-state verifier는 gate 생성 시 deployment-owned authority로 고정한다.
  audit store의 resolved path·Run ID는 authenticated managed Run과 같아야 하며, final proof는 caller path가 아닌
  그 managed Run만 읽고 실제 Graph store의 consumed CleanupPermit과 exact-match한다.
- `ExistingModeCleanupCapabilityGatewayDispatcher`는 B1 CleanupPermit만 소비하고 unchanged Tool Gateway·Worker를
  호출한다. separate claimed/terminal audit와 reconciliation은 completed, failed, cancelled, expired,
  consumed-without-claim, claimed-outcome-unknown을 구분하며 exact retry나 unknown outcome은 다시 실행하지 않는다.
- restored assessment는 sealed completed cleanup, current release·roles, exact Gateway·Worker·evidence,
  Normalizer·Success Oracle과 no-recursive-cleanup을 검증한 뒤 code-identified verifier가 actual target-state
  digest를 다시 관찰해야 성립한다. Gateway success만으로는 restored가 아니다.
- current CAP-005 production inventory는 여전히 no-write다. positive path는 격리된 synthetic state
  write→restore fixture이며 default Supervisor 실행을 활성화하지 않는다.

핵심 위치:

- `src/pajin/supervision/action_outcome.py`
- `src/pajin/supervision/action_permit.py`
- `src/pajin/supervision/action_cleanup.py`
- `src/pajin/supervision/cleanup_mapping.py`
- `src/pajin/capabilities/cleanup_dispatch.py`
- `tests/test_general_attack_action_cleanup.py`
- `tests/test_general_attack_cleanup_mapping.py`
- `tests/test_cleanup_capability_dispatch.py`
- `docs/orchestration/PERMIT-004B2-authenticated-reversible-cleanup-dispatch.md`
- `docs/adr/0133-authenticate-and-verify-reversible-cleanup.md`

## 현재 검증

- PERMIT-004B2·A·B1·Cleanup Gateway·Graph 집중 묶음: 104 passed
- isolated reversible write→cleanup→actual restored-state 수직·음성 경로: 9 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 254 source files 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 Benchmark registry fixture 만료에서 중단.
  `Benchmark registry distribution is not currently valid`이며 이번 변경의 코드 회귀와 구분한다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_outcome.py tests\test_general_attack_action_permit.py tests\test_general_attack_cleanup_mapping.py tests\test_cleanup_capability_dispatch.py tests\test_general_attack_action_cleanup.py tests\test_graph_action_permit.py
.\.venv\Scripts\ruff.exe check src tests containers
.\.venv\Scripts\mypy.exe --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

저장소 전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 변경 Python만
확인하고 전체 저장소를 기계적으로 재포맷하지 않는다.

## 커밋 전 독립 검토

초기 구현은 sealed-result authentication core, code-owned cleanup mapping, cleanup Gateway lifecycle을 서로
독립된 병렬 작업으로 분리했다. 통합 뒤 trust·correctness·contract 관점의 읽기 전용 재검토에서 current
Handler plan pre/post-claim 재구성 누락, caller-selected cleanup Run path, stored CleanupPermit 미검증,
assessment-time verifier substitution, per-call alternate audit store, prospective Permit보다 긴 Grant의 뒤늦은
거부를 발견했다. Handler plan exact rebuild, constructor-bound deployment runtime/verifier, managed Run path,
stored Permit equality와 pre-claim Grant window 검사 및 각각의 음성 테스트로 해소했다. 수정 후 최종 trust
재검토에서 남은 P0-P3가 없었다.

## 다음 작업의 첫 단계

`APPROVAL-001`을 구현하기 전에 현재 Approval·Permit·async/batch 관련 코드, 테스트, 계약과 `PLAN.md` 완료
조건을 다시 읽어 중복 authority를 피한다. 첫 수직 슬라이스는 다음 순서로 설계한다.

1. T2 실행이 현재 어느 경계에서 거부되는지, 기존 operator authorization·MissionEnvelope·Capability
   `approvalRequired`가 무엇을 보장하는지 inventory한다.
2. caller boolean이나 model output이 아니라 deployment/operator authority가 발급한 content-addressed
   `ApprovalEnvelope`를 exact Campaign·Run·Capability·Target·request/plan·risk·budget·expiry에 결박한다.
3. single, batch, async claim이 같은 approval을 중복 소비하거나 서로 다른 request를 substitution하지 못하도록
   최소 durable authority와 idempotency 경계를 결정한다.
4. 승인 위조, stale/cross-Campaign/cross-request replay, scope·batch 확대, 부분 claim·unknown outcome을 Worker
   전에 fail closed하는 음성 테스트를 먼저 고정한다.

## 알려진 경계

- Envelope·Decision provenance, pricing, managed Run/Grant, cleanup Grant, mapping과 restored-state verifier의
  production composition은 deployment-supplied TCB다.
- current production inventory에는 reversible-write release가 없고 SUP-007 default execution도 비활성이다.
- schema v3 direct downgrade, expired·abandoned hold 자동 release와 failed·unknown cleanup 자동 retry는 없다.
- 전체 pytest의 Benchmark registry fixture 만료와 그 뒤 Windows symlink 권한 제약은 코드 회귀와 구분한다.
- Docker daemon은 이번 체크포인트에서 확인하지 않았고 real-container 검증은 수행하지 않았다.
