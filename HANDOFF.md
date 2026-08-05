# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 작업 시작 원격 체크포인트: `ae877f69c693fbdeb79e6eb441ca8c46e9dd2cb4` (`PERMIT-004A`)
- 현재 구현 체크포인트: `PERMIT-004B1` Pre-reserved One-shot CleanupPermit Authority
- 다음 구현: `PERMIT-004B2` Authenticated Reversible-write Cleanup Dispatch

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

`PERMIT-004B1`은 reversible write 실행 전에 cleanup capacity를 durable하게 확보하고, 그 hold를 별도
CleanupPermit으로 정확히 한 번만 소비하는 GRAPH authority substrate다. 기존 PERMIT-004A no-write gate와
ActionProposal·ActionPermit v1alpha2 wire는 바꾸지 않는다.

- `ActionCleanupReservationRequest`가 source ActionProposal, distinct cleanup Capability, 동일 Target,
  Cleanup Handler·Executor identity, budget와 claim deadline을 content-addressed input으로 결박한다.
- `GraphReversibleActionPermitAuthority`와 dispatcher는 기존 ActionPermit claim과 cleanup hold를 같은
  `BEGIN IMMEDIATE` transaction에서 커밋한 뒤에만 write callback을 호출한다. claim 전후에는 필수
  `ReversibleActionPermitInputAuthority`가 current signed reversible Definition과 code-owned cleanup mapping을
  검증하며 permissive 기본 구현은 없다. 한쪽만 존재하는 retry, callback failure와 outcome uncertainty는
  재실행하지 않는다.
- `CleanupRequest`는 source ActionPermit·dispatch, pre-action hold, outcome/Run/audit coordinates,
  Graph Decision/Snapshot, Handler·Executor·plan, distinct cleanup Capability, fresh ToolRequest와 budget을
  결박하지만 그 outcome·plan이 sealed source에서 왔다는 의미 권위는 아직 PERMIT-004B2 입력 TCB다.
- `GraphCleanupPermitAuthority`는 같은 Campaign-pinned compiler writer를 재사용하고 stored ActionPermit,
  hold, latest Snapshot과 request를 exact 검증한 뒤 domain-separated consumed CleanupPermit을 발급한다.
  필수 `CleanupPermitInputAuthority`가 claim 전후 sealed source와 current plan을 검증해야 하며 B1에는 production
  구현이 없다. 원 ActionPermit은 lineage일 뿐 cleanup 실행 권위로 재사용하지 않는다.
- 예산은 일반 ActionPermit + cleanup hold를 Tool-call, request-unit, fixed-point cost, rolling request-unit에
  합산한다. CleanupPermit은 hold를 재차감하지 않는다. 미소비 hold는 rolling window가 지나도 capacity를
  유지하며 자동 release하지 않는다.
- SQLite schema v3는 `graph_action_cleanup_reservations`, `graph_cleanup_permits`를 fingerprinted append-only
  table로 추가한다. exact v1/v2 store를 v3로 migration하되 cleanup row를 만들지 않는다.
- backup manifest v1alpha2는 cleanup reservation/Permit count와 head digest를 결박한다. legacy
  v1alpha1/schema-v2 backup은 원본을 먼저 검증하고 private destination만 v3로 migration한다. retained
  statement와 detached manifest도 새 producer는 v1alpha2를 쓰며, strict v1alpha1 reader는 기존 low-level
  manifest와 signature/AEAD domain만 허용한다.
- current CAP-005 production inventory는 여전히 `none/read-only`, `cleanupRequired=false`뿐이다. 신규
  reversible-write positive path는 저장소 authority를 검증하는 격리 fixture이며 production 활성화가 아니다.

핵심 위치:

- `src/pajin/graph/cleanup.py`
- `src/pajin/graph/sqlite_store.py`
- `src/pajin/graph/__init__.py`
- `src/pajin/graph/backup_retention.py`
- `tests/test_graph_action_permit.py`
- `docs/orchestration/PERMIT-004B1-pre-reserved-one-shot-cleanup-permit.md`
- `docs/adr/0132-pre-reserve-cleanup-capacity-before-reversible-write.md`

## 현재 검증

- PERMIT-004B1 집중 authority·migration·backup: 30 passed
- Graph store·backup·PERMIT 인접 묶음: 51 passed, 2 skipped
- general-attack·CAP·GRAPH 회귀 묶음: 165 passed
- ORCH·PERMIT·CAP·Replay·Supervisor·Graph 확장 묶음: 331 passed, 2 skipped
- Ruff 전체: 통과
- Linux 대상 strict mypy: 251 source files 통과
- 전체 pytest: 190 passed, 3 skipped, 1 failed 뒤 중단. 실패는 만료된 Benchmark registry fixture의
  `Benchmark registry distribution is not currently valid`이며 이번 변경의 코드 회귀와 구분한다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_permit.py tests\test_graph_sqlite_store.py tests\test_graph_backup_repository.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_proposal.py tests\test_general_attack_action_permit.py tests\test_general_attack_action_outcome.py tests\test_capability_authorities.py tests\test_existing_capability_adapters.py tests\test_existing_capability_rollout.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_discovery_hypothesis.py tests\test_discovery_replanning.py tests\test_general_attack_action_proposal.py tests\test_general_attack_action_permit.py tests\test_general_attack_action_outcome.py tests\test_capability_authorities.py tests\test_capability_definition.py tests\test_existing_capability_adapters.py tests\test_existing_capability_rollout.py tests\test_graph_action_permit.py tests\test_replay_models.py tests\test_replay_compiler.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_adversarial_prompt_injection.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

저장소 전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 변경 Python만
확인하고 전체 저장소를 기계적으로 재포맷하지 않는다.

## 커밋 전 독립 검토

초기 및 수정 후 병렬 계약·SQLite 품질·trust 검토에서 다음 문제를 반영했다.

- 결과 뒤 CleanupPermit만 예산에 합산하면 Action과 cleanup 사이 다른 Action이 budget을 소진해 compensation이
  굶을 수 있으므로, write callback 전에 ActionPermit + cleanup capacity를 같은 transaction에서 hold한다.
- 기존 ActionProposal·ActionPermit wire와 action-only Protocol을 수정하지 않고 parallel reversible/cleanup
  authority contract를 추가한다.
- 별도 cleanup writer·database를 만들지 않고 기존 `graph_action_permit_writers` identity와 SQLite writer
  token을 재사용한다.
- schema fingerprint 변경을 숨기지 않고 v3 migration과 v1alpha2 backup wire를 명시하며, populated v2
  ActionPermit과 legacy backup restore 호환을 검증한다.
- current production inventory에 reversible-write가 없는 사실을 유지하고 positive path를 격리된 authority
  fixture로 한정한다.
- self-authenticated CleanupRequest나 일반 Action을 reversible authority로 승격하지 못하도록 두 public claim에
  외부 input-authority Protocol을 필수화하고 claim 전후 검증한다.
- retained v1alpha1 outer wire에 v1alpha2 low-level manifest를 넣지 않고 outer/crypto domain까지 버전 분리한다.
- backup/restore가 canonical forged hold·Permit의 Run, Envelope, Target, Handler·Executor, deadline 등 공유 권위를
  빠짐없이 교차 검증한다.

최종 trust 재검토는 P0-P2가 없었고, 계약·품질 재검토의 P2는 문구·검증 숫자·Permit deadline 검증으로
해소했다. delivery 전 실제 diff와 최종 테스트 결과를 다시 우선한다.

## 다음 작업의 첫 단계

`PERMIT-004B2`는 generic GRAPH request를 실제 authenticated general-attack cleanup 경로에 연결해야 한다.

1. PERMIT-004A의 Run·anchor·Grant·terminal lifecycle·evidence·WorkerJob 인증을 no-write와 write 경로가
   중복 없이 재사용할 private core로 분리하되 기존 public assessment wire와 동작을 유지한다.
2. `reversible-write + cleanupRequired=true` completed execution을 인증하고 semantic Oracle 결과와 무관하게
   current Cleanup Handler의 exactly-one bounded plan을 typed request로 해석한다.
3. code-owned source→distinct cleanup Capability mapping, current activation/release, Handler·Executor identity,
   exact Target·ToolRequest·price가 pre-action hold와 같음을 증명한다.
4. fresh cleanup Grant와 existing Gateway lifecycle로 CleanupPermit-bound request를 한 번만 dispatch한다.
5. cleanup terminal evidence와 actual restored target state를 별도 verifier로 확인한다. irreversible write,
   incomplete·uncertain source, plan/Permit forgery, stale activation, cross-action substitution과 unknown cleanup
   result는 Worker 전에 또는 restored 판정 전에 fail closed한다.

## 알려진 경계

- verified general-attack Envelope producer, Decision provenance registry, generic pricing provider와
  `GeneralAttackActionOutcomeInputAuthority` production composition은 아직 deployment-supplied TCB다.
- PERMIT-004B1은 GRAPH reservation/Permit만 제공한다. generic CleanupRequest의 outcome·Handler plan provenance,
  cleanup Gateway dispatch, restored-state proof, Finding, replay, default Supervisor execution 권위는 없다. 두
  필수 input-authority의 production 구현도 PERMIT-004B2 전까지 없다.
- 전체 pytest의 registry fixture 만료는 이번 변경의 코드 회귀가 아니다. 그 뒤의 기존 Windows symlink
  권한 제약은 이번 실행에서 도달하지 않았다.
- Docker daemon은 이번 체크포인트에서 확인하지 않았고 real-container 검증은 수행하지 않았다.
