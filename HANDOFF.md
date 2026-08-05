# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 기준 원격 체크포인트: `d4032a6a5fb15c0ec8cf876acba1206224507eb0` (`PERMIT-003`)
- 현재 구현 체크포인트: `PERMIT-004A` Authenticated No-write Action Outcome Gate
- 다음 구현: `PERMIT-004B` Bounded One-shot Cleanup Permit와 aggregate Campaign budget

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

`PERMIT-004A`는 consumed PERMIT-003 action의 live callback 값을 직접 신뢰하지 않고, current
source와 배포가 해석한 sealed execution authority를 모두 다시 교차 검증한 뒤에만 CAP-002
outcome role을 호출하는 direct-call no-write gate다.

- complete PERMIT-001/002 source를 exact-rebuild하고 current signed CAP-005 activation에서 같은
  Capability·release·prepared request·activation set을 다시 해석한다.
- current GRAPH store에서 exact consumed ActionPermit을 재조회하고 proposal·Permit·intent의 Campaign,
  Run, Envelope, Decision, Snapshot, Capability, Target, request, digest, reservation을 교차 검증한다.
- caller가 Run path를 선택하지 않는다. 외부 `GeneralAttackActionOutcomeInputAuthority`가
  deployment-owned Run path, exact pre-claim `CapabilityGraphRunAuditAnchor`와 그 pre-claim seal,
  실제 Gateway Grant를 공급하며 gate가 canonical copy와 current Campaign·Envelope·release set·
  activation set·compiler를 다시 교차 검증한다.
- caller가 Run path를 주입할 수 없으며, authority가 해석한 Run의 missing result evidence,
  missing·duplicated·late·divergent anchor와 substituted Grant는 Oracle 전에 fail closed한다. canonical
  managed Run mapping 자체는 deployment input authority가 책임지는 명시적 TCB다.
- 기존 verified Run loader와 CAP-005 reconciliation만 재사용해 exact sealed
  `claimed -> completed` lifecycle을 요구한다. missing·retry·claimed-outcome-unknown·failed·cancelled·
  expired 상태는 success, cleanup completion, redispatch로 승격하지 않는다.
- terminal audit의 exact Grant digest·Gateway outcome digest·Worker execution·policy/result flags·evidence
  path를 검증한다.
- sealed evidence를 strict duplicate-free UTF-8 JSON으로 다시 읽고 request·policy·pre-evidence result·
  Worker result·artifact provenance를 재구성한다. exact `worker.dispatched` audit과 image·command·network·
  egress·limits·stdin·secret request/lease metadata를 교차 검증한다.
- current Result Normalizer가 sealed pre-evidence ToolResult를 exact 재현해야 하며, 그 뒤에만 Success
  Oracle과 Cleanup Handler를 호출한다. 일반 adapter RuntimeError도 public gate error로 fail closed한다.
- Executor Adapter는 identity만 결박하고 `prepare()`를 다시 호출하지 않는다.
- current seven-Capability inventory의 `none/read-only`, `cleanupRequired=false`만 허용한다. side-effect
  absence와 semantic information flow는 attested로 승격하지 않으며 write·cleanup 권위는 모두 false다.
- `GeneralAttackActionOutcomeAssessment` 모델 자체는 output projection이다. consumer는 complete source와
  deployment input authority를 사용해 `verify_assessment()`를 통과해야 하며, self-consistent digest만으로
  predecessor authority가 되지 않는다. verifier는 predecessor 인증 뒤 current Oracle·Cleanup Handler를
  다시 평가하고 candidate equality를 검사하므로 두 role은 외부 side effect가 없는 evaluation/planning
  authority여야 한다.

핵심 위치:

- `src/pajin/supervision/action_outcome.py`
- `src/pajin/supervision/__init__.py`
- `tests/test_general_attack_action_outcome.py`
- `docs/orchestration/PERMIT-004A-authenticated-action-outcome-gate.md`
- `docs/adr/0131-authenticate-sealed-action-results-before-oracle.md`

## 현재 검증

- PERMIT-004A 신규 성공·음성 경계: 17 passed
- PERMIT-001/002/003/004A·CAP-002/005·GRAPH-006 인접 묶음: 147 passed
- ORCH·PERMIT·CAP·Replay·Supervisor 확장 묶음: 291 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 250 source files 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 Benchmark registry distribution fixture 만료에서 중단
  (`Benchmark registry distribution is not currently valid`)

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_outcome.py
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

초기 병렬 계약·품질·trust 검토에서 다음 문제를 찾아 커밋 전에 보완했다.

- caller-selected self-sealed Run을 결과 권위로 오인할 수 있던 경로 인자 제거
- terminal Grant digest의 존재 확인을 trusted exact Grant equality로 강화
- evidence Worker job을 실제 `worker.dispatched` audit과 결박하고 secret lease wire 의미 정합화
- assessment model self-digest와 predecessor authority를 분리하고 exact-rebuild verifier 추가
- authority adapter의 ordinary exception을 typed public error로 정규화
- 이 체크포인트와 모순되던 인수인계 갱신

최종 재검토 결과와 그 이후 수정이 있다면 delivery 전 실제 diff와 테스트 결과를 다시 우선한다.

## 다음 작업의 첫 단계

`PERMIT-004B`는 원 ActionPermit을 재사용하지 않는 별도 cleanup 실행 권위를 기존 GRAPH durability와
budget domain 안에 추가해야 한다.

1. 기존 `ActionBudgetReservation`, SQLite `graph_action_permits` writer/claim transaction, CAP-002
   Cleanup Handler·Executor Adapter 계약을 다시 읽고 같은 writer에서 확장 가능한 최소 schema를 정한다.
2. authenticated PERMIT-004A outcome·Oracle decision·Handler plan·원 ActionPermit lineage에 결박된 typed
   `CleanupRequest`와 domain-separated `CleanupPermit`을 정의한다.
3. CleanupPermit은 consumed-on-issuance, exact one-shot이며 원 ActionPermit이나 별도 in-memory ledger를
   실행 권위로 사용하지 않는다.
4. action+cleanup reservation을 같은 Campaign의 Tool-call, request-unit, fixed-point cost, rolling-rate
   예산에 원자적으로 합산하고 crash/duplicate/concurrency에서도 초과 발급되지 않게 한다.
5. 하나의 최소 `reversible-write` positive fixture와 cleanup execution을 검증하되 production Capability가
   존재하지 않는 사실을 숨기지 않는다. `irreversible-write`, uncertain outcome, forged plan/Permit,
   cross-action substitution, duplicate claim, budget overflow는 모두 실행 전에 거부한다.

## 알려진 경계

- verified general-attack Envelope producer, Decision provenance registry, generic pricing provider와
  `GeneralAttackActionOutcomeInputAuthority` production composition은 아직 deployment-supplied TCB다.
- PERMIT-004A는 no-write result authentication만 제공한다. write admission, cleanup plan/Permit/execution,
  Finding, replay, default Supervisor execution 권위는 없다.
- 전체 pytest의 registry fixture 만료는 이번 변경의 코드 회귀가 아니다. 그 뒤의 기존 Windows symlink
  권한 제약은 이번 실행에서 도달하지 않았다.
- Docker daemon은 이번 체크포인트에서 확인하지 않았고 real-container 검증은 수행하지 않았다.
