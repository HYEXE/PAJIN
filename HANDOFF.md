# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 직전 원격 체크포인트: `2bc239c855061a2fe82650bcb247e84b51db6d6f` (`SUP-006`)
- 현재 구현 체크포인트: `PERMIT-001` 일반 공격 ActionProposal
- 다음 구현: `PERMIT-002` Deterministic Action Compiler

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

`PERMIT-001`은 기존 `pajin.graph.ActionProposal`을 변경하지 않고 그 앞에 독립적인
`GeneralAttackActionProposal` 비실행 권위를 추가한다.

- 새 ORCH `SurfaceSnapshotAuthority`는 sealed Recon의 `campaign.json`과 `recon-plan.json`을 exact
  재검증한 뒤 complete Campaign digest를 포함하고 강화된 v2 Snapshot digest domain을 사용한다.
- 기존 field-absent v1 Snapshot·Plan·WALK·multi-wave wire는 원래 digest로 계속 읽힌다. 다만 full Campaign
  identity를 증명하지 못하므로 PERMIT-001 입력으로는 거부한다.
- Action kind/version/digest, evidence, side-effect, cleanup과 risk는 exact CAP-001 definition에서만 온다.
  target은 Campaign에서 다시 열고 deny-first Scope를 검사하며 Target reference에는 endpoint digest만 남긴다.
- method와 arguments는 exact ORCH Task에서만 오며 모두 action-semantics digest에 결박된다. arguments는 별도
  pre-materialization digest를 가지지만 Capability parameter digest로 오인하지 않는다.
- SUP-003 typed proposal은 완전한 외부 검증 원천 없이 부분 lineage로 수용하지 않는다. prompt, rationale,
  Supervisor field는 Action 의미를 만들 수 없다.
- `ToolRequest`, activated Capability, Grant, MissionEnvelope, Graph Decision, budget reservation, Permit, dispatch와
  execution은 생성하지 않으며 관련 authority flag는 모두 literal false다.
- same-name foreign Campaign 재라벨, cross-Snapshot/Plan/Task, Scope 확대, method·arguments·risk·definition drift,
  non-canonical risk/method, executable top-level field 주입은 fail closed한다.

핵심 위치:

- `src/pajin/supervision/action_proposal.py`
- `src/pajin/discovery/hypothesis.py`
- `src/pajin/discovery/replanning.py`
- `src/pajin/discovery/walking.py`
- `src/pajin/discovery/walking_mcp.py`
- `src/pajin/discovery/walking_replanning.py`
- `tests/test_general_attack_action_proposal.py`
- `tests/test_discovery_hypothesis.py`
- `tests/test_discovery_replanning.py`
- `docs/orchestration/PERMIT-001-general-attack-action-proposal.md`
- `docs/orchestration/ORCH-001-surface-snapshot-plan-task-binding.md`
- `docs/adr/0128-bind-general-attack-semantics-before-action-compilation.md`

## 현재 검증

- ORCH·Replanning·PERMIT 집중 회귀: 49 passed
- legacy WALK-003→WALK-004→WALK-005A seal/read 및 전체 Walking 인접 회귀: 38 passed
- PERMIT·Replay·GRAPH-006·Engine Gate·Supervisor 인접 회귀: 144 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 247 source files 통과
- 변경 Python 11개 Ruff formatter check: 통과
- `git diff --check`: 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 registry distribution bundle 만료로 중단
  (`test_benchmark_single_agent_measurement.py`; 현재 시각 2026-08-05가 fixture 만료 시각을 지남)
- 독립 품질 리뷰: method 의미 digest, strict risk wire, endpoint 문구, legacy nested parent digest 및 WALK
  원본 Campaign digest 전파 P2를 발견해 수정·재검토했으며 최종 잔존 P0-P2 없음
- 독립 trust 리뷰: same-name Campaign 재라벨과 검증되지 않은 SUP-003 lineage P2를 발견해 sealed source exact
  검증·lineage 제거 후 재검토했으며 최종 잔존 P0-P2 없음
- 독립 계약 리뷰: additive Snapshot 필드의 nested field-absence와 transitive WALK parent digest 호환성을
  재검토했으며 최종 잔존 P0-P2 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_discovery_hypothesis.py tests\test_discovery_replanning.py tests\test_general_attack_action_proposal.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_proposal.py tests\test_replay_models.py tests\test_replay_compiler.py tests\test_graph_action_permit.py tests\test_engine_execution_gate.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_adversarial_prompt_injection.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 변경 Python만 검사하고 저장소
전체를 기계적으로 재포맷하지 않는다.

## 핵심 신뢰 경계

- `GeneralAttackActionProposal`은 실행 요청이나 Permit 후보가 아니다. 기존 GRAPH-006
  `ActionProposal`만 Permit-adjacent authority다.
- static `CapabilityDefinitionRef`는 reviewed metadata reference이지 activated Capability나 Grant가 아니다.
- exact ORCH arguments에는 endpoint-shaped 문자열이나 hostile prompt가 inert data로 포함될 수 있다. Target
  reference가 endpoint text를 추가하지 않는다는 보장과 proposal 전체가 content-free라는 주장을 혼동하지 않는다.
- legacy v1 Snapshot은 historical reader compatibility만 가진다. PERMIT-001은 `campaignDigest`가 없는 Snapshot을
  재해석하거나 현재 Campaign으로 승격하지 않는다.
- expected evidence는 required-not-observed metadata이고 Success Oracle은 아직 결박되지 않았다. cleanup도
  metadata-only이며 handler, plan, Permit은 없다.

## 다음 작업의 첫 단계

`PERMIT-002`는 PERMIT-001 proposal을 다시 검증한 뒤 code-backed compiler가 기존 실행 권위로 가는 첫
결정론적 변환을 담당한다.

1. CAP-002 compiler interface, Replay compiler, 기존 `pajin.graph.ActionProposal`, MissionEnvelope와 GRAPH-006
   소비 경계를 먼저 인벤토리해 중복 compiler·request·registry·Permit 타입을 만들지 않는다.
2. PERMIT-001 proposal과 exact current Campaign/Snapshot/Plan/Task/definition을 모두 다시 열고 registered
   compiler ID/version/digest를 content-addressed output에 결박한다.
3. target, method, arguments, risk, evidence, cleanup, Scope와 budget을 확대하지 않는 exact mapping을 정의한다.
4. compiler substitution, source replay, self-consistent output forgery와 `ToolRequest`/Capability/Permit 주입을
   Worker 호출 전 fail closed하는 가장 작은 수직 슬라이스를 설계한다.
5. PERMIT-003의 기존 GRAPH-006 single-use Permit 연결을 선점하거나 새 Permit store/dispatcher를 만들지 않는다.

## 알려진 경계

- PERMIT-001은 code-backed action compiler, normalized Capability parameters, `ToolRequest`, MissionEnvelope,
  Graph Decision, budget reservation, Grant, Permit 또는 execution runtime에 아직 연결되지 않았다.
- Success Oracle과 cleanup handler/plan/Permit은 PERMIT-004 전까지 metadata-only다.
- 전체 pytest에는 기존 Benchmark registry fixture 만료와 이후 Windows symlink 권한 제약이 남아 있다.
- Docker daemon 상태는 이번 체크포인트에서 확인하지 않았고 real-container 검증은 수행하지 않았다.
