# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `043d3f7cfddb8411ea0ea3630370885bbe115543`
- 현재 구현 체크포인트: `MEM-003` current Graph CollaborationSnapshot 검증·사전 리뷰 완료
- 다음 구현: `HANDOFF-001` Supervisor-mediated AgentHandoff

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. 정상 delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같아야 한다.

## 현재 구현 상태

MEM-003은 새 ledger·Graph projection·Snapshot store를 만들지 않고 기존 GRAPH-003 current
`GraphSnapshotRef`에서 receiver-neutral `CollaborationSnapshot`을 파생한다.

- 기존 Graph Snapshot store의 current head와 exact resolve를 재사용한다.
- resolve 전후와 bounded artifact 검증 뒤에 head가 같은지 재확인해 컴파일 중 stale state를
  fail closed한다.
- resolved projection의 `validationState=admitted` CampaignFact 전체를 caller 선택 없이 정렬해
  `GraphNodeRef` membership으로 결박한다.
- MEM-002 `SharedArtifactRef`는 sealed source를 다시 검증하고 full `GraphEvidence`가 같은 projection에
  exact member일 때만 포함한다.
- Fact·Artifact·Evidence membership은 unique/sorted이고 전체 wire는 1 MiB, Fact와 Artifact는 각각
  최대 256개다.
- Graph projection, Fact statement, artifact bytes, prompt, source filesystem path, receiver, Scope,
  Capability, execution authority는 wire에 포함하거나 부여하지 않는다.

핵심 구현 위치:

- `src/pajin/collaboration/snapshots.py`
- `tests/test_collaboration_snapshots.py`
- `docs/graph/MEM-003-current-graph-collaboration-snapshot.md`
- `docs/adr/0112-derive-collaboration-snapshots-from-current-graph.md`

## 마지막 검증

- MEM-002/003 집중 테스트: 14 passed, 1 skipped
- MEM-002/003·Graph·SQLite 인접 회귀: 74 passed, 3 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 229 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark Harness 고정 fixture 만료로 중단
- 만료된 두 fixture 파일 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_snapshots.py tests\test_collaboration_artifacts.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_snapshots.py tests\test_collaboration_artifacts.py tests\test_graph_projection.py tests\test_graph_admission.py tests\test_graph_models.py tests\test_graph_campaign_fact.py tests\test_graph_sqlite_store.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 다음 조치

`HANDOFF-001`의 가장 작은 Supervisor-mediated `AgentHandoff` 수직 슬라이스를 설계한다.

1. 기존 Agent/Task identity, Supervisor decision, Graph Snapshot과 MEM-003 contract를 먼저 대조해
   새 identity registry나 message bus를 만들지 않는다.
2. sender·receiver·purpose·exact current CollaborationSnapshot·lineage를 content-addressed handoff
   proposal/record에 결박하되 direct Agent-to-Agent command를 금지한다.
3. Supervisor-mediated admission만 record를 만들 수 있게 하고 content read, prompt interpretation,
   Scope·Capability·Permit·execution authority는 모두 false로 유지한다.
4. forged Supervisor/sender/receiver, self-handoff, cross-Campaign/Snapshot, stale Snapshot,
   duplicate/equivocal handoff, prompt/command/authority injection을 fail closed한다.

## 알려진 경계

- CollaborationSnapshot은 current Graph membership만 증명한다. sender·receiver·purpose와 실제
  handoff admission은 HANDOFF-001 범위다.
- Snapshot은 Graph/Run content를 복사하거나 읽기 권한을 부여하지 않는다. receiver-bound reader는
  HANDOFF-004에서 Capability·TTL·byte limit와 함께 별도로 구현해야 한다.
- Graph store와 여러 RunStore 사이에 분산 transaction은 없다. cooperative head check 직후 Graph가
  advance할 수 있으며, 이때 기존 Snapshot은 다음 검증에서 stale로 거부된다.
- 전체 pytest는 기존 Benchmark fixture 만료와 Windows symlink 권한 제약으로 완주하지 못했다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
