# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `3ed872c961c523923dd469663004ea9eec0d5e0b`
- 현재 구현 체크포인트: `WALK-004` Observation Graph·Replan 구현·검증 완료, 커밋 전
- 다음 구현: `WALK-005` Candidate·Atomic Validation·Replay·Report·Retest

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `3ed872c`였다. WALK-004 변경은 아직
커밋하지 않은 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/discovery/walking_replanning.py`
- `src/pajin/discovery/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-004-observation-graph-replan.md`
- `docs/adr/0071-evidence-bound-walking-observation-replan.md`
- `README.md`, `docs/rfc/0001-pajin-architecture-v2.md`
- `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-004`가 구현됐다. 새 WALK-004 경계는 다음을 보장한다.

- 봉인된 WALK-003 Campaign, Run root, artifact SHA-256, publication event와 정확히 하나의
  `registered-not-authorized` Hypothesis를 재검증한다.
- WALK-003에 포함된 WALK-002 H-17 lineage, HTTP/RAG Snapshot, MCP Snapshot, immutable
  Capability Definition, Tool binding, 독립 사용자 승인 요구를 그대로 보존한다.
- `sealed-hypothesis-state` 증거만 content-addressed Observation으로 Admission한다.
- admitted Observation이 baseline과 다른 `request-independent-approval` 후속 Plan을
  선택하고, Plan 상태는 `proposed-not-authorized`로 고정된다.
- Graph에는 `supports`, `enables`, `depends-on` 관계가 기록된다. `contradicts`는 타입
  어휘로 예약되며 불일치 증거는 Graph 생성 전에 거부된다.
- canonical Campaign payload, expected-state 비교와 baseline 또는 봉인된 이전 WALK-004
  authority에서만 복원한 bounded state history로 결정론성을 유지하고 stale, repeated,
  cycle, Run/Hypothesis 치환 및 Scope·Snapshot·Capability 확대를 fail closed한다.
- 봉인 artifact와 exact audit event를 재검증하는 reader가 전체 권위를 재구성한다.
- Activation, CapabilityGrant, approval receipt, ActionPermit, ToolRequest, MCP argument,
  Worker dispatch를 만들지 않는다.

핵심 구현 위치:

- `src/pajin/discovery/walking_replanning.py`
- `src/pajin/discovery/walking_mcp.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-004-observation-graph-replan.md`
- `docs/adr/0071-evidence-bound-walking-observation-replan.md`

## 마지막 검증

현재 WALK-004 worktree 기준:

- WALK-004 결정론성 양성 테스트 5회 반복 통과
- WALK/ORCH/문서 집중 회귀: 30 passed
- WALK 전용 회귀: 14 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 186 source files 통과
- 전체 `pytest -x -q`: 150 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py tests\test_discovery_replanning.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 WALK-004 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경
제약이다.

## 다음 조치

현재 변경을 다시 검토하고 사용자의 명시적 승인 후에만 다음을 수행한다.

1. 관련 파일만 stage하고 staged diff와 민감정보 포함 여부를 확인한다.
2. 한국어 Conventional Commit으로 WALK-004 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

이 문서를 포함한 WALK-004 커밋이 이미 존재한다면 위 배포 절차를 반복하지 않고 실제 Git
상태를 우선한다. 다음 개발은 WALK-005이며, 먼저 기존 Candidate·Claim·Atomic
Validation·Restricted Replay·Report·Retest 경로와 WALK-004 사이의 누락된 연결만
조사한다. 승인 receipt, CapabilityGrant, ActionPermit, Gateway, Budget, Policy를 암묵적으로
생성하거나 우회하지 않는다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

커밋과 push에는 사용자의 명시적 승인이 필요하다.
