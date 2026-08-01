# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `315bd307ec81b9645ea910da154c50852fdfc4ca`
- 현재 구현 체크포인트: `WALK-005B1` Claim-bound 비실행 MCP Replay Plan 구현, 커밋 전
- 다음 구현: `WALK-005B2` Plan-bound fresh 실행·Claim 검증 projection

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `315bd307`이었다. WALK-005A는 이미
커밋·push됐고 WALK-005B1 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/discovery/walking_replay.py`
- `src/pajin/discovery/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-005B1-claim-bound-mcp-replay-plan.md`
- `docs/adr/0073-claim-bound-non-executable-mcp-replay-plan.md`
- `docs/rfc/0001-pajin-architecture-v2.md`
- `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-005A`와 `WALK-005B1`이 구현됐다. 새 B1 경계는 다음을 보장한다.

- 봉인된 WALK-005A authority를 다시 열어 exact validity Claim 하나만 선택한다.
- WALK-005A publication Run root·artifact SHA-256와 원 execution·Run·request,
  Tool·target·method·parameter digest를 Plan에 결박한다.
- replay Run·request·approval·Grant·Permit·dispatch·Worker identity의 fresh 요구를 고정한다.
- 상태는 `planned-not-authorized`이며 approval, Grant, Permit, request, ticket, dispatch,
  ReplayOutcome 또는 confirmation을 만들지 않는다.
- 기존 KISA M03/M06/A04 materializer·Oracle을 A02 MCP Candidate로 재표기하지 않는다.

핵심 구현 위치:

- `src/pajin/discovery/walking_replay.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-005B1-claim-bound-mcp-replay-plan.md`
- `docs/adr/0073-claim-bound-non-executable-mcp-replay-plan.md`

## 마지막 검증

현재 WALK-005B1 worktree 기준:

- WALK/Capability/Replanning/문서 집중 회귀: 69 passed
- WALK-005B1 + 문서 집중 회귀: 26 passed
- WALK-005B1 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 188 source files 통과
- 전체 `pytest -x -q`: 150 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py tests\test_discovery_replanning.py tests\test_existing_capability_rollout.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 WALK-004 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경
제약이다.

## 다음 조치

현재 변경은 사용자 승인에 따라 다음 순서로 자동 진행한다.

1. 관련 파일만 stage하고 staged diff와 민감정보 포함 여부를 확인한다.
2. 한국어 Conventional Commit으로 WALK-005B1 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

WALK-005B1을 사전 커밋 검토·검증·push한 뒤 `WALK-005B2`를 시작한다. B1 Plan digest를 fresh
approval·Grant·Permit·Gateway execution의 dispatch 전에 봉인하고, exact validity Claim의
검증 projection을 별도 sealed Run에서 재구성한다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
