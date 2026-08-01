# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `6fe27943208755982251a4c0a6a4bcd59e94ddb8`
- 현재 구현 체크포인트: `WALK-005C1` MCP 확인·Report·Remediation baseline 구현, 커밋 전
- 다음 구현: `WALK-005C2` baseline-bound fresh Retest·보수적 lifecycle 판정

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `6fe27943`이었다. WALK-005B2는 이미
커밋·push됐고 WALK-005C1 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/discovery/walking_closure.py`
- `src/pajin/discovery/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-005C1-mcp-confirmation-report-remediation-baseline.md`
- `docs/adr/0075-mcp-replay-confirmation-baseline.md`
- `docs/rfc/0001-pajin-architecture-v2.md`
- `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-005C1`이 구현됐다. 새 C1 경계는 다음을 보장한다.

- 봉인된 B2 authority와 fresh validity replay만 MCP 전용 확인 근거로 채택한다.
- impact·severity Claim은 `source-bound-information-only`로 고정해 replay됐다고 확장하지 않는다.
- Candidate Finding은 `validated=true` 외의 의미를 바꾸지 않는다.
- typed Report·exact Markdown·비실행 Remediation Plan을 confirmation authority에 결박한다.
- C1은 remediation 적용, Retest 실행, `fixed`·`still-vulnerable` 판정을 만들지 않는다.

핵심 구현 위치:

- `src/pajin/discovery/walking_closure.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-005C1-mcp-confirmation-report-remediation-baseline.md`
- `docs/adr/0075-mcp-replay-confirmation-baseline.md`

## 마지막 검증

현재 WALK-005C1 worktree 기준:

- WALK/Capability/Replanning/문서 집중 회귀: 73 passed
- WALK-005C1 포함 WALK + 문서 집중 회귀: 30 passed
- WALK-005C1 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 189 source files 통과
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
2. 한국어 Conventional Commit으로 WALK-005C1 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

WALK-005C1을 사전 커밋 검토·검증·push한 뒤 `WALK-005C2`를 시작한다. confirmation baseline
이후의 별도 fresh B2 execution만 Retest로 받아들이고, baseline replay와 모든 fresh identity가
달라야 한다. 동일 취약점 재현은 `still-vulnerable`, 불완전·음성 결과는 독립 수정 증명이 없는
한 `inconclusive`로 유지하며 `fixed`를 합성하지 않는다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
