# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `7df812773b9b693388171f4b380390b33f8dfb9c`
- 현재 구현 체크포인트: `BENCH-003A` Shadow Decision structural comparison 구현, 커밋 전
- 다음 구현: `BENCH-003B` 동일 좌표 measured Result Harness·numeric comparison

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `7df81277`이었다. WALK-006은 이미
커밋·push됐고 BENCH-003A 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/benchmark/shadow.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/benchmark/BENCH-003A-walking-shadow-decision-comparison.md`
- `docs/adr/0078-shadow-decision-structural-benchmark.md`
- `docs/rfc/0001-pajin-architecture-v2.md`
- `README.md`, `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-006`과 `BENCH-003A`가 구현됐다. 새 BENCH-003A 경계는 다음을 보장한다.

- baseline-only BENCH-001 Manifest와 exact WALK-006 source publication을 결박한다.
- completed C2의 deterministic terminal Decision과 Shadow Task·Stop의 구조 delta만 기록한다.
- human review Task 추가 외 autonomous execution·Capability 변화가 없음을 고정한다.
- 12개 필수 metric 이름만 보존하고 metric 값·delta를 만들지 않는다.
- numeric BenchmarkComparison과 Supervisor activation eligibility를 모두 false로 유지한다.

핵심 구현 위치:

- `src/pajin/benchmark/shadow.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/benchmark/BENCH-003A-walking-shadow-decision-comparison.md`
- `docs/adr/0078-shadow-decision-structural-benchmark.md`

## 마지막 검증

현재 BENCH-003A worktree 기준:

- WALK/Capability/Replanning/Benchmark/문서 집중 회귀: 87 passed
- BENCH-003A 포함 WALK + 문서 집중 회귀: 36 passed
- BENCH-003A 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 191 source files 통과
- 전체 `pytest -x -q`: 150 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py tests\test_discovery_replanning.py tests\test_existing_capability_rollout.py tests\test_documentation.py tests\test_benchmark_contract.py
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
2. 한국어 Conventional Commit으로 BENCH-003A 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

BENCH-003A를 사전 커밋 검토·검증·push한 뒤 `BENCH-003B`를 시작한다. BENCH-001의 exact
reset·isolation·cleanup protocol과 seed/repetition 좌표를 실제 sealed Run에 결박하고, 12개 metric
전부가 근거 있는 관찰에서 계산될 때만 baseline/candidate `BenchmarkResult`와 numeric comparison을
생성하는 최소 Harness를 설계한다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
