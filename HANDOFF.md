# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `fbbf72e569bcfbe5e3c0c07a1d01f21b469355f1`
- 현재 구현 체크포인트: `WALK-006` Shadow Supervisor Decision 기록 구현, 커밋 전
- 다음 구현: `BENCH-003` Deterministic Baseline·Shadow Decision 비교

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `fbbf72e5`였다. WALK-005C2는 이미
커밋·push됐고 WALK-006 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/discovery/walking_shadow.py`
- `src/pajin/discovery/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-006-shadow-supervisor-decision-record.md`
- `docs/adr/0077-walking-shadow-supervisor-record.md`
- `docs/rfc/0001-pajin-architecture-v2.md`
- `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-006`이 구현됐다. 새 WALK-006 경계는 다음을 보장한다.

- sealed C2 `still-vulnerable` authority와 publication provenance만 Snapshot 입력으로 받는다.
- code-registered Shadow policy와 human remediation-review Task·Stop Decision을 exact하게 결박한다.
- Task는 Capability가 없고 `proposed-not-authorized`이며 Stop은 execution을 허용하지 않는다.
- 결과는 `shadowMode=true`, `baselineMutated=false`, `recorded-not-applied`로 고정한다.
- source Run·TaskGraph·Campaign을 변경하거나 모델·Tool·Permit을 생성하지 않는다.

핵심 구현 위치:

- `src/pajin/discovery/walking_shadow.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-006-shadow-supervisor-decision-record.md`
- `docs/adr/0077-walking-shadow-supervisor-record.md`

## 마지막 검증

현재 WALK-006 worktree 기준:

- WALK/Capability/Replanning/Benchmark/문서 집중 회귀: 85 passed
- WALK-006 포함 WALK + 문서 집중 회귀: 34 passed
- WALK-006 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 190 source files 통과
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
2. 한국어 Conventional Commit으로 WALK-006 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

WALK-006을 사전 커밋 검토·검증·push한 뒤 `BENCH-003`을 시작한다. 기존 BENCH-001 manifest와
result digest 계약을 다시 열어 동일 좌표의 deterministic baseline과 WALK-006 Shadow record를
비교하되, 측정하지 않은 yield·비용·지연 값을 합성하지 않는 최소 comparison authority를 설계한다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
