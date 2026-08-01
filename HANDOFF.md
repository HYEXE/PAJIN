# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `d9b658eec6247b4c07bbbd9033f3db16bc37eb9e`
- 현재 구현 체크포인트: `BENCH-003B2` WALK-006 Shadow policy-bound measurement 구현, 커밋 전
- 다음 구현: `P0-C` provider-backed Target Factory measurement adapter

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `d9b658e`이었다. BENCH-003B1은 이미
커밋·push됐고 BENCH-003B2 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/benchmark/shadow_measurement.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/benchmark/BENCH-003B2-walking-shadow-policy-binding.md`
- `docs/adr/0080-shadow-policy-bound-measured-benchmark.md`
- `docs/rfc/0001-pajin-architecture-v2.md`
- `README.md`, `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-006`과 `BENCH-003A/B1/B2`가 구현됐다. 새 BENCH-003B2 경계는 다음을
보장한다.

- sealed BENCH-003A와 BENCH-003B1 source Run/root/artifact SHA를 함께 결박한다.
- measured Manifest envelope와 baseline arm이 A와 exact equality여야 한다.
- candidate implementation ID/version/configuration digest가 WALK-006 policy와 같아야 한다.
- B1 Result·metric·Comparison을 다시 계산하거나 바꾸지 않는다.
- benchmark comparison eligibility는 true지만 Supervisor activation은 false다.
- 외부 measurement authority의 의미적 진실성은 여전히 명시적 trust root다.

핵심 구현 위치:

- `src/pajin/benchmark/shadow_measurement.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/benchmark/BENCH-003B2-walking-shadow-policy-binding.md`
- `docs/adr/0080-shadow-policy-bound-measured-benchmark.md`

## 마지막 검증

현재 BENCH-003B2 worktree 기준:

- BENCH/WALK/Capability/Replanning/문서 집중 회귀: 92 passed
- WALK + 문서 집중 회귀: 38 passed
- BENCH-003B2 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 193 source files 통과
- 전체 `pytest -x -q`: 150 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py tests\test_discovery_replanning.py tests\test_existing_capability_rollout.py tests\test_documentation.py tests\test_benchmark_contract.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_benchmark_measurement.py
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
2. 한국어 Conventional Commit으로 BENCH-003B2 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

BENCH-003B2를 사전 커밋 검토·검증·push한 뒤 `P0-C`를 시작한다. provider-backed Target
Factory adapter가 모든 coordinate마다 reset·isolation·execution·raw observation·cleanup을 실제로
수행하고, B1 measurement authority identity에 외부 attestation을 결박하는 최소 경계를 설계한다.
운영 Target이나 비용 발생 외부 자원은 사용자 승인 없이 생성하지 않는다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
