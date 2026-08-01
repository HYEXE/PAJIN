# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `3087ff093e384f89cc7325a43203629c1eae241e`
- 현재 구현 체크포인트: `P0-C1` provider-neutral Target Factory lifecycle 구현, 커밋 전
- 다음 구현: `P0-C2` real Docker/provider adapter·key registry

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `3087ff0`이었다. BENCH-003B2는 이미
커밋·push됐고 P0-C1 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/benchmark/target_factory.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_target_factory.py`
- `docs/benchmark/P0-C1-provider-neutral-target-factory-lifecycle.md`
- `docs/adr/0081-provider-neutral-benchmark-target-lifecycle.md`
- `docs/rfc/0001-pajin-architecture-v2.md`
- `README.md`, `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-006`, `BENCH-003A/B1/B2`, `P0-C1`이 구현됐다. 새 P0-C1 경계는 다음을
보장한다.

- exact Manifest arm/seed/repetition coordinate로 provider lifecycle을 시작한다.
- reset·isolation authority를 다음 provider 호출 전에 검증하고 identity drift를 차단한다.
- 유효한 isolation 이후 execution 실패나 foreign raw Observation에서도 cleanup을 시도한다.
- raw metric identity를 덮어쓰지 않고 final cleanup 상태와 content ID만 재구성한다.
- 네 receipt와 Observation을 외부 Ed25519 measurement signature 및 public anchor에 결박한다.
- 같은 sealed Run을 BENCH-003B1 Observation reader가 직접 읽을 수 있다.
- deterministic adapter는 계약 fixture이며 실제 provider 실행은 P0-C2로 남긴다.

핵심 구현 위치:

- `src/pajin/benchmark/target_factory.py`
- `tests/test_benchmark_target_factory.py`
- `docs/benchmark/P0-C1-provider-neutral-target-factory-lifecycle.md`
- `docs/adr/0081-provider-neutral-benchmark-target-lifecycle.md`

## 마지막 검증

현재 P0-C1 worktree 기준:

- BENCH/WALK/Capability/Replanning/문서 집중 회귀: 98 passed
- P0-C1 + 문서 집중 회귀: 8 passed
- P0-C1 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 194 source files 통과
- 전체 `pytest -x -q`: 156 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py tests\test_discovery_replanning.py tests\test_existing_capability_rollout.py tests\test_documentation.py tests\test_benchmark_contract.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_benchmark_measurement.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_target_factory.py
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
2. 한국어 Conventional Commit으로 P0-C1 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

P0-C1을 사전 커밋 검토·검증·push한 뒤 `P0-C2`를 시작한다. 먼저 Docker daemon과 기존 local
Target image/command 지원 상태를 read-only로 확인한다. 실제 adapter를 안전하게 실행할 토대가 없으면
허상 구현을 만들지 않고 provider evidence·network policy·key registry·cleanup recovery 중 독립적인
최소 계약을 선택한다. 운영 Target이나 비용 발생 외부 자원은 사용자 승인 없이 생성하지 않는다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
