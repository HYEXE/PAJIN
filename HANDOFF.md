# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 직전 원격 기준: `01c8f3e8ccb30f3b85581866c4589bd25b1edfcb` (`P0-C1`)
- 현재 구현 체크포인트: `P0-C2A` durable Target operation recovery
- 다음 구현: `P0-C2B` 중 Docker 비의존 최소 슬라이스 또는 daemon 복구 후 실제 provider adapter

## 재개 전 확인

이 문서의 고정 SHA보다 실제 저장소 상태를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

정상 delivery 뒤에는 `main`, clean worktree, local HEAD와 `origin/main` 및 실제 원격
`refs/heads/main`이 모두 같아야 한다. merge, rebase, cherry-pick 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-006`, `BENCH-003A/B1/B2`, `P0-C1`, `P0-C2A`가 구현됐다. P0-C2A는
P0-C1 wire format을 바꾸지 않고 다음 복구 경계를 추가한다.

- exact adapter·coordinate마다 SQLite transaction으로 단조 fence를 발급한다.
- reset·isolation·execution·cleanup 호출 전에 content-addressed idempotency operation intent를
  `synchronous=FULL`, `journal_mode=DELETE` journal에 저장한다.
- provider receipt는 exact operation ID·adapter·coordinate·stage와 일치할 때만 기록한다.
- 새 coordinate 전에 open attempt를 더 높은 fence로 claim하고 cleanup을 최대 3회 재시도한다.
- 성공 cleanup 없이는 새 reset을 실행하지 않고 `cleanup-unresolved`로 fail closed한다.
- 전체 journal chain과 resolution fence를 별도 sealed Recovery Authority에 결박하며
  `measurementAdmissionEligible=false`로 고정한다.
- spawn child가 execution intent 직후 `os._exit(23)`으로 종료돼도 다음 시작이 cleanup을
  복구한 뒤에만 새 coordinate를 허용한다.
- recovery 중 `BaseException`은 삼키거나 provider 오류로 허위 분류하지 않고 unmatched intent로
  남겨 다음 더 높은 fence의 reconciliation이 이어받는다.

핵심 구현 위치:

- `src/pajin/benchmark/target_recovery.py`
- `tests/test_benchmark_target_recovery.py`
- `docs/benchmark/P0-C2A-durable-target-operation-recovery.md`
- `docs/adr/0082-durable-target-operation-recovery.md`

## 마지막 검증

- P0-C1/P0-C2A 집중 테스트: 15 passed
- Benchmark·문서 집중 회귀: 최종 검증 기준 28 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 195 source files 통과
- 전체 `pytest -x -q`: 165 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 코드 회귀가 아니라 `KNOWN_ISSUES.md`의 Windows 환경 제약이다.

## 다음 조치

P0-C2A delivery 후 `P0-C2B`를 시작한다. Docker daemon은 2026-08-01 재확인에서도
`//./pipe/docker_engine` 부재로 비활성이므로 실제 Docker 실행 성공을 주장하지 않는다.

1. 먼저 기존 `DockerWorkerBackend`, compose Target, container entrypoint와 P0-C2A recoverable
   provider 계약의 실제 연결 가능성을 read-only로 대조한다.
2. daemon이 계속 비활성이면 Docker 동작을 모사하지 않고, 독립적으로 검증 가능한
   measurement Trust Anchor key registry·rotation/revocation을 `P0-C2B1`로 구현한다.
3. 실제 Docker adapter는 daemon과 로컬 image가 확인된 뒤 provider evidence·network policy·stale
   fence 음성 검증을 포함해 `P0-C2B2`로 구현한다.
4. 운영 Target, 비용 발생 외부 자원, 비밀 key 값은 사용자 추가 승인 없이 생성하지 않는다.

## 알려진 경계

- provider의 원격 fence 강제는 아직 deterministic fixture로만 검증됐다.
- Recovery Authority seal 직후 journal terminal 전이 전에 다시 종료되면 provider cleanup은
  반복하지 않지만 동일 measurement-ineligible authority Run이 중복될 수 있다.
- Docker daemon은 현재 비활성이다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
