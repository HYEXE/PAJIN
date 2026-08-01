# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `e68404011c39f7061f11dc5bfd4605e4500f4fe1` (`P0-C2B2A2`)
- 현재 구현 체크포인트: `P0-C2B2B` local Docker provider·evidence·network policy
- 다음 구현: `P0-D1` Traditional Web/API Target Factory catalog·ground-truth profile

## 재개 전 확인

이 문서의 고정 SHA보다 실제 저장소 상태를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

정상 delivery 뒤에는 `main`, clean worktree, local HEAD, `origin/main`, 실제 원격
`refs/heads/main`이 모두 같아야 한다. merge, rebase, cherry-pick 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-006`, `BENCH-003A/B1/B2`, `P0-C1`, `P0-C2A`, `P0-C2B1`,
`P0-C2B2A1/A2/B`가 구현됐다. P0-C2B2B는 다음 경계를 추가한다.

- 고정 synthetic Boolean-SQLi profile이 Target·Worker image reference와 exact image ID,
  `internal-bridge` policy를 Target Factory digest에 결박한다.
- provider-owned SQLite가 core journal과 별도로 operation ID, attempt, stage order, monotonic fence,
  completed result를 영속하고 stale fence를 Docker 호출 전에 차단한다.
- 별도 SQLite operation lock이 live lower-fence mutation과 higher-fence cleanup을 같은 host에서
  직렬화하며 process crash 때 자동 해제된다.
- deterministic labelled network·Target·Worker를 생성하고 internal network, 무포트, non-root,
  read-only, cap-drop, no-new-privileges, CPU·memory·PID 제한을 inspect로 검증한다.
- 실제 Worker의 고정 `bug-bounty-sqli-probe` 결과만 Observation으로 변환하고 cleanup 뒤 모든
  container와 network의 부재를 요구한다.
- bounded provider evidence를 stage receipt digest에 결박하고 exact receipt로만 재조회한다.
- 기존 P0-C2A runner와 P0-C2B2A2 governed Harness에 provider 전용 우회 없이 연결된다.

핵심 구현 위치:

- `src/pajin/benchmark/docker_provider.py`
- `src/pajin/benchmark/target_recovery.py`
- `src/pajin/benchmark/measurement_harness.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_docker_provider.py`
- `docs/benchmark/P0-C2B2B-local-docker-provider-evidence.md`
- `docs/adr/0086-local-docker-benchmark-provider.md`

## 마지막 검증

- Docker provider·Benchmark registry·Target·문서 집중 테스트: 60 passed, 1 skipped
  - skip: opt-in real Docker conformance
- real Docker conformance: 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 199 source files 통과
- 전체 `pytest -x -q`: 197 passed, 4 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- live conformance 종료 뒤 `pajin-bench-*` container·network 없음 확인

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_docker_provider.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_target_factory.py tests\test_benchmark_target_recovery.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_contract.py tests\test_documentation.py
docker build --tag pajin-benchmark-worker:dev containers\benchmark-worker
docker build --tag pajin-bug-bounty-target:dev containers\bug-bounty-target
$env:PAJIN_TEST_DOCKER_BENCHMARK='1'; .\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_docker_provider.py::test_real_docker_bug_bounty_provider_conformance
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 코드 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경 제약이다.

## 다음 조치

P0-C2B2B delivery 후 `P0-D1`을 진행한다.

1. `BENCH-001`, P0-C1/C2 계약과 현재 Bug Bounty profile을 읽고 단일 profile의 고정값과
   일반 Traditional Web/API Target catalog authority를 구분한다.
2. arbitrary image/command 실행 권한을 만들지 않고 code-registered Target profile ID·version·digest,
   exact image identities, scenario, Ground Truth mapping, mutation eligibility를 정의한다.
3. unknown·duplicate·stale profile, image substitution, cross-profile Ground Truth, capability/network
   policy 확대를 fail closed하는 최소 contract와 registry부터 구현한다.
4. P0-C2B2B adapter가 catalog의 exact registered profile만 선택하도록 additive wrapper를 연결한다.
5. 다음 실제 profile 추가는 catalog authority와 기존 synthetic lab 연결이 검증된 뒤 별도 기능으로
   진행한다.

Docker daemon은 2026-08-01에 Docker Desktop 4.78.0 / Engine 29.5.3으로 가동됐고 live conformance가
통과했다. 다음 세션에는 daemon과 exact image ID를 다시 확인한다. 운영 Target, 비용 발생 외부 자원,
비밀 key 값은 추가 승인 없이 생성하거나 사용하지 않는다.

## 알려진 경계

- provider fence와 operation lock은 한 host의 SQLite·Docker 경계이며 cross-host를 보장하지 않는다.
- activation database 전체 삭제·교체를 막는 외부 복구 anchor는 없다.
- distribution Trust Anchor rotation, remote HTTPS fetch, transparency/federation은 아직 없다.
- Recovery Authority seal과 journal terminal 전이 사이 hard exit는 같은 보수적 authority를 중복 생성할 수 있다.
- Docker daemon 가용성은 세션 의존이며 live test는 opt-in이다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 후 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
