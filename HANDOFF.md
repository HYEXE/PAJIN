# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `1ee4627a385ad93cf9e179f511e617b244b11e03` (`P0-C2A`)
- 현재 구현 체크포인트: `P0-C2B1` Benchmark Measurement Trust Registry
- 다음 구현: `P0-C2B2` signed durable registry checkpoint와 mandatory Harness admission

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

`WALK-001`~`WALK-006`, `BENCH-003A/B1/B2`, `P0-C1`, `P0-C2A`, `P0-C2B1`이 구현됐다.
P0-C2B1은 기존 P0-C1 Trust Anchor wire shape을 유지하면서 다음 경계를 추가한다.

- 한 measurement authority ID/version에 속한 public Trust Anchor를 content-addressed registry로 관리한다.
- registry마다 active key는 정확히 하나이며 retired key는 bounded historical verification만 허용한다.
- revoked key는 발행 시점과 무관하게 fresh·historical 검증을 모두 거부한다.
- revision 2부터 exact predecessor를 요구하고 rollback·gap·key substitution·lifecycle resurrection을 차단한다.
- P0-C1/P0-C2A 공통 runner Protocol을 사용해 provider reset 전에 active key를 preflight한다.
- 별도 sealed Admission Run이 registry/predecessor와 source Run/root/artifact/signature를 결박한다.
- 미래에 발행된 registry revision은 fresh뿐 아니라 historical admission에서도 거부한다.
- 기존 direct runner와 BENCH-003B1 reader는 호환성을 위해 유지되며 registry-governed 주장을 자동 부여하지 않는다.

핵심 구현 위치:

- `src/pajin/benchmark/measurement_registry.py`
- `src/pajin/benchmark/target_factory.py`
- `src/pajin/benchmark/target_recovery.py`
- `tests/test_benchmark_measurement_registry.py`
- `docs/benchmark/P0-C2B1-benchmark-measurement-trust-registry.md`
- `docs/adr/0083-benchmark-measurement-trust-registry.md`

## 마지막 검증

- Benchmark·문서 집중 테스트: 36 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 196 source files 통과
- 전체 `pytest -x -q`: 173 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_measurement_registry.py tests\test_benchmark_target_factory.py tests\test_benchmark_target_recovery.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 코드 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경 제약이다.

## 다음 조치

P0-C2B1 delivery 후 `P0-C2B2`를 다음 순서로 진행한다.

1. signed registry distribution과 마지막 accepted revision의 durable anti-rollback checkpoint를 최소 수직 슬라이스로 구현한다.
2. registry-governed Benchmark Harness에서 combined target/admission outcome과 reader 검증을 필수화한다.
3. 기존 `DockerWorkerBackend`, compose Target, container entrypoint를 조사해 recoverable provider 계약 연결점을 정한다.
4. Docker daemon과 로컬 image가 가용할 때 provider evidence·network policy·stale fence 음성 검증을 실제 컨테이너에서 수행한다.
5. 운영 Target, 비용 발생 외부 자원, 비밀 key 값은 추가 승인 없이 생성하거나 사용하지 않는다.

Docker daemon은 2026-08-01 재확인에서 `//./pipe/docker_engine` 부재로 비활성이다. 따라서
daemon이 계속 비활성이면 실제 Docker 실행 성공을 주장하지 않고, 1~2번의 로컬 권위 경계부터 완료한다.

## 알려진 경계

- registry distribution origin은 아직 서명되지 않았고 latest revision은 durable store에 pin되지 않는다.
- direct P0-C1/P0-C2A runner와 기존 BENCH-003B reader는 registry admission을 자동 요구하지 않는다.
- provider의 exact fence 강제는 아직 deterministic fixture로만 검증됐다.
- Recovery Authority seal과 journal terminal 전이 사이 hard exit는 같은 measurement-ineligible authority Run을 중복 생성할 수 있다.
- Docker daemon은 현재 비활성이다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 후 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
