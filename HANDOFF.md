# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `ef137213d56933f24369aced367c4baa07c56c2b` (`P0-C2B2A1`)
- 현재 구현 체크포인트: `P0-C2B2A2` mandatory sealed registry-governed Harness
- 다음 구현: `P0-C2B2B` real Docker/provider adapter·evidence·network policy

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
`P0-C2B2A1/A2`가 구현됐다. P0-C2B2A2는 다음 경계를 추가한다.

- signed distribution bundle과 durable activation을 provider reset 전에 필수 검증한다.
- 기존 P0-C1/P0-C2A runner를 P0-C2B1 active-key wrapper로 실행해 lifecycle을 중복하지 않는다.
- 실행 뒤 Target Run과 registry Admission Run을 재개방하고 activation이 seal 시점의 latest head인지 확인한다.
- complete activation·distribution Trust Anchor·Admission Authority와 exact Target/Admission
  Run·root·artifact SHA-256·authority/signature/Observation digest를 새 Harness Authority에 결박한다.
- governed outcome에는 lower-level Observation 변환 메서드를 두지 않고 전용 reader만 제공한다.
- reader는 세 sealed Run, exact accepted activation revision, 현재 out-of-band distribution Trust
  Anchor를 재검증한 뒤에만 registry-governed Observation을 반환한다.
- 실행 중 rotation은 publication을 차단하고, 완료 뒤 measurement registry rotation은 historical
  exact revision으로 보존하며, distribution signing-key revocation은 과거 결과에도 적용한다.
- source·activation·authority·audit mutation과 empty/wrong activation store가 fail closed한다.

핵심 구현 위치:

- `src/pajin/benchmark/measurement_harness.py`
- `src/pajin/benchmark/measurement_registry_distribution.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_measurement_registry.py`
- `docs/benchmark/P0-C2B2A2-mandatory-registry-governed-harness.md`
- `docs/adr/0085-mandatory-registry-governed-benchmark-harness.md`

## 마지막 검증

- Benchmark registry·Target·문서 집중 테스트: 49 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 198 source files 통과
- 전체 `pytest -x -q`: 186 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_measurement_registry.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_target_factory.py tests\test_benchmark_target_recovery.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 코드 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경 제약이다.

## 다음 조치

P0-C2B2A2 delivery 후 `P0-C2B2B`를 진행한다.

1. 먼저 Docker daemon을 재확인하고 기존 `DockerWorkerBackend`, compose Target, container
   entrypoint, network 설정을 read-only로 조사한다.
2. daemon과 로컬 image가 가용하면 `RecoverableBenchmarkTargetFactoryAdapter`를 구현해 reset,
   isolation, execution, cleanup/reconcile, measurement attestation을 실제 컨테이너 lifecycle에 연결한다.
3. operation ID와 fence를 provider label/state에 원자적으로 반영하고 stale fence 거부를 검증한다.
4. container/image/network/exit 상태를 canonical provider evidence로 수집하고 receipt digest에 결박한다.
5. egress deny-by-default와 명시적 allow policy를 실제 network inspection으로 음성 검증한다.
6. 구현된 adapter를 P0-C2B2A2 governed Harness에 넣어 live sealed Observation까지 검증한다.

Docker daemon은 2026-08-01 마지막 확인에서 `//./pipe/docker_engine` 부재로 비활성이다. daemon이
계속 비활성이면 실제 Docker 성공을 주장하지 않고, 안전하게 검증 가능한 adapter contract와
negative preflight까지만 분리해 진행한다. 운영 Target, 비용 발생 외부 자원, 비밀 key 값은 추가
승인 없이 생성하거나 사용하지 않는다.

## 알려진 경계

- 실제 Docker/cloud provider의 fence enforcement, provider evidence, network policy는 아직 검증되지 않았다.
- activation database 전체 삭제·교체를 막는 외부 복구 anchor는 없다.
- distribution Trust Anchor rotation, remote HTTPS fetch, transparency/federation은 아직 없다.
- Recovery Authority seal과 journal terminal 전이 사이 hard exit는 같은 보수적 authority를 중복 생성할 수 있다.
- Docker daemon은 현재 비활성이다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 후 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
