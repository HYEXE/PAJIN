# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `cb27dc21d6bc653d9d3e1b74361d1cce1b36e425` (`P0-C2B1`)
- 현재 구현 체크포인트: `P0-C2B2A1` signed measurement registry distribution
- 다음 구현: `P0-C2B2A2` mandatory sealed registry-governed Harness admission

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
`P0-C2B2A1`이 구현됐다. P0-C2B2A1은 다음 경계를 추가한다.

- measurement registry 배포 전용 out-of-band Ed25519 Trust Anchor를 사용한다.
- signed statement가 현재·직전 registry, registry revision과 같은 sequence, 이전 bundle digest,
  trust domain·issuer, 7일 이하의 validity window를 결박한다.
- unknown/revoked distribution key를 거부하고 retired key는 발행 시점이 유효기간 안인 과거 bundle만 검증한다.
- host-local SQLite activation store가 `synchronous=FULL`, `journal_mode=DELETE`,
  `BEGIN IMMEDIATE`로 accepted head를 저장한다.
- revision 1만 bootstrap하고 이후 contiguous revision만 허용해 restart rollback·gap·equivocation·
  predecessor mismatch·Trust Anchor substitution을 차단한다.
- update·delete·replace trigger와 file/ancestor/sidecar/symlink/junction/hardlink 검사를 적용한다.
- restart reader가 SQLite row identity와 content-addressed activation 내부 bundle을 exact equality로 재검증한다.
- private distribution key는 signer helper 밖으로 직렬화되지 않는다.

핵심 구현 위치:

- `src/pajin/benchmark/measurement_registry_distribution.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_measurement_registry_distribution.py`
- `docs/benchmark/P0-C2B2A1-signed-measurement-registry-distribution.md`
- `docs/adr/0084-signed-measurement-registry-distribution.md`

## 마지막 검증

- Benchmark registry·Target·문서 집중 테스트: 41 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 197 source files 통과
- 전체 `pytest -x -q`: 178 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_target_factory.py tests\test_benchmark_target_recovery.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 코드 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경 제약이다.

## 다음 조치

P0-C2B2A1 delivery 후 `P0-C2B2A2`를 다음 순서로 진행한다.

1. verified `BenchmarkMeasurementRegistryActivation`을 exact P0-C2B1 target/admission outcome에 결박하는 새 sealed Harness Authority를 설계한다.
2. Harness reader가 activation bundle signature/current validity, durable store head, target Run,
   registry admission Run을 모두 다시 열어 검증한 뒤에만 Observation을 반환하게 한다.
3. existing direct P0-C1/P0-C2A/B1 reader는 호환성을 위해 유지하되 registry-governed API에서는 우회할 수 없게 한다.
4. activation/source/admission/Harness artifact와 audit event mutation, stale activation, cross-bundle substitution을 Worker 결과 사용 전에 차단한다.
5. 그 다음 `P0-C2B2B`에서 Docker daemon 가용성을 확인하고 실제 provider evidence·network policy를 구현한다.

Docker daemon은 2026-08-01 재확인에서 `//./pipe/docker_engine` 부재로 비활성이다. 운영 Target,
비용 발생 외부 자원, 비밀 key 값은 추가 승인 없이 생성하거나 사용하지 않는다.

## 알려진 경계

- activation database 전체가 삭제·교체되면 remembered head도 사라지므로 외부 복구 anchor는 없다.
- distribution Trust Anchor rotation, remote HTTPS fetch, transparency/federation은 아직 없다.
- signed activation은 아직 exact target/admission과 하나의 mandatory sealed Harness authority로 결박되지 않았다.
- provider의 exact fence 강제와 실제 network policy는 deterministic fixture 밖에서 검증되지 않았다.
- Docker daemon은 현재 비활성이다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 후 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
