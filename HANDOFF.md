# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `6d38519694aafd5572b8794963e3edfa61ddd45d` (`P0-D5`)
- 현재 구현 체크포인트: `P0-E1` Deterministic PAJIN baseline measurement authority
- 다음 구현: `P0-E2` 일반 Scanner baseline measurement authority

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. 정상 delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같아야 한다.

## 현재 구현 상태

P0-E1은 P0-D1 runnable catalog와 P0-C2B2A2 registry-governed Harness를 하나의 실제 baseline
measurement authority로 연결한다.

- 각 Harness와 Target Run을 reader로 다시 열고 signed registry activation·admission·attestation을
  검증한다.
- sealed execution receipt로 Docker provider evidence를 다시 조회하고, exact image·fixed probe·private
  Ground Truth matcher를 다시 검증한다.
- 정확히 하나의 deterministic baseline arm과 Manifest의 전체 seed/repetition 좌표를 요구한다.
- caller aggregate를 받지 않고 sealed raw Observation에서 기존 BENCH-003B1과 동일한 12 metric을
  계산한다.
- Manifest, catalog selection, source binding, raw Observation bundle, Result와 audit event를 별도
  content-addressed Run으로 봉인한다.
- candidate comparison과 Supervisor activation eligibility는 literal false다.

핵심 구현 위치:

- `src/pajin/benchmark/deterministic_baseline.py`
- `src/pajin/benchmark/target_catalog.py`
- `src/pajin/benchmark/measurement.py`
- `tests/test_benchmark_deterministic_baseline.py`
- `docs/benchmark/P0-E1-deterministic-pajin-baseline-measurement.md`
- `docs/adr/0095-catalog-and-registry-governed-deterministic-baseline.md`

## 마지막 검증

- P0-E1 단독 테스트: 6 passed
- P0-E1·catalog·registry·BENCH-003·Holdout·Mutation·문서·계약 집중 회귀: 81 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 207 source files 통과
- 전체 `pytest -x -q`: 283 passed, 6 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_deterministic_baseline.py tests\test_benchmark_target_catalog.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_measurement_registry_distribution.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_holdout_target_factory.py tests\test_benchmark_mutation_target_factory.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- catalog selection digest만 사후 부착해 catalog matcher 실행을 가장할 수 없는지 확인한다.
- provider evidence가 exact execution receipt·operation·coordinate·image와 결박되는지 확인한다.
- source reader가 Harness·Target·registry activation과 catalog evidence를 모두 다시 여는지 확인한다.
- 누락·중복·추가 seed/repetition과 cross-Manifest·cross-arm replay가 거부되는지 확인한다.
- raw Observation 또는 evidence bundle과 다른 Result를 봉인할 수 없는지 확인한다.
- candidate comparison·Supervisor activation flag가 false에서 상승할 수 없는지 확인한다.

## 다음 조치

`P0-E2`를 진행한다.

1. 저장소에 이미 일반 Scanner adapter·CLI·SARIF/JSON parser 또는 scanner identity 계약이 있는지 먼저
   조사한다.
2. 없으면 특정 외부 Scanner를 임의 선택하거나 설치하지 않고, scanner registration·invocation·output
   evidence를 비실행 contract로 먼저 묶어야 하는지 판단한다.
3. runnable 수직 슬라이스가 가능하면 P0-E1과 같은 Manifest·Target·registry 좌표를 재사용하되 scanner
   binary/image/version/configuration과 raw output digest를 별도 authority에 결박한다.
4. synthetic output이나 PAJIN Observation 변환을 실제 Scanner 측정으로 오인하지 않으며 candidate
   comparison과 Supervisor activation은 계속 false로 유지한다.

## 알려진 경계

- P0-E1은 local deterministic P0-D1 Docker lab 측정이며 production Web/API benchmark가 아니다.
- catalog distribution은 아직 signed durable activation이 아니며 code-owned local registration이다.
- P0-E1은 PAJIN baseline 하나만 측정하고 Scanner 또는 single-agent 비교를 수행하지 않는다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않을 수 있다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
