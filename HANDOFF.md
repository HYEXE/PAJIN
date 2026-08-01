# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `5d96d81f6d27fc57700946a26bfe4dd71d19ee18` (`P0-E1`)
- 현재 구현 체크포인트: `P0-E2A` Generic Scanner baseline measurement plan
- 다음 구현: `P0-E2B` 실제 Scanner provider·raw output·measurement authority

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

P0-E2A는 저장소에 일반 Scanner runtime·parser·artifact identity가 없는 상태에서 허위 실측을 막는
contract-first 경계다.

- code-owned generic Scanner contract가 scanner ID/version, executable artifact SHA-256,
  configuration digest와 SARIF 2.1.0 parser contract를 요구한다.
- Scanner baseline Manifest는 정확히 하나의 deterministic arm, 고정 implementation/configuration과
  mutation 없음만 허용한다.
- 기존 P0-D1 selector로 Manifest·adapter·Docker profile·catalog·private Ground Truth를 다시 검증한다.
- 전체 seed/repetition 좌표를 canonical plan에 한 번씩 결박한다.
- scanner identity, invocation receipt, raw output, Benchmark Result, comparison, Supervisor activation은
  모두 literal false다.

핵심 구현 위치:

- `src/pajin/benchmark/scanner_baseline.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_scanner_baseline.py`
- `docs/benchmark/P0-E2A-generic-scanner-baseline-plan.md`
- `docs/adr/0096-bind-scanner-contract-before-measurement.md`

## 마지막 검증

- P0-E2A 단독 테스트: 13 passed
- P0-E2A·P0-E1·Target catalog·BENCH-001·문서 집중 회귀: 37 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 208 source files 통과
- 전체 `pytest -x -q`: 296 passed, 6 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_scanner_baseline.py tests\test_benchmark_deterministic_baseline.py tests\test_benchmark_target_catalog.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- 특정 Scanner product·binary·image가 구현 없이 등록된 것처럼 보이지 않는지 확인한다.
- parser contract·identity fields·Manifest implementation/configuration 치환이 거부되는지 확인한다.
- alternate Target profile/catalog/Ground Truth와 candidate·mutation scope 확대를 차단하는지 확인한다.
- 전체 좌표의 누락·중복·재정렬이 authority 생성 전에 거부되는지 확인한다.
- 실행·raw output·Result·comparison·Supervisor flag가 false에서 상승할 수 없는지 확인한다.

## 다음 조치

`P0-E2B`를 진행한다.

1. 실제 Scanner artifact 후보와 라이선스·배포·출력 안정성·Docker isolation 적합성을 결정한다.
2. 선택한 artifact의 immutable image/binary digest와 configuration을 별도 registration에 결박한다.
3. fresh P0-D1 Target isolation 안에서 invocation receipt와 bounded raw SARIF artifact를 봉인한다.
4. code-owned parser로 raw output을 Observation으로 변환하고 recovery·cleanup·measurement registry
   admission을 거친 뒤에만 completed Result를 허용한다.

구체 외부 Scanner 선택은 제품·공급망 결정이므로 현재 구현이 임의로 확정하지 않는다. 선택 전에도
parser와 runtime boundary를 더 구체화할 수 있는 범위는 계속 조사한다.

## 알려진 경계

- P0-E2A는 measurement plan이며 Scanner 측정 결과가 아니다.
- P0-E1 local deterministic PAJIN Result와 비교할 Scanner Result는 아직 없다.
- catalog distribution과 provider fence의 기존 local 범위는 그대로다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않을 수 있다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
