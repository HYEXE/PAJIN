# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `0e89f8640dee2337f09bbdd7e099dfbd95048b3b` (`P0-E2A`)
- 현재 구현 체크포인트: `P0-E2B` OWASP ZAP Scanner baseline measurement
- 다음 구현: `P0-E3` Single-agent baseline measurement authority

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

P0-E2B는 P0-E2A plan을 실제 OWASP ZAP 2.17.0 provider와 registry-governed measurement에
연결한다.

- code-owned `ZAPScannerRegistration`이 exact runtime image ID, automation-plan digest와 기존
  parser-contract digest를 결박한다. Scanner container는 tag가 아니라 immutable image ID로 생성된다.
- 기존 P0-D1 fenced lifecycle과 catalog wrapper를 재사용해 reset→internal isolation→ZAP execution→
  cleanup→registry admission을 수행한다.
- Scanner는 read-only root, dropped capabilities, `no-new-privileges`, 고정 user/resource limit와
  operation 전용 mount만 사용한다. 저장소 전체를 mount하지 않는다.
- requestor→bounded active scan→`sarif-json` plan과 raw SARIF bytes를 그대로 보존한다.
- strict parser는 exact ZAP 2.17.0 tool identity와 bounded shape만 수용하고, P0-D1 known surface를
  scheme·host·port·path·query key에 결박한다.
- provider evidence가 registration/plan/image/container/raw hash·size/normalization을 execution receipt에
  결박한다.
- measurement reader가 registry-governed Harness, Target Run, provider raw SARIF와 별도 sealed raw
  SARIF를 모두 다시 열어 exact equality를 요구한다.
- zero candidate·confirmation·replay·human count를 허용하고, completed Result의 실제 분모 없는 5개
  metric만 explicit `not-applicable`로 허용한다. comparison과 Supervisor activation은 false다.

핵심 구현 위치:

- `src/pajin/benchmark/scanner_sarif.py`
- `src/pajin/benchmark/scanner_docker_provider.py`
- `src/pajin/benchmark/scanner_measurement.py`
- `src/pajin/benchmark/measurement.py`
- `tests/test_benchmark_zap_scanner.py`
- `docs/benchmark/P0-E2B-zap-scanner-baseline-measurement.md`
- `docs/adr/0097-run-concrete-zap-baseline-with-raw-sarif.md`

## 실제 Docker 검증

Docker Desktop 4.78.0 / Engine 29.5.3에서 production adapter의 opt-in conformance를 실행했다.

- target image ID: `sha256:1237af881d2cdbe96cc87dada42a9fd8952abd10ab357463c2efaf8aafd1e5a1`
- worker image ID: `sha256:84c1dad2e13f260c6daee0850c0c76b1be8b7944dccd2c33689ae83b949f04af`
- ZAP image ID: `sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2`
- 결과: `1 passed in 28.60s`
- 종료 뒤 `pajin.benchmark.managed=true` container와 network가 남지 않았고 테스트 전용 임시
  디렉터리도 제거했다.

Windows sandbox 계정과 escalated Docker 계정의 기본 `%TEMP%` ACL이 달라 Run lock 접근이 두 번
실패했으나, `TEMP/TMP`와 pytest `--basetemp`를 저장소 전용 임시 디렉터리로 맞춘 뒤 production
경로가 통과했다. 이는 코드나 Docker lifecycle 실패가 아니다.

## 마지막 검증

- P0-E2B·BENCH-001 집중 테스트: 14 passed, 1 skipped(opt-in live)
- Scanner·measurement·Docker·문서 집중 회귀: 70 passed, 3 skipped
- 실제 Docker ZAP conformance: 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 211 source files 통과
- 전체 `pytest -x -q`: 302 passed, 7 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_zap_scanner.py tests\test_benchmark_contract.py tests\test_benchmark_scanner_baseline.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_docker_provider.py tests\test_documentation.py
$env:PAJIN_TEST_DOCKER_ZAP='1'
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_zap_scanner.py::test_real_docker_zap_scanner_measurement_conformance
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`P0-E3`의 가장 작은 수직 슬라이스를 설계한다.

1. 저장소의 기존 single-agent Planner/Worker/model/tool execution과 benchmark 관련 authority를 조사해
   이미 충족된 lifecycle과 실제 누락된 identity·trace·measurement 경계를 구분한다.
2. Scanner나 deterministic PAJIN provider를 이름만 바꾸지 않고, exact agent implementation/version,
   model/tool configuration, bounded execution policy와 raw trace parser contract를 먼저 결박한다.
3. 실제 provider가 저장소와 환경에 없다면 P0-E3A non-runnable plan으로 허상 실행을 차단하고,
   provider 선택·비용·비밀정보 authority는 별도 결정으로 남긴다.
4. runnable 경계가 이미 존재하면 fresh P0-D1 isolation, complete coordinates, sealed raw trace,
   registry-governed admission을 잇는 최소 additive provider를 구현한다.

## 알려진 경계

- P0-E2B는 local Docker P0-D1과 ZAP 2.17.0 한 configuration의 baseline이다.
- 실제 live run은 known surface를 관찰했지만 등록 SQL-injection Finding은 일치하지 않았다. 이는
  recall을 0으로 기록해야 하는 측정 결과이며 실패를 양성으로 합성하지 않는다.
- P0-E1과 P0-E2B Result는 분모 없는 metric 때문에 현재 numeric comparison 대상이 아니다.
- catalog distribution, cross-host fence와 production Scanner 공급망은 별도 경계다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않을 수 있다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 commit·push하고
다음 개발로 계속 진행하는 것을 승인했다.
