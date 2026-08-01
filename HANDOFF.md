# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `15d4e1a72283a3448c4a9713b569e4841c59386e` (`P0-C2B2B`)
- 현재 구현 체크포인트: `P0-D1` Traditional Web/API Target catalog·private Ground Truth
- 다음 구현: `P0-D2` AI/RAG/MCP Target catalog·ground-truth profile

## 재개 전 확인

이 문서의 SHA보다 실제 저장소 상태를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

정상 delivery 뒤에는 `main`, clean worktree, local HEAD, `origin/main`, 실제 원격
`refs/heads/main`이 모두 같아야 한다. merge, rebase, cherry-pick 또는 background helper가 없어야
한다.

## 현재 구현 상태

`WALK-001`~`WALK-006`, `BENCH-003A/B1/B2`, `P0-C1`, `P0-C2A`, `P0-C2B1`,
`P0-C2B2A1/A2/B`, `P0-D1`이 구현됐다. P0-D1은 다음 경계를 추가한다.

- public `BenchmarkTargetProfileRegistration`과 canonical catalog가 exact profile/factory/provider
  digest, 빈 mutation allowlist, internal network policy, Ground Truth digest를 결박한다.
- complete Ground Truth case와 matcher는 public catalog가 아니라 private
  `BenchmarkTargetGroundTruthBinding`에만 존재한다.
- 첫 code-registered profile은 기존 synthetic Boolean-SQLi Docker lab 하나이며 arbitrary
  image·command, Holdout, AI/RAG/MCP, Hybrid, Mutation을 허용하지 않는다.
- non-executable selection authority는 catalog·registration·Manifest·adapter·provider profile·private
  binding digest를 하나로 묶고 `providerExecutionAuthorized=false`를 고정한다.
- additive Docker wrapper가 provider 호출 전에 exact selection과 provider identity를 검증하고,
  실행 뒤 receipt·coordinate·operation·evidence·image와 등록된 Surface·Finding·chain count를
  다시 대조한다.
- 기존 P0-C lifecycle, recovery, measurement registry, governed Harness wire format은 변경하지
  않는다.

핵심 구현 위치:

- `src/pajin/benchmark/target_catalog.py`
- `src/pajin/benchmark/docker_provider.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_target_catalog.py`
- `tests/test_benchmark_docker_provider.py`
- `docs/benchmark/P0-D1-traditional-web-api-target-catalog.md`
- `docs/adr/0087-traditional-web-api-target-catalog.md`

## 마지막 검증

- Benchmark·Target·문서 집중 테스트: 69 passed, 1 skipped
  - skip: opt-in real Docker conformance
- real Docker registry-governed catalog conformance: 1 passed
  - Docker Desktop 4.78.0 / Engine 29.5.3
  - exact local image ID를 사용한 reset·isolation·HTTP probe·cleanup·seal·reader 완료
  - 종료 뒤 `pajin-bench-*` container·network 없음
- Ruff 전체 통과
- Linux 대상 strict mypy: 200 source files 통과
- 전체 `pytest -x -q`: 206 passed, 4 skipped 뒤 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_benchmark_measurement.py tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_benchmark_target_catalog.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_docker_provider.py tests\test_benchmark_contract.py tests\test_documentation.py
$env:PAJIN_TEST_DOCKER_BENCHMARK='1'; .\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_docker_provider.py::test_real_docker_bug_bounty_provider_conformance
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

권한이 분리된 실행 환경에서 live Docker test가 사용자 Temp의 pytest/advisory lock 경로를 읽지
못하면 저장소 내부의 검증된 임시 경로를 만들고 Python 시작 전에 `TEMP`와 `TMP`를 그 경로로
지정한다. 검증 뒤 해당 임시 경로만 절대 경로 범위를 확인하고 삭제한다. SSL 또는 파일 검증을
끄지 않는다.

## 커밋 전 검토 결과

- public catalog와 selection 직렬화에 private `cases`가 포함되지 않는지 검증했다.
- unknown·duplicate·stale profile, unregistered mutation, forged digest, cross-profile Ground Truth,
  image/profile substitution이 provider 호출 전에 차단되는지 검증했다.
- 생성 뒤 provider identity drift와 foreign receipt/operation/coordinate/evidence가 catalog wrapper
  자체에서 차단되도록 보강했다.
- code-owned matcher가 실제 P0-C2B2B execution evidence보다 넓은 Finding을 주장하지 않는지
  대조했고, 단일 seeded SQLi case와 기존 exact probe count만 허용했다.
- catalog selection이 Capability, measurement signature, registry activation 또는 sealed Harness
  admission으로 오인되지 않도록 `providerExecutionAuthorized=false`와 문서 경계를 확인했다.
- staged diff에서 민감정보, SSL 우회, arbitrary image/command 확장, 기존 wire format 변경이 없는지
  커밋 직전에 다시 확인해야 한다.

## 다음 조치

P0-D1 delivery 뒤 `P0-D2`를 진행한다.

1. WALK-002 RAG injection과 WALK-003 MCP authorization Hypothesis, WALK-004/005 evidence가 실제로
   어떤 target state와 Ground Truth case를 증명하는지 코드·테스트·계약으로 대조한다.
2. 현재 저장소에 AI/RAG/MCP provider lifecycle이 실제로 존재하는지 확인한다. 없으면 catalog가
   실행 가능하다고 주장하지 않고 non-executable profile/fixture 경계 또는 선행 provider 작업을
   명시한다.
3. Traditional Web/API registration을 복제하지 않고 target family별 registration payload와 private
   matcher binding을 확장할 최소 호환 지점을 찾는다.
4. unknown family, cross-family Ground Truth, Hybrid scope expansion, discovered Tool 실행 권한 전환을
   fail closed하는 음성 테스트를 먼저 설계한다.
5. 기능 구현 뒤 집중 테스트, Ruff, Linux-target strict mypy, 가능한 전체 pytest, staged 사전 검토,
   한국어 Conventional Commit, `origin/main` push와 원격 SHA 검증을 반복한다.

## 알려진 경계

- catalog는 content-addressed지만 아직 distribution signature, durable anti-rollback activation,
  sealed Harness source binding이 없다.
- exact image ID는 trusted local provisioning input이며 catalog 생성 주체의 진위는 별도 권위가
  증명하지 않는다.
- provider fence는 같은 host·SQLite·Docker 경계이며 cross-host를 보장하지 않는다.
- activation database 전체 삭제·교체를 막는 외부 복구 anchor는 없다.
- Recovery Authority seal과 journal terminal 전이 사이 hard exit는 같은 cleanup receipt를 참조하는
  보수적 authority를 중복 생성할 수 있다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 뒤 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
