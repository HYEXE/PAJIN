# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `70722888d377f45e44442866942e686e070f16e0` (`P0-D1`)
- 현재 구현 체크포인트: `P0-D2` AI/RAG/MCP non-runnable fixture catalog·Ground Truth
- 다음 구현: `P0-D2B` local AI/RAG/MCP provider·catalog promotion

## 재개 전 확인

이 문서보다 실제 저장소 상태를 우선한다.

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
`P0-C2B2A1/A2/B`, `P0-D1`, `P0-D2`가 구현됐다. P0-D2는 다음 경계를 추가한다.

- shared public Target catalog가 기존 `traditional-web-api`와 새 `ai-rag-mcp` 두 family를
  code-owned catalog ID별로 구분한다. mixed-family registration은 모델 생성 단계에서 거부한다.
- 기존 P0-D1 public wire에는 새 필드를 추가하지 않았다. family, provider API version, network
  policy validator만 두 번째 exact 값을 허용한다.
- `AIRAGMCPWalkingTargetProfile`이 WALK-002/003/005A/005B2/005C1 API version과 현재 fixture의
  execution·evidence trust 경계를 content digest로 결박한다.
- private Ground Truth는 File Upload -> RAG Injection -> MCP Tool Authorization Failure -> Internal
  Data Access seeded case 하나와 실제 walking validator가 사용하는 exact state·input/output matcher를
  가진다. public catalog에는 그 digest만 노출한다.
- `BenchmarkTargetFixtureSelectionAuthority`에는 adapter digest가 없고
  `registered-fixture-not-runnable`, `providerExecutionAuthorized=false`,
  `measurementAdmissionEligible=false`가 고정된다.
- P0-D2는 Target adapter, provider receipt, Benchmark Observation, measurement signature, registry
  admission, governed Harness authority를 만들지 않는다.

핵심 구현 위치:

- `src/pajin/benchmark/ai_target_catalog.py`
- `src/pajin/benchmark/target_catalog.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_ai_target_catalog.py`
- `tests/test_benchmark_target_catalog.py`
- `docs/benchmark/P0-D2-ai-rag-mcp-target-fixture-catalog.md`
- `docs/adr/0088-non-runnable-ai-rag-mcp-target-fixture.md`

## 마지막 검증

- WALK·Benchmark·Target·문서 집중 테스트: 127 passed, 1 skipped
  - skip: P0-D1 opt-in real Docker conformance
- Ruff 전체 통과
- Linux 대상 strict mypy: 201 source files 통과
- 전체 `pytest -x -q`: 216 passed, 4 skipped 뒤 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- P0-D2는 의도적으로 provider를 실행하지 않으므로 새 live conformance를 성공했다고 기록하지
  않는다. 직전 P0-D1 Docker provider live conformance는 해당 delivery에서 별도로 통과했다.

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_file_upload.py tests\test_walking_rag_injection.py tests\test_walking_mcp_authorization.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_target_catalog.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_docker_provider.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 결과

- WALK-002 실제 execution state가 `not-authorized`임을 코드와 대조해 설명형 가상 값
  `non-executable`을 matcher에서 제거했다.
- 가상의 `documentInfluenceObserved` 필드를 만들지 않고 실제 validator가 읽는 input marker,
  `vulnerable`, `authorizationEnforced`, `internalDataAccessed`, observation, MCP server/tool,
  `networkLogTrusted`만 matcher에 결박했다.
- fixture selection에 adapter digest가 없고 provider·measurement flag를 true로 바꿀 수 없는지
  음성 테스트로 확인했다.
- source contract 누락·재정렬, profile·Ground Truth·matcher·visibility 치환, mutation 확대,
  Traditional/AI catalog 교차 대입, catalog ID/family 불일치를 fail closed했다.
- P0-D1 serialized field set을 변경하지 않고 기존 P0-D1 테스트가 그대로 통과하는지 확인했다.
- staged diff에서 민감정보, SSL 우회, provider 실행 추가, 기존 wire 필드 변경이 없는지 커밋 직전에
  다시 확인해야 한다.

## 다음 조치

P0-D2 delivery 뒤 `P0-D2B`를 진행한다.

1. `containers/`, `src/pajin/runtime/worker.py`, P0-C2B2B Docker provider를 읽고 File Upload·RAG
   corpus seed·MCP authorization failure·internal data observation을 실제 local Target/Worker로
   증명할 최소 protocol을 설계한다.
2. P0-C2B2B 코드를 arbitrary image runner로 일반화하지 않는다. 공통 lifecycle/fence/evidence
   부분의 안전한 재사용 지점과 AI profile별 exact command/result validator를 분리한다.
3. reset이 corpus와 authorization state를 seed로 복원하고, isolation이 external network와 port를
   닫으며, execution이 실제 HTTP/MCP chain을 통과하고, cleanup이 모든 resource 부재를 증명해야
   runnable catalog promotion을 허용한다.
4. fixture selection digest를 재사용해 실행 권한을 얻지 못하게 하고, 새 runnable registration은
   새 profile/factory digest와 실제 provider evidence를 요구한다.
5. 구현 후 집중 테스트, Ruff, Linux-target strict mypy, 가능한 전체 pytest, live Docker
   conformance, staged 사전 검토, 한국어 Conventional Commit, `origin/main` push와 원격 SHA 검증을
   반복한다.

## 알려진 경계

- P0-D2 profile은 contract-only fixture이며 Benchmark metric 근거가 아니다.
- catalog는 content-addressed지만 distribution signature, durable anti-rollback activation, sealed
  Harness source binding이 없다.
- exact Docker image ID는 trusted local provisioning input이다.
- provider fence는 같은 host·SQLite·Docker 경계이며 cross-host를 보장하지 않는다.
- activation database 전체 삭제·교체를 막는 외부 복구 anchor는 없다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 뒤 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
