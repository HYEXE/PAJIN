# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `90df69fcc14af1784843736eaa37d012c713a785` (`P0-D3B1`)
- 현재 구현 체크포인트: `P0-D3B2` runnable local Hybrid Docker provider
- 다음 구현: `P0-D4` Holdout Target Factory authority

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

P0-D3B2는 P0-D3B1 topology를 새 Hybrid Factory·profile·catalog·Ground Truth matcher와 세 Docker
image에 결박하고 recoverable runner로 실제 실행한다.

- Hybrid Traditional Target의 Boolean-SQLi expanded response가 실제 `documentContent`를 제공한다.
- Worker는 complete source body를 seal하고 canonical transfer artifact를 만든 뒤 그 exact content만 AI
  Target에 upload한다. upload·RAG·MCP response 전체도 Base64·SHA-256으로 기록하고 host가 재검증한다.
- transfer artifact는 schema·source Observation·source response·document identity를 묶고 bridge receipt는
  topology·coordinate·operation·fence·ordered steps와 source/upload/query digest를 결박한다.
- 세 container는 하나의 unpublished internal bridge와 단일 coordinate·fence를 사용한다. startup은
  Traditional→AI→Worker이고 cleanup은 Worker→AI→Traditional→network 역순이다.
- 두 seeded Finding, 네 Surface, 한 Hybrid chain의 code-owned matcher를 Manifest Ground Truth에 묶는다.
  P0-D3B1 private predecessor digest만으로는 measurement를 만들 수 없다.
- partial AI startup은 성공으로 기록되지 않으며 higher-fence recovery cleanup만 남은 리소스를 제거한다.
- 기존 P0-D3 selection은 계속 non-runnable이다. 실행은 새 Hybrid local-Docker catalog selection과
  recoverable runner에서만 허용된다.

핵심 구현 위치:

- `src/pajin/benchmark/hybrid_docker_provider.py`
- `src/pajin/benchmark/hybrid_provider_contract.py`
- `src/pajin/benchmark/hybrid_target_composition.py`
- `src/pajin/benchmark/docker_provider.py`
- `src/pajin/benchmark/target_catalog.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_hybrid_docker_provider.py`
- `tests/test_benchmark_hybrid_target_composition.py`
- `containers/hybrid-traditional-target/`
- `containers/hybrid-ai-rag-mcp-target/`
- `containers/hybrid-benchmark-worker/`
- `docs/benchmark/P0-D3B2-local-hybrid-docker-provider.md`
- `docs/adr/0092-runnable-local-hybrid-docker-provider.md`

## 마지막 검증

- P0-D3B2 fake-provider·계약 집중 테스트: 57 passed, 3 skipped
- P0-D3B2 real-Docker conformance: 1 passed
- Benchmark/Target/문서 회귀 묶음: 104 passed, 3 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 204 source files 통과
- 전체 `pytest -x -q`: 244 passed, 6 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_hybrid_docker_provider.py tests\test_benchmark_hybrid_target_composition.py tests\test_benchmark_target_catalog.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_docker_provider.py tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- success flag만 맞고 decoded response body가 다른 결과를 거부한다.
- transfer content가 sealed SQLi response에서 파생되지 않으면 거부한다.
- bridge receipt가 topology·schema·coordinate·operation·fence와 exact equality인지 확인한다.
- partial start와 cleanup 역순·higher fence recovery를 확인한다.
- P0-D3 non-runnable selection과 기존 single-target evidence wire를 변경하지 않는다.

## 다음 조치

`P0-D4`를 진행한다.

1. 기존 Benchmark Ground Truth visibility와 catalog 공개 범위를 읽고 Holdout case가 active profile
   selection·로그·public artifact에 노출될 수 있는 지점을 찾는다.
2. active Target과 identity가 분리된 Holdout registration·private binding·selection authority의 최소 계약을
   설계한다.
3. Holdout contents·matcher·seed 누출, active/holdout replay, catalog scope expansion을 fail closed한다.
4. 실제 Holdout provider를 만들기 전에는 execution·measurement eligibility를 false로 유지한다.

## 알려진 경계

- P0-D3B2는 host-local deterministic no-model lab이다.
- MCP endpoint는 AI Target 내부 protocol boundary이며 별도 service 격리를 증명하지 않는다.
- provider fence는 host-local SQLite이며 cross-host control-plane CAS가 아니다.
- catalog distribution, anti-rollback activation과 production model behavior는 아직 증명하지 않는다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
