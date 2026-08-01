# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `8a906a2ac5e44fc1d633f27f64034eac7d9e9c01` (`P0-D3`)
- 현재 구현 체크포인트: `P0-D3B1` Hybrid provider topology·transfer authority
- 다음 구현: `P0-D3B2` runnable multi-container adapter·bridge receipt·recovery evidence

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

P0-D3B1은 P0-D3 selection을 실행했다고 주장하지 않고, runnable Hybrid provider가 충족해야 할
새 Factory·adapter identity와 다중 컨테이너 경계를 content-addressed authority로 결박한다.

- 두 Target과 한 Worker는 하나의 unpublished internal bridge, 단일 coordinate·fence를 사용한다.
- startup은 Traditional→AI→Worker, cleanup은 정확한 역순이며 bridge 단계도 probe→source seal→extract
  →transfer seal→upload→AI probe로 고정된다.
- transfer artifact는 sealed Traditional 응답의 `/records/0/documentContent`에서 본문을 추출하고 source
  Observation·response digest, document ID·content를 canonical JSON으로 기록해야 한다.
- 현재 SQLi 응답에는 이 필드가 없으므로 Hybrid 전용 seeded source semantics가 다음 구현에 필요하다.
- image binding·adapter registration·Manifest·execution·measurement eligibility·bridge observation은 모두
  false/non-executed 상태다.
- P0-D3 private binding을 다시 열어 selection 전체를 재구성하므로 cross-composition binding과 component
  치환이 차단된다.

P0-D3의 exact two-component composition과 non-runnable 경계는 그대로 유지된다.

P0-D3는 P0-D1 Traditional Web/API와 P0-D2B local AI/RAG/MCP의 exact
`BenchmarkTargetProfileSelectionAuthority`를 ordinal 1·2 component로 결박한다.

- component는 code-owned catalog, family, profile, Factory/version, provider API, internal-network
  policy, empty mutation set, provider/profile digest equality를 요구한다.
- catalog, Factory, adapter, Manifest와 private Ground Truth binding identity는 두 component 사이에서
  모두 달라야 한다. reversal·repetition·partial composition이 차단된다.
- bridge는 Boolean-SQLi Finding/Surface에서 AI upload/RAG/MCP Finding/Surface로 향하는
  `synthetic-record-to-untrusted-document` 관계이며 `declared-not-executed`로 고정된다.
- public composition과 selection에는 private cases가 없다. 별도
  `HybridTargetGroundTruthBinding`이 두 complete seeded case와 matcher를 결박한다.
- final selection이 private registration과 binding digest를 component selection에 다시 대조하므로
  self-consistent한 private profile 치환도 차단된다.
- Hybrid Target Factory, `BenchmarkManifest`, provider receipt, Observation, metric, Harness authority는
  생성하지 않는다. Factory registration, Manifest eligibility, provider execution, measurement
  admission은 모두 false다.

핵심 구현 위치:

- `src/pajin/benchmark/hybrid_provider_contract.py`
- `src/pajin/benchmark/hybrid_target_composition.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_hybrid_target_composition.py`
- `docs/benchmark/P0-D3B1-hybrid-provider-topology-contract.md`
- `docs/adr/0091-hybrid-provider-topology-before-runtime.md`
- `docs/benchmark/P0-D3-hybrid-target-composition.md`
- `docs/adr/0090-non-runnable-hybrid-target-composition.md`

## 마지막 검증

- P0-D3/P0-D3B1 계약 테스트: 17 passed
- 문서 정책 테스트 포함 계약 묶음: 19 passed
- Benchmark/Target/문서 회귀 묶음: 98 passed, 2 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 203 source files 통과
- 전체 `pytest -x -q`: 238 passed, 5 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_hybrid_target_composition.py tests\test_benchmark_target_catalog.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_docker_provider.py tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- topology authority를 실행 capability나 provider receipt로 사용하지 않는다.
- 기존 component image가 실제 transfer를 수행한다고 허위 주장하지 않는다.
- transfer body는 반드시 sealed source response에서 파생되며 code-owned prompt로 대체하지 않는다.
- public authority에 private Ground Truth case를 노출하지 않는다.
- 기존 single-target Manifest·Docker evidence wire를 변경하지 않는다.

## 다음 조치

`P0-D3B2`를 진행한다.

1. Hybrid 전용 Traditional·AI Target과 Worker image를 구현하고 exact image ID profile을 만든다.
2. `HybridProviderTopologyAuthority`의 startup·bridge·cleanup order를 하나의 adapter와 operation journal에
   구현한다.
3. source response, transfer artifact, destination upload와 final AI result를 별도 digest·receipt로 결박한다.
4. component 1 성공/2 실패, transfer 치환, partial cleanup, reverse order, cross-coordinate receipt,
   replay와 higher-fence recovery를 fail closed한다.
5. fake-provider와 real-Docker 검증이 모두 통과하기 전에는 runnable selection이나 Hybrid metric을 만들지
   않는다.

## 알려진 경계

- P0-D3B1도 topology/schema authority일 뿐 runnable provider가 아니다.
- bridge data-flow는 schema만 등록됐으며 실제 transfer artifact나 receipt가 없다.
- 두 component는 각자 host-local provider이고 cross-provider fence·cleanup authority가 없다.
- catalog distribution, anti-rollback activation과 Hybrid Harness source binding은 없다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
