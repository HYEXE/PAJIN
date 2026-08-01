# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `f9e96526d51757a041f9f8a75dd105e24dd2ed22` (`P0-D2B`)
- 현재 구현 체크포인트: `P0-D3` non-runnable Hybrid Target composition authority
- 다음 구현: `P0-D3B` runnable Hybrid multi-provider lifecycle·bridge evidence

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

- `src/pajin/benchmark/hybrid_target_composition.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_hybrid_target_composition.py`
- `docs/benchmark/P0-D3-hybrid-target-composition.md`
- `docs/adr/0090-non-runnable-hybrid-target-composition.md`

## 마지막 검증

- P0-D3 계약 테스트: 11 passed
- Benchmark/Target/문서 회귀 묶음: 92 passed, 2 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 202 source files 통과
- 문서 정책 테스트: 2 passed
- 전체 `pytest -x -q`: 232 passed, 5 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_hybrid_target_composition.py tests\test_benchmark_target_catalog.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_docker_provider.py tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- 두 independent component 성공을 Hybrid chain completion으로 합산하지 않는다.
- 기존 one-Factory Manifest에 composition digest를 넣지 않는다.
- public authority에 private Ground Truth case를 노출하지 않는다.
- builder 검증에만 의존하지 않고 final selection에서 private registration·binding을 재대조한다.
- bridge state와 모든 execution·measurement eligibility는 false/non-executed로 고정한다.
- 기존 P0-D1/P0-D2/P0-D2B wire와 provider 동작을 변경하지 않는다.

## 다음 조치

`P0-D3B`를 진행한다.

1. 기존 recoverable runner가 one adapter/coordinate를 가정하는 지점을 확인하고, composition을 기존
   Manifest digest로 위장하지 않는 별도 Hybrid Factory identity를 설계한다.
2. SQLi Target과 AI Target을 하나의 shared internal bridge 또는 coordinated network에 배치하고 exact
   transfer artifact를 component 1 output에서 component 2 upload input으로 생성한다.
3. 두 component의 reset·isolation·execution·cleanup과 fence를 하나의 ordered operation journal과
   bridge receipt에 결박한다.
4. component 1 성공/2 실패, transfer 치환, partial cleanup, reverse order, cross-coordinate receipt,
   replay와 higher-fence recovery를 fail closed한다.
5. 위 경계가 실제 Docker에서 증명되기 전에는 P0-D3 selection을 runnable로 변경하거나 Hybrid metric을
   만들지 않는다.

## 알려진 경계

- P0-D3는 structural composition일 뿐 runnable provider가 아니다.
- bridge data-flow는 선언만 됐으며 실제 transfer artifact나 receipt가 없다.
- 두 component는 각자 host-local provider이고 cross-provider fence·cleanup authority가 없다.
- catalog distribution, anti-rollback activation과 Hybrid Harness source binding은 없다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
