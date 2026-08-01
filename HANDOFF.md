# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `dedab38b669cf5cefd1139d3b94383989469dacf` (`P0-D4`)
- 현재 구현 체크포인트: `P0-D5` Mutation Target Factory authority
- 다음 구현: `P0-E1` Deterministic PAJIN baseline measurement authority

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

P0-D5는 기존 unmutated P0-D1 catalog 위에 별도 non-runnable Mutation authority를 추가한다.

- base Manifest·adapter·Docker profile·catalog·private Ground Truth를 기존 P0-D1 selector로 다시 검증한다.
- 기존 base registration의 `mutationProfileIds=()`는 바꾸지 않는다. 별도 Mutation registration이 exact
  base registration digest와 code-owned Mutation profile을 묶는다.
- derived Manifest는 base Manifest에서 `mutationProfileId`만 달라야 하며 helper 자체도 base registration의
  profile·Factory·Ground Truth identity를 재검증한다.
- 공개 deterministic mutation seed, base/expected state digest와 restore→apply→verify 세 operation의 exact
  order·state chain을 profile에 결박한다.
- reset plan은 두 Manifest, base registration, profile, benchmark seed, mutation seed, state와 operation
  digest를 묶지만 `declared-not-applied`, `resetReceiptBound=false`다.
- materialization·provider execution·measurement admission은 모두 literal false다.

핵심 구현 위치:

- `src/pajin/benchmark/mutation_target_factory.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_mutation_target_factory.py`
- `docs/benchmark/P0-D5-mutation-target-factory-authority.md`
- `docs/adr/0094-non-runnable-mutation-target-authority.md`

## 마지막 검증

- P0-D5 단독 테스트: 19 passed
- Mutation·Holdout·Target catalog·Hybrid·BENCH-001·문서 집중 회귀: 84 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 206 source files 통과
- 전체 `pytest -x -q`: 277 passed, 6 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_mutation_target_factory.py tests\test_benchmark_holdout_target_factory.py tests\test_benchmark_target_catalog.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_hybrid_target_composition.py tests\test_benchmark_hybrid_docker_provider.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- base selector를 우회하거나 alternate profile/catalog를 mutation base로 사용할 수 없는지 확인한다.
- derived Manifest가 mutation ID 외의 Campaign·Ground Truth·protocol·Factory 범위를 바꾸지 않는지 확인한다.
- operation order·state chain·mutation seed·reset provenance 치환을 거부하는지 확인한다.
- reset receipt·materialization·execution·measurement flag가 false에서 상승할 수 없는지 확인한다.
- 기존 P0-D1 catalog의 빈 mutation allowlist와 runnable provider 동작을 변경하지 않는다.

## 다음 조치

`P0-E1`을 진행한다.

1. BENCH-003B1/B2, P0-C2B2A2 registry-governed Harness와 P0-D1 runnable catalog wrapper가 실제로
   연결되지 않은 지점을 먼저 대조한다.
2. 하나의 exact deterministic PAJIN implementation·Manifest·catalog selection·registry activation·Target
   Run을 baseline Result에 결박하는 최소 authority를 설계한다.
3. synthetic fixture를 운영 측정으로 오인하거나 caller-supplied aggregate를 채택하지 않고, sealed raw
   Observation에서만 12 metric을 재구성한다.
4. catalog·registry·Manifest·arm·seed/repetition replay와 partial Result publication을 fail closed한다.

## 알려진 경계

- P0-D5는 mutation contract fixture이며 실제 materializer나 reset evidence를 제공하지 않는다.
- 기존 P0-D1 runnable catalog allowlist는 계속 비어 있어 mutation Manifest를 실행할 수 없다.
- reset plan은 provider receipt가 아니며 measurement admission 근거로 사용할 수 없다.
- runnable mutation은 별도 profile·provider evidence·recovery·registry-governed Harness binding이 필요하다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
