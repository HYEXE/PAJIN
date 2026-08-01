# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `72e6a9239b045384235a7ee20173f8bdc6db771d` (`P0-D3B2`)
- 현재 구현 체크포인트: `P0-D4` Holdout Target Factory authority
- 다음 구현: `P0-D5` Mutation Target Factory authority

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

P0-D4는 기존 active Target catalog에 Holdout case를 섞지 않고 별도 non-runnable 권위를 추가한다.

- 기존 Traditional Web/API Manifest·adapter·profile·catalog·seeded Ground Truth를 기존 selector로 다시
  검증한 뒤에만 Holdout binding을 만든다.
- Holdout Factory는 active registration digest에 결박되지만 별도 Factory ID·digest를 사용한다.
- case·Finding·matcher·evaluation seed는 `HoldoutTargetPrivateSuite`와 private binding에만 있고, 공개
  profile·registration·selection에는 content digest만 남는다.
- active Ground Truth는 seeded-only, private suite는 holdout-only다. 양쪽 case·Finding·matcher identity는
  disjoint하며 evaluation seed는 active protocol seed와 겹칠 수 없다.
- catalog scope expansion, alternate-image replay, suite·binding·digest 치환과 authority flag 상승은 fail
  closed한다.
- provider 실행, measurement admission, Holdout content disclosure는 모두 literal false다. 이 단계는 실제
  비밀 저장소나 runnable Holdout evaluator를 주장하지 않는다.

핵심 구현 위치:

- `src/pajin/benchmark/holdout_target_factory.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_holdout_target_factory.py`
- `docs/benchmark/P0-D4-holdout-target-factory-authority.md`
- `docs/adr/0093-separate-holdout-target-authority.md`

## 마지막 검증

- P0-D4 단독 테스트: 14 passed
- Holdout·Target catalog·Hybrid·BENCH-001·문서 집중 회귀: 65 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 205 source files 통과
- 전체 `pytest -x -q`: 258 passed, 6 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_holdout_target_factory.py tests\test_benchmark_target_catalog.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_hybrid_target_composition.py tests\test_benchmark_hybrid_docker_provider.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 커밋 전 검토 초점

- 공개 profile·registration·selection에 private case·matcher·evaluation seed가 없는지 확인한다.
- active selector를 우회하거나 digest-only selection을 신뢰하지 않는지 확인한다.
- seeded/holdout identity와 seed set이 분리되고 catalog 확대·cross-profile replay가 거부되는지 확인한다.
- provider·measurement·content disclosure flag가 false에서 상승할 수 없는지 확인한다.
- 기존 BENCH-001·P0-D1 wire와 runnable provider 동작을 변경하지 않는다.

## 다음 조치

`P0-D5`를 진행한다.

1. 기존 Target registration의 빈 `mutationProfileIds`와 Manifest `mutationProfileId`, reset·isolation
   receipt가 어떤 mutation provenance를 아직 표현하지 못하는지 대조한다.
2. 하나의 exact base Target에 결박된 code-registered Mutation profile·selection authority를 최소 계약으로
   설계한다.
3. unregistered mutation, base profile replay, mutation order·seed·reset provenance 치환과 catalog scope
   expansion을 fail closed한다.
4. 실제 mutation materializer와 provider reset evidence를 구현하기 전에는 execution·measurement
   eligibility를 false로 유지한다.

## 알려진 경계

- P0-D4는 deterministic contract fixture이며 repository source를 비밀 저장소로 주장하지 않는다.
- 실제 Holdout evaluator, access-controlled private storage, signed adjudication projection은 아직 없다.
- provider 실행과 measurement admission은 의도적으로 false다.
- catalog distribution과 anti-rollback activation은 아직 Holdout selection에 결박되지 않는다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 커밋·push하고
다음 개발로 계속 진행하는 것을 승인했다.
