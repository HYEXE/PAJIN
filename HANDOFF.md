# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 기준 체크포인트: `188b90346adda9465bcb719f1c3bc504e66acd6c` (`SUP-004B3`)
- 현재 구현 체크포인트: `SUP-005A` B3·BENCH-003B2 source-bound non-attribution lineage
- 다음 구현: `SUP-005B` 호출 전 Benchmark 좌표·B3-backed observation 결박

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같은지 확인한다.

## 현재 구현 상태

`SUP-005A`는 실제 terminal `SUP-004B3` invocation과 기존 `BENCH-003B2` policy benchmark를
하나의 content-addressed lineage authority에 결박하되, 기존 numeric comparison을 model proposal의
효과로 귀속하지 않는다.

- `SupervisorDeterministicBaselineLineageRunner`는 `consume_supervisor_invocation()`으로 journal,
  schedule, two-seal receipt, Snapshot, model·Provider binding과 content-free SUP-003 proposal을 다시
  검증한다.
- 기존 BENCH-003B2 reader를 통해 sealed policy comparison을 다시 열고 exact WALK-006 policy,
  Run/root/artifact, embedded BENCH-003A/B1, Result와 Comparison lineage를 결박한다.
- SUP-001/Profile Campaign digest와 WALK-006 Campaign digest는 서로 다른 domain이므로 같다고 주장하지
  않는다. 하나의 exact `CampaignManifest`를 양쪽 reader에 전달하고 detached manifest digest와 두
  domain-specific digest를 별도로 보존한다.
- 열두 canonical metric 이름만 보존하고 값·delta를 복제하거나 다시 계산하지 않는다. 현재 B2 fixture의
  candidate model call은 0이며 B3에는 Manifest·arm·seed·repetition 좌표가 없으므로 상태는
  `structural-source-bound-not-model-measured`다.
- model attribution, pre-invocation coordinate binding, model-backed eligibility, threshold, baseline
  mutation, Task·Plan·Scope·Capability·Permit·execution·activation은 모두 false다.
- BENCH-003B2와 SUP-005A reader는 exact 1 seal, 3 artifact, 3 ordered event와 전체 payload,
  strict unambiguous `run.json`을 재구성한다. foreign artifact/event/payload/state와 duplicate JSON key를
  포함해 유효하게 재봉인한 envelope도 fail closed한다.
- 새 API는 additive direct-module API이며 기존 public import, Benchmark Result/Comparison, Supervisor,
  Walking, Provider와 RunStore wire를 변경하지 않는다.

핵심 위치:

- `src/pajin/supervision/baseline_comparison.py`
- `src/pajin/benchmark/shadow_measurement.py`
- `tests/test_supervisor_deterministic_baseline_comparison.py`
- `docs/orchestration/SUP-005A-source-bound-deterministic-baseline-lineage.md`
- `docs/benchmark/BENCH-003B2-walking-shadow-policy-binding.md`
- `docs/adr/0124-bind-supervisor-proposals-to-benchmark-lineage-without-attribution.md`

## 현재 검증

- SUP-005A 집중 회귀: 6 passed
- BENCH-003B1/B2·SUP-003·SUP-004A/B3·공통 benchmark 인접 회귀: 76 passed
- 전체 Ruff 통과
- Linux 대상 strict mypy: 244 source files 통과
- 전체 `pytest -x -q`: 기존 Benchmark registry fixture 만료로 190 passed, 3 skipped 뒤 중단
- `git diff --check` 통과
- 독립 품질 검토: P0-P2 없음, 테스트 private-helper 결합 P3는 `KNOWN_ISSUES.md`에 기록
- 독립 신뢰경계 검토: resealed envelope P2 두 건과 duplicate-key P2를 수정한 뒤 잔존 P0-P3 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_deterministic_baseline_comparison.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_deterministic_baseline_comparison.py tests\test_walking_benchmark_measurement.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_checkpoint_scheduler.py tests\test_benchmark_contract.py tests\test_walking_mcp_authorization.py::test_walking_shadow_measured_benchmark_binds_exact_policy_and_sources tests\test_walking_mcp_authorization.py::test_walking_shadow_measured_benchmark_rejects_foreign_policy_and_mutation
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 독립 검토에서 수정한 문제

- BENCH-003B2 source reader가 integrity-valid foreign artifact, 권위 event, 위조된 campaign payload와
  `run.json`을 받아들일 수 있어 exact sealed envelope 검증을 추가했다.
- SUP-005A output reader가 시작·완료 event payload와 `run.json` 전체를 검증하지 않아 같은 exact
  envelope 검증을 추가했다.
- 두 reader의 일반 `json.loads()`가 duplicate key를 last-value-wins로 해석해 foreign state를 예상값으로
  덮을 수 있어 기존 `parse_strict_json_bytes()`로 교체하고 양쪽 유효 재봉인 공격 회귀를 추가했다.
- 신규 테스트가 두 대형 선행 테스트의 비공개 fixture helper에 결합된 유지보수 P3는 현재 제품 동작과
  무관하므로 이번 Trust Boundary에서 대규모 fixture 재배치를 하지 않고 해소 조건을 기록했다.

## 다음 작업의 첫 단계

`SUP-005B`를 구현하기 전에 기존 `BenchmarkTargetCoordinate`, `BenchmarkManifest`,
`WalkingBenchmarkRunObservation`, P0-C registry-governed Harness와 SUP-004A/B3의 request 생성 순서를
다시 대조한다. post-hoc receipt-to-coordinate mapping을 금지하고 다음 최소 권위를 설계한다.

1. actual model binding·Provider·configuration·SUP-003 compiler·SUP-004 request/budget을 하나의
   versioned candidate implementation digest에 결박한다.
2. 기존 `BenchmarkTargetCoordinate`를 stable request와 dispatch 전에 고정한다.
3. 모든 candidate seed/repetition 좌표가 exact B3 journal·receipt·proposal에 대응하도록 한다.
4. Finding·Chain·Replay·Policy·Human 의미는 proposal에서 추론하지 않고 기존 외부 measurement/
   adjudication authority가 봉인한 B1-compatible Observation만 받는다.
5. complete two-arm coordinate set만 기존 Result·Comparison 계산에 전달하며 threshold와 activation은
   계속 false로 유지한다.

## 알려진 경계

- SUP-005A는 shared policy lineage만 증명하며 B3 model proposal의 benchmark 효과를 측정하지 않는다.
- B3 schedule/receipt에는 아직 Benchmark Manifest, arm, seed, repetition과 Target Coordinate가 없다.
- B2 fixture의 candidate model call은 0이며 운영 measurement attestation이 아니다.
- exact retry는 같은 authority identity를 만들지만 별도 sealed publication Run을 만들 수 있다.
- B3 journal은 host-local SQLite, budget ledger는 process-local이고 distributed exactly-once를 보장하지
  않는다.
- 전체 pytest는 기존 Benchmark registry fixture 만료 뒤 Windows symlink 권한 제약도 남아 있다.
