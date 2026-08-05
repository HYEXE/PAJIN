# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 기준 체크포인트: `77bdeff8bd872d9008f466e9a4350500f8c9065b` (`SUP-005A`)
- 현재 구현 체크포인트: `SUP-005B1` complete coordinate Plan·typed B3 request context
- 다음 구현: `SUP-005B2` registry-governed Observation·canonical numeric Comparison

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

`SUP-005B1`은 기존 수치를 실제 모델 효과로 재라벨하지 않고, model-backed candidate를 호출 전에
정확한 Benchmark 좌표와 결박하는 request-lineage 경계를 구현한다.

- exact BENCH-003B2 reader에서 baseline-only 구조만 가져와 model call ceiling 1인 새 two-arm
  `BenchmarkManifest`를 도출한다. 기존 Result와 Comparison은 재사용하지 않는다.
- `SupervisorBenchmarkCandidateImplementation`은 SUP-001 model binding, Provider/model/configuration,
  registered SUP-003 compiler, SUP-004 dedicated budget과 request/response schema를 static configuration
  digest로 결박한다. Snapshot·schedule·coordinate·receipt는 per-coordinate 계보다.
- `SupervisorBenchmarkCampaignPlan`은 전체 Campaign, BENCH-003B2 source Run/root/artifact, 새 Manifest,
  모든 arm·seed·repetition 좌표와 각 candidate 좌표의 exact sealed SUP-004A schedule을 결박한다.
- Plan은 `sealed-complete-set-not-dispatch-authority`이며 `preDispatchBindingProven=false`다. Plan 단독으로
  dispatch 부재나 실행 권위를 주장하지 않는다.
- `SupervisorBenchmarkRequestContext`는 exact Plan publication, Manifest/set, coordinate와 schedule을
  명시적으로 담는다. generic B3에서는 caller assertion일 뿐이며 candidate authority가 아니다.
- context-bound B3는 intent·receipt `v1alpha2`에 같은 typed context를 저장하고 그 digest를 stable request
  ID v2에 포함한다. ID는 실제 Gateway `ToolRequest`, reservation, Provider outcome과 evidence에 도달한다.
- context 없는 기존 B3는 intent·receipt `v1alpha1`, requestContext field omission, stable request v1을 그대로
  유지한다. SQLite schema migration은 없다.
- candidate wrapper와 public verifier는 exact `SupervisorCheckpointInvoker`, sealed Plan/source, current
  schedules, terminal journal, two-seal receipt, Provider outcome과 기존 SUP-003 proposal consumer를 모두
  재검증하고 Plan seal이 dispatch보다 앞선 경우에만 candidate invocation을 인정한다.
- numeric comparison, proposal causal effect, threshold, execution과 activation은 모두 false다.

핵심 위치:

- `src/pajin/supervision/benchmark_campaign.py`
- `src/pajin/supervision/invocation_journal.py`
- `src/pajin/supervision/invocation_runtime.py`
- `tests/test_supervisor_benchmark_campaign.py`
- `tests/test_supervisor_invocation_journal.py`
- `docs/orchestration/SUP-005B1-sealed-benchmark-campaign-request-context.md`
- `docs/adr/0125-bind-benchmark-coordinates-into-supervisor-provider-requests.md`

## 현재 검증

- SUP-005B1·journal 집중 회귀: 15 passed
- Supervisor·Benchmark 좌표/측정 인접 회귀: 73 passed
- 전체 Ruff: 통과
- 변경 파일 Ruff format check: 통과
- Linux 대상 strict mypy: 245 source files 통과
- 전체 `pytest -x -q`: 기존 Benchmark registry fixture 만료로 190 passed, 3 skipped 뒤 중단
- `git diff --check`: 통과
- 독립 품질 재검토: 초기 P1/P2 수정 뒤 잔존 P0-P2 없음
- 독립 신뢰경계 재검토: foreign invoker·Campaign/WALK cross-domain P1/P2 수정 뒤 잔존 P0-P2 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_invocation_journal.py tests\test_supervisor_benchmark_campaign.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_benchmark_campaign.py tests\test_supervisor_deterministic_baseline_comparison.py tests\test_supervisor_invocation_journal.py tests\test_supervisor_checkpoint_scheduler.py tests\test_benchmark_contract.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_target_factory.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 formatter check는 이번 변경과 무관한 기존 156개 파일이 현재 Ruff formatter와 불일치한다. 이번에
수정한 Python 파일은 모두 formatter를 통과한다. 저장소 전체를 기계적으로 재포맷하지 않는다.

## 독립 검토에서 수정한 문제

- raw caller digest가 stable request ID에 영향을 주지만 intent/receipt에 의미가 보존되지 않던 P1을 제거했다.
  complete typed context와 명시적 `v1alpha2` wire를 도입하고 legacy `v1alpha1` field omission을 보존했다.
- duck-typed fake invoker가 Worker·journal·seal 없이 candidate completion을 위조할 수 있던 P1을 exact type과
  기존 B3 consumer 재실행으로 차단했다.
- Plan이 dispatch 이전에 만들어졌다고 과장하던 P2를 수정해 timing authority를 false로 낮추고, 실제
  candidate verifier에서만 Plan seal과 dispatch 시각을 비교한다.
- detached Campaign만 바꾸거나 WALK baseline domain만 foreign digest로 일관되게 재계산한 Plan을 모델이
  받아들이던 P2를 full Campaign, SUP-001 source Campaign과 public WALK digest 재계산 equality로 차단했다.
- 테스트 private-helper 결합과 단일 seed/repetition fixture는 비차단 P3로 `KNOWN_ISSUES.md`에 유지한다.

## 다음 작업의 첫 단계

`SUP-005B2`는 새 aggregate·Result·Comparison store를 만들지 않고 기존 P0-C Harness와 BENCH-003B1을
재사용한다.

1. `SupervisorBenchmarkCandidateInvocation`을 exact reader로 다시 열어 Plan context, B3 receipt/proposal과
   candidate coordinate를 고정한다.
2. registry-governed `BenchmarkTargetFactoryRunner`의 reset·isolation·execution·cleanup receipt와 external
   measurement attestation이 같은 coordinate와 실행 창을 증명하게 한다.
3. Finding·Chain·Replay·Policy·Human 값은 content-free proposal이나 rationale에서 추론하지 않는다.
   외부 adjudicator가 Ground Truth와 실제 Target evidence를 평가한 Observation만 받는다.
4. candidate는 이 slice의 제한된 계약에서 coordinate당 exact B3 model call 1회를 요구하고 charged usage와
   coordinate-total call/cost 의미를 분리한다.
5. baseline과 candidate의 모든 seed/repetition Observation이 complete set일 때만 기존
   `WalkingBenchmarkMeasuredComparisonRunner`를 호출한다. caller aggregate injection, partial set,
   cross-coordinate receipt와 duplicate stable request를 fail closed한다.
6. proposal이 Target 동작에 적용되지 않은 Shadow sidecar라는 사실을 유지해 causal effect attribution,
   threshold와 activation을 계속 false로 둔다.

## 알려진 경계

- B1은 request lineage만 증명하며 model-visible Snapshot과 Target measurement 사이의 의미 연결은 아직 없다.
- generic typed context는 caller assertion이며 benchmark verifier를 통과하기 전에는 candidate authority가 아니다.
- 기존 BENCH-003B2 fixture의 candidate model call은 0이고 새 model-backed Manifest Result로 재사용할 수 없다.
- B3 journal은 host-local SQLite, budget ledger는 process-local이며 distributed exactly-once가 아니다.
- Plan exact retry는 같은 content identity라도 별도 sealed publication Run을 만들 수 있다.
- 전체 pytest는 기존 Benchmark registry fixture 만료 뒤 Windows symlink 권한 제약도 남아 있다.
