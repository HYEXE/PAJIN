# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 직전 원격 체크포인트: `fc6c2f60e1b0ab65db2ca75375dc8d9e2caa74f2` (`SUP-005B1`)
- 현재 구현 체크포인트: `SUP-005B2` registry-governed model-backed Comparison
- 다음 구현: `SUP-006` Adversarial Prompt Injection Regression

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

`SUP-005B2`는 SUP-005B1이 호출 전에 결박한 model-backed candidate를 실제 registry-governed
Target/Harness Observation과 연결하고, 완전한 두 arm 집합에만 기존 BENCH-003B1 numeric Comparison을
허용한다.

- candidate Target adapter는 signed execution 구간 안에서 exact
  `invoke_supervisor_benchmark_candidate()`를 호출한다.
- `SupervisorBenchmarkCandidateExecutionEvidence`는 Plan·coordinate·typed context·stable request,
  terminal journal, Provider Run/root·receipt·outcome, SUP-003 proposal과 원시 Target evidence digest를
  domain-separated relation으로 결박한다.
- relation digest는 existing execution receipt의 `providerEvidenceDigest`가 된다. 기존 P0-C external
  measurement attestation이 execution receipt·coordinate·lifecycle·Observation을 서명하므로 B3 관계도
  전이적으로 서명된다.
- public reader는 Plan/B3/Harness/Target/registry admission/durable activation/attestation/Observation을
  모두 재검증한다. timestamp나 coordinate만 맞춘 post-hoc sidecar는 admission할 수 없다.
- BENCH-003B1 Observation binding의 Target Run/root/path/SHA-256/전체 Observation은 같은 Harness source와
  exact equality여야 한다. generic recorder나 다른 유효 Comparison 치환도 admission하지 않는다.
- baseline은 model call 0회, candidate는 externally attested Observation과 B3 charged usage 모두 1회를
  요구한다. signed Target execution window가 journal dispatch·terminal을 포함해야 한다.
- 모든 좌표가 동일한 registry activation/revision을 사용하고 Harness·Target·Observation·stable request·
  intent·Provider Run·receipt·proposal가 fresh/unique일 때만 기존
  `WalkingBenchmarkMeasuredComparisonRunner`를 호출한다.
- 최종 `SupervisorBenchmarkMeasuredComparisonAuthority`는 Plan, coordinate source, relation과 기존
  Comparison Run의 digest-only lineage만 저장한다. Observation 값, metric, delta, draft, rationale는 복제하지
  않는다.
- numeric comparison은 유효하지만 proposal causal effect, threshold, execution, activation은 false다.

핵심 위치:

- `src/pajin/supervision/benchmark_measurement.py`
- `src/pajin/supervision/benchmark_campaign.py`
- `tests/test_supervisor_benchmark_measurement.py`
- `docs/orchestration/SUP-005B2-registry-governed-model-backed-comparison.md`
- `docs/adr/0126-bind-b3-completions-into-externally-attested-target-execution.md`

## 현재 검증

- SUP-005B2 end-to-end fake-provider 집중 테스트: 6 passed
- SUP-005B2와 인접 benchmark/supervision 회귀: 46 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 246 source files 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 고정 registry distribution bundle 만료로 중단
  (`test_benchmark_single_agent_measurement.py`; SUP-005B2 집중·인접 검증과 무관한 기존 fixture 제한)
- 변경 Python formatter check와 `git diff --check`: 통과
- 독립 품질 리뷰: 잔존 P0-P2 없음; 단일 seed/repetition fixture만 비차단 P3
- 독립 신뢰 리뷰: foreign generic Comparison metric 세탁 P1을 발견해 exact Observation binding으로 수정,
  공격 재검증 1 passed 뒤 잔존 P0-P2 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_benchmark_measurement.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_benchmark_measurement.py tests\test_supervisor_benchmark_campaign.py tests\test_supervisor_invocation_journal.py tests\test_benchmark_measurement_registry.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_target_factory.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 수정 파일만 검사하고 저장소
전체를 기계적으로 재포맷하지 않는다.

## 핵심 신뢰 경계

- generic `WalkingBenchmarkRunObservationRecorder` 결과는 SUP-005B2 입력이 아니다.
- 다른 유효 BENCH-003B1 Comparison도 그 Observation binding이 exact Harness source와 다르면 거부한다.
- proposal·draft·rationale에서 Finding·Chain·Replay·Policy·Human·time·call·cost를 생성하지 않는다.
- Target execution receipt가 exact typed relation digest를 외부 서명하지 않으면 candidate Observation을
  admission하지 않는다.
- B3 conservative charged cost와 externally adjudicated coordinate-total cost를 같다고 보거나 합산하지 않는다.
- B3 성공 뒤 Target/Harness 봉인 전에 중단되면 이전 receipt를 새 Target Run에 자동 재사용하지 않는다.
- complete coordinate set과 모든 source freshness를 확인하기 전에는 numeric Comparison을 생성하지 않는다.
- Comparison이 생성돼도 proposal 적용이나 Supervisor activation 권위가 아니다.

## 다음 작업의 첫 단계

`SUP-006`은 새 실행·활성화 권위를 만들지 않고 model-visible Snapshot의 adversarial prompt injection이
Supervisor proposal과 Benchmark 경계에 미치는 회귀를 검증한다.

1. SUP-002 Target Taint, SUP-003 content-free typed compiler, SUP-004B3 B3 consumer, SUP-005B1 context와
   SUP-005B2 external measurement relation에서 이미 차단하는 prompt-shaped 입력을 인벤토리한다.
2. developer/system 역할 상승, taint downgrade, Scope 확대, Tool/Capability/Permit 요청, proposal schema
   escape, cross-Snapshot/Plan replay를 최소 adversarial corpus로 고정한다.
3. 기존 Shadow proposal은 계속 non-executable이며 metric은 external Target evidence에서만 오도록 회귀
   테스트한다.
4. adversarial regression 결과를 threshold나 activation으로 자동 승격하지 않는다.

## 알려진 경계

- SUP-005B2는 외부 measurement signer와 host-local registry activation을 신뢰한다.
- B3 journal은 host-local SQLite, budget ledger는 process-local이며 distributed exactly-once가 아니다.
- proposal은 Target 실행에 적용되지 않은 Shadow sidecar라 numeric delta의 causal improvement를 주장하지
  않는다.
- 현재 실행 fixture는 seed 1개·repetition 1개이며 private test helper 결합이 남아 있다.
- Docker daemon은 세션별 재확인이 필요하며, fake-provider 검증은 real-container 검증을 대신하지 않는다.
- 전체 pytest에는 기존 Benchmark registry fixture 만료와 Windows symlink 권한 제약이 남아 있다.
