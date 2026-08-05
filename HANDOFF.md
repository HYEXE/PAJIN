# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 이전 체크포인트: `801770909b16848a401cf810835569f1faa9e40b` (`SUP-004B2`)
- 현재 구현 체크포인트: `SUP-004B3` durable Supervisor invocation journal·sealed draft receipt
- 다음 구현: `SUP-005` Deterministic Baseline 비교

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

`SUP-004B3`는 exact `SUP-004A` checkpoint에 대해 Provider 호출 의도를 dispatch 전에 영속
결박하고, 불확실한 호출을 자동 재시도하지 않으며, 완전한 두 단계 seal을 재검증한 뒤에만
untrusted draft를 기존 `SUP-003` 제안 컴파일러에 전달한다.

- `SupervisorInvocationJournal`은 deterministic stable request ID와 preplanned Provider Run을
  canonical SQLite journal에 claim한다. 상태는 `intent-recorded`,
  `dispatch-started-outcome-unknown`, `terminal-success`이며 불변 trigger와 append-only hash
  chain으로 전이를 보호한다.
- `SupervisorCheckpointInvoker`는 current schedule과 request를 다시 검증하고 journal에 started를
  기록한 뒤에만 Run과 Provider 호출을 만든다. started인데 완전한 receipt가 없으면 자동
  redispatch하지 않고 수동 검토 상태를 유지한다.
- 첫 seal은 request reservation, Gateway evidence와 실행 event prefix를 결박하고, 두 번째 seal은
  full `SUP-004B2` outcome, strict untrusted draft와 receipt event를 결박한다.
- consumer는 exact journal row, 양쪽 seal과 artifact, 전체 10개 event sequence, Gateway·Worker·Provider
  source, dual budget scope를 코드 소유 expected value로 재구성한다. 검증된 draft만 `SUP-003`에
  직접 전달하며 Task·Plan·Scope·Capability·Permit·execution·activation은 계속 false다.
- Worker execution ID, reconstructed `WorkerJob`, `WorkerResult`, ToolResult-from-stdout, Secret Lease
  issue·revoke와 concrete runtime authority class까지 exact 검증한다.
- `WeeklyTestingWindow.days`와 Rules of Engagement의 set-backed JSON 필드는 정렬해 Python hash seed와
  무관한 nested authority digest를 유지한다.
- 기존 public import와 Provider wire는 깨지 않았으며 새 B3 API는
  `pajin.supervision.invocation_journal`과 `pajin.supervision.invocation_runtime`의 직접 module API다.

핵심 위치:

- `src/pajin/supervision/invocation_journal.py`
- `src/pajin/supervision/invocation_runtime.py`
- `src/pajin/runtime/control.py`
- `src/pajin/domain/models.py`
- `tests/test_supervisor_invocation_journal.py`
- `tests/test_supervisor_checkpoint_scheduler.py`
- `tests/test_manifest.py`
- `docs/orchestration/SUP-004B3-durable-supervisor-invocation-receipt.md`
- `docs/adr/0123-durably-claim-and-seal-supervisor-invocations.md`

## 현재 검증

- 고정 hash seed journal·manifest·Supervisor scheduler: 68 passed
- Capability authorities·기존 capability rollout·scheduler·Provider·Provider agents 동일 process 회귀: 110 passed
- B3 journal·scheduler와 proposal/snapshot/model/provider/Gateway/Worker 통합 회귀: 294 passed
- 전체 Ruff 통과
- Linux 대상 strict mypy: 243 source files 통과
- 전체 `pytest -x -q`: 기존 Benchmark registry fixture 만료로 190 passed, 3 skipped 뒤 중단
- `git diff --check` 통과
- 독립 공격 검토 최종 결과: 잔존 P0-P3 finding 없음

```powershell
$env:PYTHONHASHSEED='13'
.\.venv\Scripts\python.exe -m pytest -q tests\test_manifest.py tests\test_supervisor_checkpoint_scheduler.py
Remove-Item Env:PYTHONHASHSEED
.\.venv\Scripts\python.exe -m pytest -q tests\test_capability_authorities.py tests\test_existing_capability_rollout.py tests\test_supervisor_checkpoint_scheduler.py tests\test_provider.py tests\test_provider_agents.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_invocation_journal.py tests\test_supervisor_checkpoint_scheduler.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_snapshot_input.py tests\test_model_binding.py tests\test_provider_session.py tests\test_gateway.py tests\test_worker.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 사전 허상·버그 검토 결과

독립 저널 검토와 receipt 공격 검토에서 다음 문제를 발견해 커밋 전에 수정했다.

- caller가 제공한 추상 runtime을 concrete 권위로 오인할 수 있어 ledger·budget·policy·registry의 exact
  class gate를 어떤 dereference보다 먼저 수행한다.
- Worker execution metadata가 seal과 event 사이에서 갈라질 수 있어 code-owned `WorkerJob`과
  `WorkerResult`·dispatch/completed event를 exact equality로 묶었다.
- caller가 `ToolResult`를 Worker stdout과 독립적으로 만들 수 있어 sealed stdout에서 Provider tool의
  `interpret()`로 결과를 다시 도출한다.
- Secret Lease issue·revoke payload와 순서, full event sequence에 대한 누락·추가·치환 검증을 추가했다.
- Campaign의 set-backed JSON 순서가 process hash seed에 따라 바뀌어 nested Supervisor binding이 달라질
  수 있음을 확인하고 serializer 정렬과 비결정성 회귀 테스트를 추가했다.
- final seal 또는 journal finalize가 실패한 경우에도 complete exact two-seal receipt가 있을 때만
  recovery하며, forged·foreign·부분 receipt는 unknown/manual review로 유지한다.

## 다음 조치

`SUP-005`의 가장 작은 수직 슬라이스를 설계한다. 먼저 `BENCH-003A/B`, `WALK-006`, 현재 Benchmark
Harness와 `SUP-004B3` sealed proposal의 authority를 대조한다. 동일한 benchmark 좌표와 sealed source에서
결정론적 baseline 결과와 Shadow Supervisor proposal을 비교하되 기존 measurement/adjudication authority를
중복 구현하지 않는다. 비교 결과는 비실행·비활성화 상태로 유지하고, Confirmed Finding Yield, Chain
Completion, Policy Violation, 비용, 지연, variance와 Human Overturn 기준을 exact sealed input에 결박한다.

## 알려진 경계

- B3 journal은 하나의 host-local canonical SQLite 파일에 한정된다. alternate/copy database나 cross-host
  dispatcher에 대한 distributed exactly-once는 보장하지 않는다.
- `SUP-004B1` budget ledger는 process-local이다. receipt가 증명하는 호출 당시 charge projection과 restart
  뒤 현재 in-memory 잔액은 같은 권위가 아니다.
- started인데 complete receipt가 없으면 자동 재시도하지 않고 수동 검토가 필요하다. Graph current-view
  검증과 journal 전이는 하나의 분산 transaction이 아니다.
- 첫 seal의 Gateway evidence는 complete tainted request를 포함하는 민감 artifact다.
- `SUP-004A`는 canonical input이 기존 `ProviderMessage` 65,536-character 한도를 넘으면 fail closed한다.
- 전체 pytest는 기존 Benchmark registry fixture 만료 뒤 Windows symlink 권한 제약도 남아 있다.
